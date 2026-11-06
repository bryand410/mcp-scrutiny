"""Enumerate tool definitions from a live MCP server.

We speak JSON-RPC 2.0 directly instead of pulling in the official SDK. Two
reasons: the scanner must run with zero third-party dependencies in a CI
container, and the SDK's transport layer hides exactly the bytes we want to
inspect (the raw ``tools/list`` payload, before any normalisation).

Supported transports:

* ``stdio``  - spawn the command, talk over stdin/stdout
* ``http``   - streamable HTTP, JSON or SSE framed responses

The probe is read-only. It calls ``initialize``, then ``tools/list`` and
``prompts/list``. It never calls a tool.
"""

from __future__ import annotations

import collections
import contextlib
import json
import os
import queue
import shutil
import subprocess
import threading
import urllib.error
import urllib.request
from typing import Any

from .. import __version__
from ..models import ServerSpec, ToolSpec

__all__ = ["PROTOCOL_VERSION", "ProbeError", "probe_server"]

PROTOCOL_VERSION = "2025-06-18"
# Sent in `initialize`. A server operator reading their own logs should be able
# to tell which scanner version touched them, so this is not a cosmetic string.
_CLIENT_INFO = {"name": "mcp-scrutiny", "version": __version__}
_DEFAULT_TIMEOUT = 20.0


class ProbeError(RuntimeError):
    """The server could not be reached or did not speak MCP."""


def probe_server(server: ServerSpec, timeout: float = _DEFAULT_TIMEOUT) -> list[ToolSpec]:
    """Return every tool the server advertises.

    A server that fails to start raises :class:`ProbeError`; the caller records
    it as a scan error rather than crashing the whole run.
    """
    payloads = _http_session(server, timeout) if server.url else _stdio_session(server, timeout)

    tools: list[ToolSpec] = []
    for payload in payloads:
        tools.extend(_tools_from_payload(server.name, payload, kind="tool"))
    # Prompts are injected into the same context window as tool descriptions,
    # so they get scanned the same way.
    for payload in _extra_payloads(payloads):
        tools.extend(_tools_from_payload(server.name, payload, kind="prompt"))

    seen: set[str] = set()
    unique: list[ToolSpec] = []
    for t in tools:
        if t.name not in seen:
            seen.add(t.name)
            unique.append(t)
    return unique


def _extra_payloads(payloads: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Pull ``prompts/list`` results out of a session's payloads, if present."""
    return [p for p in payloads if isinstance(p.get("result"), dict) and "prompts" in p["result"]]


def _tools_from_payload(server: str, payload: dict[str, Any], kind: str) -> list[ToolSpec]:
    result = payload.get("result")
    if not isinstance(result, dict):
        return []
    raw_items = result.get("tools") if kind == "tool" else result.get("prompts")
    if not isinstance(raw_items, list):
        return []
    out: list[ToolSpec] = []
    for item in raw_items:
        if not isinstance(item, dict) or not item.get("name"):
            continue
        annotations = item.get("annotations")
        if not isinstance(annotations, dict):
            annotations = {}
        annotations = dict(annotations)
        annotations["mcp_scrutiny_kind"] = kind
        schema = item.get("inputSchema") or item.get("arguments") or {}
        out.append(
            ToolSpec(
                server=server,
                name=str(item["name"]),
                description=str(item.get("description") or ""),
                input_schema=schema if isinstance(schema, dict) else {},
                annotations=annotations,
            )
        )
    return out


# --------------------------------------------------------------------------- #
# stdio
# --------------------------------------------------------------------------- #


def _stdio_session(server: ServerSpec, timeout: float) -> list[dict[str, Any]]:
    if not server.command:
        raise ProbeError(f"{server.name}: stdio server has no command")
    exe = _resolve(server.command)
    if exe is None:
        raise ProbeError(f"{server.name}: command not found on PATH: {server.command}")

    # The config's `env` block is the only way most servers receive their
    # credentials. Dropping it here makes every authenticated server exit on
    # startup, and the failure surfaces as "no response to initialize", which
    # reads as a broken server rather than a broken probe.
    proc = subprocess.Popen(
        [exe, *server.args],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
        env=_child_env(server),
    )
    lines: queue.Queue[str | None] = queue.Queue()
    #: Last stderr lines, kept so a failure can name its own cause. A server
    #: that dies because a token is missing says so on stderr; discarding it
    #: leaves us blaming the remote end for a local mistake.
    stderr_tail: collections.deque[str] = collections.deque(maxlen=12)

    def _pump() -> None:
        assert proc.stdout is not None
        try:
            for line in proc.stdout:
                lines.put(line)
        except (ValueError, OSError):
            pass
        finally:
            lines.put(None)

    def _pump_stderr() -> None:
        assert proc.stderr is not None
        try:
            for line in proc.stderr:
                if line.strip():
                    stderr_tail.append(line.rstrip())
        except (ValueError, OSError):
            pass

    threading.Thread(target=_pump, daemon=True).start()
    threading.Thread(target=_pump_stderr, daemon=True).start()

    payloads: list[dict[str, Any]] = []
    try:
        _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": _CLIENT_INFO,
        }})
        init, reason = _await_response(lines, timeout)
        if init is None:
            raise _failure(server, "initialize", proc, stderr_tail, reason, timeout)
        payloads.append(init)

        _send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        tools, reason = _await_response(lines, timeout)
        if tools is None:
            # An empty tool list is a finding; an unanswered tools/list is a
            # broken server. Returning zero tools here would report the second
            # as the first.
            raise _failure(server, "tools/list", proc, stderr_tail, reason, timeout)
        payloads.append(tools)

        _send(proc, {"jsonrpc": "2.0", "id": 3, "method": "prompts/list", "params": {}})
        prompts, _ = _await_response(lines, timeout)
        if prompts is not None:
            payloads.append(prompts)
    finally:
        _terminate(proc)
    return payloads


def _child_env(server: ServerSpec) -> dict[str, str]:
    """Environment for the spawned server.

    The config's ``env`` block is *merged into* the inherited environment, not
    substituted for it. A child started with a bare ``{"API_KEY": ...}`` dict
    loses ``PATH``, ``HOME`` and ``SYSTEMROOT`` and dies before printing a
    byte - which is the failure this scanner exists to report, not to cause.
    """
    env = dict(os.environ)
    env.update({k: v for k, v in server.env.items() if v is not None})
    return env


def _failure(
    server: ServerSpec,
    stage: str,
    proc: subprocess.Popen[str],
    stderr_tail: collections.deque[str],
    reason: str,
    timeout: float,
) -> ProbeError:
    """Build an error that names what actually failed."""
    code = proc.poll()
    if code is None and reason == "eof":
        # EOF on stdout usually means the child is exiting; give it a moment to
        # be reaped so the message can carry its status code instead of a vague
        # "closed its output".
        with contextlib.suppress(Exception):
            code = proc.wait(timeout=0.5)
    if code is not None:
        head = f"{server.name}: the server exited with status {code} before answering {stage}"
    elif reason == "timeout":
        head = f"{server.name}: no response to {stage} within {timeout:g}s"
    else:
        head = f"{server.name}: the server closed its output before answering {stage}"
    if stderr_tail:
        head += "; stderr: " + " | ".join(stderr_tail)
    return ProbeError(head)


def _resolve(command: str) -> str | None:
    found = shutil.which(command)
    return found or (command if _is_file(command) else None)


def _is_file(path: str) -> bool:
    return os.path.isfile(path)


def _send(proc: subprocess.Popen[str], message: dict[str, Any]) -> None:
    if proc.stdin is None:
        raise ProbeError("stdin is closed")
    proc.stdin.write(json.dumps(message) + "\n")
    proc.stdin.flush()


def _await_response(
    lines: queue.Queue[str | None], timeout: float
) -> tuple[dict[str, Any] | None, str]:
    """Read until one JSON-RPC object arrives. Notifications are skipped.

    Returns ``(payload, reason)`` where reason is ``"ok"``, ``"timeout"`` or
    ``"eof"``. The caller needs the difference: a timeout means the server is
    slow or stuck, an EOF means it exited - and those two demand different
    fixes from the user.
    """
    import time

    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None, "timeout"
        try:
            line = lines.get(timeout=remaining)
        except queue.Empty:
            return None, "timeout"
        if line is None:
            return None, "eof"
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and ("result" in obj or "error" in obj):
            return obj, "ok"


def _terminate(proc: subprocess.Popen[str]) -> None:
    for stream in (proc.stdin, proc.stdout, proc.stderr):
        try:
            if stream is not None:
                stream.close()
        except Exception:
            pass
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        with contextlib.suppress(Exception):
            proc.kill()


# --------------------------------------------------------------------------- #
# HTTP (streamable)
# --------------------------------------------------------------------------- #


def _http_session(server: ServerSpec, timeout: float) -> list[dict[str, Any]]:
    assert server.url
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": PROTOCOL_VERSION,
    }
    # VS Code-style configs carry the credential in an explicit ``headers``
    # block. Honour it verbatim before guessing from variable names.
    raw_headers = server.raw.get("headers") if isinstance(server.raw, dict) else None
    if isinstance(raw_headers, dict):
        headers.update({str(k): str(v) for k, v in raw_headers.items()})
    if "Authorization" not in headers:
        auth = _bearer_from_env(server.env)
        if auth:
            headers["Authorization"] = auth

    session_id: str | None = None
    payloads: list[dict[str, Any]] = []

    init = _post(server.url, {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}, "clientInfo": _CLIENT_INFO},
    }, headers, timeout)
    payloads.append(init[0])
    session_id = init[1]

    if session_id:
        headers["Mcp-Session-Id"] = session_id
    _post(server.url, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
          headers, timeout, expect_response=False)
    payloads.extend(_post(server.url, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                          headers, timeout)[0:1])
    payloads.extend(_post(server.url, {"jsonrpc": "2.0", "id": 3, "method": "prompts/list", "params": {}},
                          headers, timeout)[0:1])
    return payloads


def _bearer_from_env(env: dict[str, str]) -> str | None:
    """Pick a bearer credential out of a config's ``env`` block.

    Clients disagree on the variable name (``GITHUB_PERSONAL_ACCESS_TOKEN``,
    ``BRAVE_API_KEY``, ``NOTION_TOKEN``), so the suffix decides. Names are
    sorted first: previously the *last* matching variable won, which made the
    header depend on the order keys happened to appear in the JSON file.
    """
    explicit = env.get("Authorization") or env.get("AUTHORIZATION")
    if explicit:
        return explicit if explicit.lower().startswith("bearer ") else f"Bearer {explicit}"
    for key in sorted(env):
        if key.upper().endswith(("TOKEN", "KEY")) and env[key]:
            return f"Bearer {env[key]}"
    return None


def _post(
    url: str,
    body: dict[str, Any],
    headers: dict[str, str],
    timeout: float,
    expect_response: bool = True,
) -> tuple[dict[str, Any], str | None]:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            session = resp.headers.get("Mcp-Session-Id") or resp.headers.get("mcp-session-id")
            ctype = resp.headers.get("Content-Type", "")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        raise ProbeError(f"{url}: HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise ProbeError(f"{url}: {exc.reason}") from exc

    if not expect_response or not raw.strip():
        return {}, session
    if "text/event-stream" in ctype or raw.lstrip().startswith("event:") or "data:" in raw[:40]:
        for event in _parse_sse(raw):
            if "result" in event or "error" in event:
                return event, session
        return {}, session
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ProbeError(f"{url}: response was not JSON: {raw[:200]}") from exc
    return (obj if isinstance(obj, dict) else {}), session


def _parse_sse(text: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for block in text.split("\n\n"):
        data_lines = [ln[5:].strip() for ln in block.splitlines() if ln.startswith("data:")]
        if not data_lines:
            continue
        try:
            obj = json.loads("\n".join(data_lines))
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            events.append(obj)
    return events

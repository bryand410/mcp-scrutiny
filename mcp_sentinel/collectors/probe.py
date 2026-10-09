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

import contextlib
import json
import queue
import shutil
import subprocess
import threading
import urllib.error
import urllib.request
from typing import Any

from ..models import ServerSpec, ToolSpec

__all__ = ["PROTOCOL_VERSION", "ProbeError", "probe_server"]

PROTOCOL_VERSION = "2025-06-18"
_CLIENT_INFO = {"name": "mcp-sentinel", "version": "0.1.0"}
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
        annotations["mcp_sentinel_kind"] = kind
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

    proc = subprocess.Popen(
        [exe, *server.args],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    )
    lines: queue.Queue[str | None] = queue.Queue()

    def _pump() -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            lines.put(line)
        lines.put(None)

    threading.Thread(target=_pump, daemon=True).start()

    payloads: list[dict[str, Any]] = []
    try:
        _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": _CLIENT_INFO,
        }})
        init = _await_response(lines, timeout)
        if init is None:
            raise ProbeError(f"{server.name}: no response to initialize")
        payloads.append(init)

        _send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        tools = _await_response(lines, timeout)
        if tools is not None:
            payloads.append(tools)

        _send(proc, {"jsonrpc": "2.0", "id": 3, "method": "prompts/list", "params": {}})
        prompts = _await_response(lines, timeout)
        if prompts is not None:
            payloads.append(prompts)
    finally:
        _terminate(proc)
    return payloads


def _resolve(command: str) -> str | None:
    found = shutil.which(command)
    return found or (command if _is_file(command) else None)


def _is_file(path: str) -> bool:
    import os

    return os.path.isfile(path)


def _send(proc: subprocess.Popen[str], message: dict[str, Any]) -> None:
    if proc.stdin is None:
        raise ProbeError("stdin is closed")
    proc.stdin.write(json.dumps(message) + "\n")
    proc.stdin.flush()


def _await_response(lines: queue.Queue[str | None], timeout: float) -> dict[str, Any] | None:
    """Read until one JSON-RPC object arrives. Notifications are skipped."""
    import time

    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        try:
            line = lines.get(timeout=remaining)
        except queue.Empty:
            return None
        if line is None:
            return None
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and ("result" in obj or "error" in obj):
            return obj
    return None


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
    for key, value in server.env.items():
        # configs often carry the bearer token as an env var; forward it.
        if "token" in key.lower() or "key" in key.lower():
            headers["Authorization"] = f"Bearer {value}"

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

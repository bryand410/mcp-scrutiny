"""The probe, tested against servers that behave like servers.

Every test here spawns a real process or opens a real socket. The probe's job
is to survive what another program does - exit, stall, answer badly - and a
mock cannot fail the way a program fails. The defect this file was written for
(``server.env`` never reaching the child) was invisible to 127 passing tests
because none of them started anything.
"""

from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

import pytest

from mcp_scrutiny.collectors.probe import ProbeError, _bearer_from_env, probe_server
from mcp_scrutiny.models import ServerSpec

FIXTURE = Path(__file__).parent / "fixtures" / "stdio_server.py"


def stdio(**env: str) -> ServerSpec:
    return ServerSpec(name="fixture", command=sys.executable, args=[str(FIXTURE)], env=dict(env))


# --------------------------------------------------------------------------- #
# stdio: the environment the child actually receives
# --------------------------------------------------------------------------- #


def test_env_from_the_config_reaches_the_child() -> None:
    tools = probe_server(stdio(FIXTURE_TOKEN="s3cr3t"), timeout=10)
    assert [t.name for t in tools] == ["report"]


def test_env_is_merged_into_the_inherited_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """The config's env block is added to os.environ, never substituted for it.

    A child started with a bare ``{"TOKEN": ...}`` dict loses PATH and HOME and
    dies before printing a byte; this asserts the inheritance still works.
    """
    monkeypatch.setenv("FIXTURE_INHERITED", "from-the-parent")
    tools = probe_server(stdio(FIXTURE_TOKEN="s3cr3t", FIXTURE_ECHO="FIXTURE_INHERITED"), timeout=10)
    assert "inherited=from-the-parent" in tools[0].description


def test_missing_env_names_the_cause_not_the_symptom() -> None:
    with pytest.raises(ProbeError) as excinfo:
        probe_server(stdio(), timeout=10)
    message = str(excinfo.value)
    assert "fixture" in message
    assert "FIXTURE_TOKEN is not set" in message, message
    assert "status 2" in message, message


def test_unknown_command_is_named_before_anything_is_spawned() -> None:
    server = ServerSpec(name="ghost", command="definitely-not-a-real-binary-xyz")
    with pytest.raises(ProbeError, match="command not found on PATH"):
        probe_server(server, timeout=5)


def test_silent_server_times_out_on_the_stage_it_stalled_at() -> None:
    with pytest.raises(ProbeError) as excinfo:
        probe_server(stdio(FIXTURE_TOKEN="t", FIXTURE_MODE="silent"), timeout=1)
    assert "no response to initialize" in str(excinfo.value)


def test_unanswered_tools_list_is_an_error_not_an_empty_toolset() -> None:
    """Zero tools and a broken server must not look the same in the report."""
    with pytest.raises(ProbeError) as excinfo:
        probe_server(stdio(FIXTURE_TOKEN="t", FIXTURE_MODE="init-only"), timeout=1)
    assert "tools/list" in str(excinfo.value)


# --------------------------------------------------------------------------- #
# HTTP: how the credential is carried
# --------------------------------------------------------------------------- #


class _McpHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    seen: ClassVar[list[dict[str, object]]] = []

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}")
        type(self).seen.append(
            {
                "method": body.get("method"),
                "authorization": self.headers.get("Authorization"),
                "session": self.headers.get("Mcp-Session-Id"),
            }
        )
        if "id" not in body:
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        method = body.get("method")
        if method == "tools/list":
            result: dict[str, object] = {
                "tools": [{"name": "ping", "description": "Ping.", "inputSchema": {"type": "object"}}]
            }
        elif method == "prompts/list":
            result = {"prompts": []}
        else:
            result = {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "serverInfo": {"name": "http-fixture", "version": "1"},
            }
        payload = json.dumps({"jsonrpc": "2.0", "id": body["id"], "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Mcp-Session-Id", "sess-1")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args: object) -> None:  # keep pytest output clean
        return


@pytest.fixture
def http_server() -> str:
    _McpHandler.seen = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _McpHandler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}/mcp"
    finally:
        srv.shutdown()
        srv.server_close()


def test_http_bearer_is_derived_from_the_env_block(http_server: str) -> None:
    server = ServerSpec(name="remote", url=http_server, env={"GITHUB_PERSONAL_ACCESS_TOKEN": "abc"})
    tools = probe_server(server, timeout=10)
    assert [t.name for t in tools] == ["ping"]
    assert _McpHandler.seen[0]["authorization"] == "Bearer abc"


def test_http_session_id_is_reused_across_calls(http_server: str) -> None:
    probe_server(ServerSpec(name="remote", url=http_server, env={"API_KEY": "k"}), timeout=10)
    later = [r for r in _McpHandler.seen if r["method"] == "tools/list"]
    assert later and later[0]["session"] == "sess-1"


def test_http_headers_from_the_config_win_over_env(http_server: str) -> None:
    server = ServerSpec(
        name="remote",
        url=http_server,
        env={"API_KEY": "ignored"},
        raw={"headers": {"Authorization": "Bearer from-config"}},
    )
    probe_server(server, timeout=10)
    assert _McpHandler.seen[0]["authorization"] == "Bearer from-config"


def test_bearer_prefers_an_explicit_authorization_variable() -> None:
    assert _bearer_from_env({"Authorization": "Bearer x", "API_KEY": "y"}) == "Bearer x"
    assert _bearer_from_env({"Authorization": "x"}) == "Bearer x"


def test_bearer_does_not_depend_on_key_order() -> None:
    """Previously the last matching variable won, so JSON key order picked it."""
    assert _bearer_from_env({"Z_TOKEN": "z", "A_KEY": "a"}) == "Bearer a"
    assert _bearer_from_env({"A_KEY": "a", "Z_TOKEN": "z"}) == "Bearer a"
    assert _bearer_from_env({"UNRELATED": "nope"}) is None

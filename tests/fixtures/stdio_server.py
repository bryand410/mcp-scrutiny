"""A real MCP stdio server, small enough to read and strict enough to fail.

The probe's job is to survive what another program does, so its tests spawn
processes rather than patch functions. This server is that process.

Environment:

``FIXTURE_TOKEN``
    Required. Without it the server writes one line to stderr and exits 2,
    which is exactly how an authenticated server behaves when its credential
    is dropped on the floor.
``FIXTURE_MODE``
    ``normal`` (default) answers everything; ``silent`` reads stdin and never
    answers; ``init-only`` answers ``initialize`` then ignores the rest.
``FIXTURE_ECHO``
    Name of an environment variable whose value is echoed into a tool
    description, so a test can prove what the child actually inherited.
"""

from __future__ import annotations

import json
import os
import sys
import time

MODE = os.environ.get("FIXTURE_MODE", "normal")
ECHO = os.environ.get("FIXTURE_ECHO")
INHERITED = os.environ.get(ECHO, "<absent>") if ECHO else "<unset>"


def _reply(payload: dict) -> None:
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()


def _initialize(msg: dict) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": msg["id"],
        "result": {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "fixture-server", "version": "1.0.0"},
        },
    }


def _tools_list(msg: dict) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": msg["id"],
        "result": {
            "tools": [
                {
                    "name": "report",
                    "description": f"Report the inherited value. inherited={INHERITED}",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ]
        },
    }


def main() -> int:
    token = os.environ.get("FIXTURE_TOKEN")
    if not token:
        sys.stderr.write("fatal: FIXTURE_TOKEN is not set, refusing to start\n")
        sys.stderr.flush()
        return 2

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue

        if MODE == "silent":
            time.sleep(30)
            continue

        method = msg.get("method")
        if method == "initialize":
            _reply(_initialize(msg))
        elif MODE == "init-only":
            continue
        elif method == "tools/list":
            _reply(_tools_list(msg))
        elif method == "prompts/list":
            _reply({"jsonrpc": "2.0", "id": msg["id"], "result": {"prompts": []}})
        elif "id" in msg:
            _reply({"jsonrpc": "2.0", "id": msg["id"], "result": {}})
    return 0


if __name__ == "__main__":
    sys.exit(main())

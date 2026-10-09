"""Scan orchestration.

The pipeline is deliberately split so that a scan can run with or without
launching the servers:

``config -> ServerSpec``
    always, from a file
``ServerSpec -> tools``
    either by probing the live server, or by reading a captured tool dump
``tools -> findings``
    by the detector set

The capture path exists because a CI job that executes every MCP server in a
developer's config, with that developer's credentials, in order to audit it, is
a worse idea than the thing it is auditing. ``mcp-scrutiny capture`` produces
the dump on a trusted machine; the CI job scans the dump.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .collectors.probe import ProbeError, probe_server
from .detectors import ALL_DETECTORS, ScanContext, get_detectors
from .detectors.base import Detector
from .models import ScanResult, ServerSpec, ToolSpec
from .snapshot import Snapshot

__all__ = ["load_tool_dump", "scan", "scan_servers"]


def scan(
    servers: Iterable[ServerSpec],
    *,
    baseline: Snapshot | None = None,
    model: Any = None,
    semantic_threshold: float = 0.5,
    probe: bool = False,
    timeout: float = 20.0,
    detectors: list[Detector] | None = None,
    enable: list[str] | None = None,
    disable: list[str] | None = None,
) -> ScanResult:
    """Run every detector over a set of servers."""
    result = scan_servers(servers, probe=probe, timeout=timeout)
    ctx = ScanContext(baseline=baseline, model=model, semantic_threshold=semantic_threshold)

    chosen = detectors if detectors is not None else get_detectors(enable, disable)
    for detector in chosen:
        try:
            result.findings.extend(detector.run(result, ctx))
        except Exception as exc:
            result.errors.append(f"detector '{detector.name}' failed: {type(exc).__name__}: {exc}")
    result.findings.sort(key=lambda f: (-f.severity.rank, f.detector, f.location))
    return result


def scan_servers(
    servers: Iterable[ServerSpec],
    *,
    probe: bool = False,
    timeout: float = 20.0,
) -> ScanResult:
    """Collect tool definitions for each server.

    ``probe=False`` leaves ``server.tools`` as whatever was already attached
    (from a capture dump). ``probe=True`` starts each server and asks it.
    """
    result = ScanResult(servers=list(servers))
    if not probe:
        for server in result.servers:
            if not server.tools:
                result.errors.append(
                    f"{server.name}: no tool definitions available "
                    "(run 'capture' or pass --probe to query the server)"
                )
        return result

    for server in result.servers:
        try:
            server.tools = probe_server(server, timeout=timeout)
        except ProbeError as exc:
            result.errors.append(str(exc))
        except Exception as exc:
            result.errors.append(f"{server.name}: probe failed: {type(exc).__name__}: {exc}")
    return result


def load_tool_dump(path: str | Path) -> list[ServerSpec]:
    """Read a capture file produced by ``mcp-scrutiny capture``.

    Format::

        {"servers": [{"name": "fs", "command": "npx", "args": [...],
                      "tools": [{"name": "...", "description": "...",
                                 "inputSchema": {...}, "annotations": {...}}]}]}
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    raw_servers = data.get("servers") if isinstance(data, dict) else None
    if not isinstance(raw_servers, list):
        raise ValueError(f"{path}: expected an object with a 'servers' list")

    out: list[ServerSpec] = []
    for entry in raw_servers:
        if not isinstance(entry, dict) or not entry.get("name"):
            continue
        server = ServerSpec(
            name=str(entry["name"]),
            command=entry.get("command"),
            args=list(entry.get("args") or []),
            env=dict(entry.get("env") or {}),
            url=entry.get("url"),
            transport=str(entry.get("transport") or "stdio"),
            raw=entry,
        )
        for tool in entry.get("tools") or []:
            if not isinstance(tool, dict) or not tool.get("name"):
                continue
            server.tools.append(
                ToolSpec(
                    server=server.name,
                    name=str(tool["name"]),
                    description=str(tool.get("description") or ""),
                    input_schema=tool.get("inputSchema") or tool.get("input_schema") or {},
                    annotations=tool.get("annotations") or {},
                )
            )
        out.append(server)
    return out


def dump_tools(servers: Iterable[ServerSpec], path: str | Path) -> Path:
    """Write the capture file consumed by :func:`load_tool_dump`."""
    payload = {
        "servers": [
            {
                "name": s.name,
                "transport": s.transport,
                "command": s.command,
                "args": s.args,
                "env": s.env,
                "url": s.url,
                "tools": [
                    {
                        "name": t.name,
                        "description": t.description,
                        "inputSchema": t.input_schema,
                        "annotations": t.annotations,
                    }
                    for t in s.tools
                ],
            }
            for s in servers
        ]
    }
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return p


def _unused() -> list[Detector]:  # pragma: no cover
    return list(ALL_DETECTORS)

"""The approved baseline.

A rug pull works because the tool definition the model reads is fetched fresh
on every session, while the approval a human gave happened once, months ago.
Pinning a hash of every definition turns "trust me" into "match this digest".

The snapshot stores, per tool:

* ``fingerprint`` - the whole definition
* ``description_fingerprint`` - the instruction text alone
* ``schema_fingerprint`` - the parameter contract alone
* ``preview`` - the first 200 characters, so a diff report can show the reader
  what was there before instead of only that something changed
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .models import ScanResult, ToolSpec

__all__ = ["SNAPSHOT_FORMAT", "Snapshot", "ToolRecord"]

SNAPSHOT_FORMAT = 1
_PREVIEW_CHARS = 200


@dataclass
class ToolRecord:
    """The approved state of one tool."""

    fingerprint: str
    description_fingerprint: str
    schema_fingerprint: str
    annotations_fingerprint: str
    preview: str = ""

    @classmethod
    def from_tool(cls, tool: ToolSpec) -> ToolRecord:
        return cls(
            fingerprint=tool.fingerprint(),
            description_fingerprint=tool.description_fingerprint,
            schema_fingerprint=_hash_json(tool.input_schema),
            annotations_fingerprint=_hash_json(
                {k: v for k, v in tool.annotations.items() if k != "mcp_scrutiny_kind"}
            ),
            preview=tool.description[:_PREVIEW_CHARS],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "description_fingerprint": self.description_fingerprint,
            "schema_fingerprint": self.schema_fingerprint,
            "annotations_fingerprint": self.annotations_fingerprint,
            "preview": self.preview,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ToolRecord:
        return cls(
            fingerprint=str(data.get("fingerprint", "")),
            description_fingerprint=str(data.get("description_fingerprint", "")),
            schema_fingerprint=str(data.get("schema_fingerprint", "")),
            annotations_fingerprint=str(data.get("annotations_fingerprint", "")),
            preview=str(data.get("preview", "")),
        )


@dataclass
class Snapshot:
    """A versioned map of ``server -> tool -> approved record``."""

    servers: dict[str, dict[str, ToolRecord]] = field(default_factory=dict)
    created_at: str = ""
    scanner_version: str = ""
    format: int = SNAPSHOT_FORMAT

    @classmethod
    def from_result(cls, result: ScanResult, scanner_version: str = "") -> Snapshot:
        snap = cls(
            created_at=datetime.now(UTC).isoformat(timespec="seconds"),
            scanner_version=scanner_version,
        )
        for server in result.servers:
            snap.servers[server.name] = {t.name: ToolRecord.from_tool(t) for t in server.tools}
        return snap

    def record(self, server: str, tool: str) -> ToolRecord | None:
        return self.servers.get(server, {}).get(tool)

    def save(self, path: str | Path) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "format": self.format,
            "created_at": self.created_at,
            "scanner_version": self.scanner_version,
            "servers": {
                server: {tool: rec.to_dict() for tool, rec in tools.items()}
                for server, tools in sorted(self.servers.items())
            },
        }
        p.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")
        return p

    @classmethod
    def load(cls, path: str | Path) -> Snapshot:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        fmt = int(data.get("format", 0))
        if fmt != SNAPSHOT_FORMAT:
            raise ValueError(
                f"unsupported snapshot format {fmt}; this build understands {SNAPSHOT_FORMAT}. "
                "Re-create the baseline with 'mcp-scrutiny baseline'."
            )
        servers: dict[str, dict[str, ToolRecord]] = {}
        for server, tools in (data.get("servers") or {}).items():
            if not isinstance(tools, dict):
                continue
            servers[server] = {
                tool: ToolRecord.from_dict(rec)
                for tool, rec in tools.items()
                if isinstance(rec, dict)
            }
        return cls(
            servers=servers,
            created_at=str(data.get("created_at", "")),
            scanner_version=str(data.get("scanner_version", "")),
            format=fmt,
        )


def _hash_json(value: Any) -> str:
    blob = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()

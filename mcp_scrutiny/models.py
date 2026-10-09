"""Core data model for mcp-scrutiny."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

#: Anything that pins a spec to a concrete revision. Note ``@latest`` and
#: friends are deliberately *not* matched: a dist-tag is a moving pointer.
_VERSION_SPEC = re.compile(
    r"(@[0-9][\w.\-+]*"          # npm: pkg@1.2.3
    r"|==[^\s,]+|~=[^\s,]+"      # pip/uv: pkg==1.2.3
    r"|>=[^\s,]+|<=[^\s,]+|!=[^\s,]+"
    r"|@sha256:[0-9a-fA-F]+"
    r"|\.git#[0-9a-fA-F]{7,40})"  # git: repo.git#<sha>
)

__all__ = [
    "Finding",
    "ScanResult",
    "ServerSpec",
    "Severity",
    "ToolSpec",
]


class Severity(StrEnum):
    """Finding severity, ordered."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _RANK[self.value]

    def __lt__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank


_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class ToolSpec:
    """One tool exposed by one MCP server.

    ``description``, ``input_schema`` and ``annotations`` are the three places a
    server controls text that the model reads as trusted context, so all three
    are part of the fingerprint.
    """

    server: str
    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)
    annotations: dict[str, Any] = field(default_factory=dict)

    @property
    def qualified_name(self) -> str:
        return f"{self.server}.{self.name}"

    def canonical(self) -> dict[str, Any]:
        """Stable representation used for hashing.

        Keys are sorted and the schema is serialised with sorted keys too, so a
        formatting-only change upstream does not look like a rug pull.
        """
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": _sort_deep(self.input_schema),
            "annotations": _sort_deep(self.annotations),
        }

    def fingerprint(self) -> str:
        """SHA-256 over the canonical form of the tool."""
        blob = json.dumps(self.canonical(), sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    @property
    def description_fingerprint(self) -> str:
        """SHA-256 over the description alone.

        A change here is the shape of a rug pull: same tool name, same schema,
        different instructions.
        """
        return hashlib.sha256(self.description.encode("utf-8")).hexdigest()


@dataclass
class ServerSpec:
    """A server entry from an MCP client configuration."""

    name: str
    command: str | None = None
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str | None = None
    transport: str = "stdio"
    tools: list[ToolSpec] = field(default_factory=list)
    #: Raw config block, kept so the report can show what was actually read.
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_pinned(self) -> bool:
        """Whether the launch spec pins a concrete revision.

        Only meaningful for package runners: ``npx -y @scope/pkg`` with no
        version resolves to whatever is latest at launch time, which is exactly
        how a rug pull reaches a machine.
        """
        if self.url:
            return True  # the client does not version remote servers
        return self.floating_package is None

    @property
    def floating_package(self) -> str | None:
        """Return the package spec that resolves to 'latest', if any.

        A spec is floating when it carries no version constraint at all:
        ``postmark-mcp`` yes, ``postmark-mcp@1.0.16`` no, ``vault-mcp==2.1.0``
        no, ``postmark-mcp@latest`` yes (a dist-tag is not a version).
        """
        runners = {"npx", "npx.cmd", "pnpm", "yarn", "bunx", "uvx", "uvx.exe", "pipx", "pipx.exe"}
        base = (self.command or "").split("/")[-1].split("\\")[-1]
        if base not in runners:
            return None
        for arg in self.args:
            if arg.startswith("-"):
                continue
            if arg.startswith(("http://", "https://")):
                return arg
            if _VERSION_SPEC.search(arg):
                continue
            return arg
        return None


@dataclass
class Finding:
    """A single risk signal."""

    detector: str
    severity: Severity
    title: str
    detail: str
    server: str
    tool: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""

    @property
    def location(self) -> str:
        return f"{self.server}.{self.tool}" if self.tool else self.server

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector": self.detector,
            "severity": self.severity.value,
            "title": self.title,
            "detail": self.detail,
            "server": self.server,
            "tool": self.tool,
            "location": self.location,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@dataclass
class ScanResult:
    """Everything a scan produced."""

    servers: list[ServerSpec] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def tools(self) -> list[ToolSpec]:
        return [t for s in self.servers for t in s.tools]

    @property
    def worst(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def by_severity(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def at_or_above(self, threshold: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity.rank >= threshold.rank]

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": {
                "servers": len(self.servers),
                "tools": len(self.tools),
                "findings": len(self.findings),
                "worst_severity": self.worst.value,
                "by_severity": self.by_severity(),
            },
            "servers": [
                {
                    "name": s.name,
                    "transport": s.transport,
                    "command": s.command,
                    "args": s.args,
                    "url": s.url,
                    "pinned": s.is_pinned,
                    "floating_package": s.floating_package,
                    "tools": len(s.tools),
                }
                for s in self.servers
            ],
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }


def _sort_deep(value: Any) -> Any:
    """Recursively sort dict keys so serialisation is order-independent."""
    if isinstance(value, dict):
        return {k: _sort_deep(value[k]) for k in sorted(value)}
    if isinstance(value, list):
        return [_sort_deep(v) for v in value]
    return value

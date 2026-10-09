"""Toxic flows: capability combinations, not individual tools.

Every tool in a toxic flow is individually reasonable. A tool that reads
configuration is fine. A tool that makes an HTTP request is fine. Together they
form a path that reads secrets and sends them out, and no static rule about
either tool alone will say so.

This is the same reasoning as OWASP's LLM06 (Excessive Agency): the risk is not
one capability but the *composition* of capabilities that the agent can chain
autonomously.

The detector tags each tool with the capabilities it advertises, then looks for
dangerous pairs - within one server and, more importantly, across servers, since
cross-server chains are exactly what the model assembles on its own.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from ..models import Finding, ScanResult, Severity, ToolSpec
from .base import ScanContext

__all__ = ["CAPABILITY_LABELS", "ToxicFlowDetector", "tag_capabilities"]


CAPABILITY_LABELS: dict[str, str] = {
    "read_secret": "reads credentials or secrets",
    "read_fs": "reads files",
    "read_env": "reads environment variables",
    "network_out": "sends data outbound",
    "exec": "executes commands",
    "write_fs": "writes or deletes files",
    "db_write": "modifies a database",
    "send_email": "sends email or messages",
}

_PATTERNS: dict[str, re.Pattern[str]] = {
    "read_secret": re.compile(
        r"\b(credential|secret|api[-_ ]?key|access[-_ ]?token|auth[-_ ]?token|password|"
        r"private[-_ ]?key|\.env\b|id_rsa|keychain|keyring|vault|\.aws|\.npmrc|\.netrc)\b",
        re.I,
    ),
    "read_fs": re.compile(
        r"\b(read|list|get|open|load|fetch|cat)\w*\b[^.]{0,40}\b(file|files|directory|directories|folder|path)s?\b",
        re.I,
    ),
    "read_env": re.compile(r"\b(environment variable|process\.env|os\.environ|env var)\b", re.I),
    "network_out": re.compile(
        r"\b(send|post|upload|forward|publish|transmit|submit|call|request)\w*\b[^.]{0,30}\b(url|endpoint|api|http|server|webhook|host)\b"
        r"|\b(http request|webhook|curl|wget|outbound)\b",
        re.I,
    ),
    "exec": re.compile(
        r"\b(run|execute|exec|spawn|shell|bash|sh\b|powershell|command|subprocess|eval|script)\b",
        re.I,
    ),
    "write_fs": re.compile(
        r"\b(write|create|save|delete|remove|move|rename|append|overwrite)\w*\b[^.]{0,40}\b(file|files|directory|folder|path)s?\b",
        re.I,
    ),
    "db_write": re.compile(
        r"\b(insert|update|delete|drop|alter|truncate|upsert|create table)\b[^.]{0,40}\b(table|row|record|database|schema|column)s?\b",
        re.I,
    ),
    "send_email": re.compile(r"\b(email|e-mail|smtp|mail|bcc|cc\b|recipient|slack|discord|sms|message)\b", re.I),
}

#: ``(source capability, sink capability, severity, why)``
_TOXIC_PAIRS: tuple[tuple[str, str, Severity, str], ...] = (
    (
        "read_secret",
        "network_out",
        Severity.CRITICAL,
        "reads credentials and can send data to an address it controls. A single prompt is enough "
        "to turn 'summarise this config' into a credential leak.",
    ),
    (
        "read_env",
        "network_out",
        Severity.CRITICAL,
        "reads the process environment and can transmit it. API keys, cloud credentials and CI "
        "tokens live in that environment.",
    ),
    (
        "read_fs",
        "network_out",
        Severity.HIGH,
        "reads files and can transmit them, so any file the server can reach is reachable by the "
        "model, including ones outside the project.",
    ),
    (
        "read_secret",
        "send_email",
        Severity.CRITICAL,
        "reads credentials and can send mail. This is the postmark-mcp shape: the mail tool was "
        "legitimate, the credentials were reachable, and the combination was the incident.",
    ),
    (
        "read_env",
        "send_email",
        Severity.HIGH,
        "reads the environment and can send messages, giving an exfiltration channel that needs no "
        "direct network tool.",
    ),
    (
        "exec",
        "network_out",
        Severity.CRITICAL,
        "executes commands and can reach the network, which is remote code execution with a "
        "delivery channel rather than a hint of one.",
    ),
    (
        "exec",
        "write_fs",
        Severity.HIGH,
        "executes commands and writes files, so the agent can persist a payload for a later "
        "session to pick up.",
    ),
    (
        "read_fs",
        "db_write",
        Severity.MEDIUM,
        "reads files and writes to a database, so local content can be moved into a shared store "
        "the model can read back.",
    ),
)


class ToxicFlowDetector:
    """Flag capability compositions that form a data-exfiltration path.

    Findings are aggregated per *capability pair*, not per tool pair. A config
    with nine servers easily contains twenty tool combinations that pair a
    reader with a sender; twenty findings is a report nobody reads. One finding
    per dangerous composition, listing every tool on each side, is the same
    information in a form a human can act on.
    """

    name = "toxic_flow"

    def run(self, result: ScanResult, ctx: ScanContext) -> list[Finding]:
        tagged = [(tool, tag_capabilities(tool)) for tool in result.tools]
        if not tagged:
            return []

        out: list[Finding] = []
        for src_cap, sink_cap, severity, why in _TOXIC_PAIRS:
            sources = [t for t, c in tagged if src_cap in c]
            sinks = [t for t, c in tagged if sink_cap in c]
            if not sources or not sinks:
                continue

            # Keyed by qualified name: ToolSpec is a mutable dataclass and so is
            # unhashable, and two tools with the same name on different servers
            # must stay distinct.
            cross: dict[tuple[str, str], tuple[ToolSpec, ToolSpec]] = {}
            within: dict[tuple[str, str], tuple[ToolSpec, ToolSpec]] = {}
            for s in sources:
                for k in sinks:
                    if s.qualified_name == k.qualified_name:
                        continue
                    key = (s.qualified_name, k.qualified_name)
                    bucket = cross if s.server != k.server else within
                    bucket.setdefault(key, (s, k))

            if not cross and not within:
                # A single tool that both reads secrets and sends data out is
                # covered by the semantic detector, not by a composition rule.
                continue

            if cross:
                out.append(
                    self._finding(
                        src_cap, sink_cap, severity, why, _ordered(cross.values()),
                        cross_server=True, sources=sources, sinks=sinks,
                    )
                )
            if within:
                out.append(
                    self._finding(
                        src_cap, sink_cap, _downgrade(severity), why, _ordered(within.values()),
                        cross_server=False, sources=sources, sinks=sinks,
                    )
                )
        return out

    def _finding(
        self,
        src_cap: str,
        sink_cap: str,
        severity: Severity,
        why: str,
        pairs: list[tuple[ToolSpec, ToolSpec]],
        *,
        cross_server: bool,
        sources: list[ToolSpec],
        sinks: list[ToolSpec],
    ) -> Finding:
        example = pairs[0]
        servers = sorted({p[0].server for p in pairs} | {p[1].server for p in pairs})
        scope = "across servers" if cross_server else f"within '{example[0].server}'"
        return Finding(
            detector=self.name,
            severity=severity,
            title=(
                f"Toxic flow {scope}: {CAPABILITY_LABELS[src_cap]} + "
                f"{CAPABILITY_LABELS[sink_cap]}"
            ),
            detail=(
                f"{len(pairs)} combination(s) exist where one tool "
                f"{CAPABILITY_LABELS[src_cap]} and another {CAPABILITY_LABELS[sink_cap]}. "
                f"Neither tool is malicious on its own; together they {why} "
                + (
                    "The two sides live in different servers, so no per-server review sees the "
                    "combination - the model assembles it at runtime from the tool list."
                    if cross_server
                    else "Both sides live in the same server, which may well be by design; confirm it."
                )
            ),
            server=example[0].server,
            tool=example[0].name,
            evidence={
                "source_capability": src_cap,
                "sink_capability": sink_cap,
                "cross_server": cross_server,
                "pair_count": len(pairs),
                "example": {
                    "source": example[0].qualified_name,
                    "sink": example[1].qualified_name,
                },
                "sources": sorted({t.qualified_name for t in sources}),
                "sinks": sorted({t.qualified_name for t in sinks}),
                "servers": servers,
            },
            remediation=(
                "Break the path, not the tools: scope the credential so the source tool cannot "
                "reach anything valuable, or require explicit user confirmation on the sink tool "
                "(destructiveHint / human-in-the-loop), or split the two capabilities across trust "
                "boundaries that cannot share a context window."
            ),
        )


def _ordered(pairs: Iterable[tuple[ToolSpec, ToolSpec]]) -> list[tuple[ToolSpec, ToolSpec]]:
    """Deterministic order so two scans of the same input produce one report."""
    return sorted(pairs, key=lambda p: (p[0].qualified_name, p[1].qualified_name))


def _downgrade(severity: Severity) -> Severity:
    """A pair inside one server is usually an intended design, so soften it."""
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    idx = order.index(severity)
    return order[max(idx - 1, 0)]


def tag_capabilities(tool: ToolSpec) -> set[str]:
    """Return the capability tags a tool advertises.

    The name carries as much signal as the description - ``read_file`` is
    explicit about what it does - so both are matched.
    """
    haystack = f"{tool.name} {tool.description}"
    return {cap for cap, pattern in _PATTERNS.items() if pattern.search(haystack)}


def describe_capabilities(caps: Iterable[str]) -> str:
    return ", ".join(sorted(CAPABILITY_LABELS.get(c, c) for c in caps))

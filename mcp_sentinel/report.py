"""Report rendering: text for humans, JSON for machines, SARIF for CI.

SARIF is not decoration. A finding that only exists in a terminal scrollback is
a finding nobody fixes; the same finding uploaded as SARIF appears in the
repository's code-scanning tab, next to the line of config that caused it.
"""

from __future__ import annotations

import json
from typing import Any

from . import __version__
from .models import Finding, ScanResult, Severity

__all__ = ["render_json", "render_sarif", "render_text"]

_RESET = "\x1b[0m"
_COLOURS = {
    Severity.CRITICAL: "\x1b[1;31m",  # bold red
    Severity.HIGH: "\x1b[31m",
    Severity.MEDIUM: "\x1b[33m",
    Severity.LOW: "\x1b[36m",
    Severity.INFO: "\x1b[2m",
}
_BADGES = {
    Severity.CRITICAL: "CRIT",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MED ",
    Severity.LOW: "LOW ",
    Severity.INFO: "INFO",
}

#: SARIF has three levels; the mapping is a policy decision, not a translation.
_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def render_text(result: ScanResult, *, colour: bool = False, show_evidence: bool = False) -> str:
    """Human-readable report."""
    lines: list[str] = []
    counts = result.by_severity()
    total_tools = len(result.tools)

    lines.append("")
    lines.append(_paint("mcp-sentinel", Severity.HIGH, colour) + f"  v{__version__}")
    lines.append(
        f"  {len(result.servers)} server(s), {total_tools} tool(s), "
        f"{len(result.findings)} finding(s)"
    )
    lines.append("")

    if not result.findings:
        lines.append("  No findings. That is not the same as safe: see 'Limitations' in the README.")
        lines.append("")
    else:
        for finding in result.findings:
            lines.append(_render_finding(finding, colour=colour, show_evidence=show_evidence))

    lines.append(
        "  summary: "
        + "  ".join(f"{sev.value}={counts[sev.value]}" for sev in reversed(list(Severity)))
    )
    if result.errors:
        lines.append("")
        lines.append("  collection errors:")
        for err in result.errors:
            lines.append(f"    - {err}")
    lines.append("")
    return "\n".join(lines)


def _render_finding(finding: Finding, *, colour: bool, show_evidence: bool) -> str:
    badge = _paint(f"[{_BADGES[finding.severity]}]", finding.severity, colour)
    out = [f"  {badge} {finding.title}", f"         {_paint(finding.location, Severity.INFO, colour)}"
           f"  ({finding.detector})"]
    for chunk in _wrap(finding.detail, width=92):
        out.append(f"         {chunk}")
    if finding.remediation:
        for chunk in _wrap("fix: " + finding.remediation, width=92):
            out.append(f"         {_paint(chunk, Severity.LOW, colour)}")
    if show_evidence and finding.evidence:
        blob = json.dumps(finding.evidence, indent=2, ensure_ascii=False, default=str)
        for line in blob.splitlines():
            out.append(f"         | {line}")
    out.append("")
    return "\n".join(out)


def render_json(result: ScanResult) -> str:
    """Stable machine-readable output."""
    payload: dict[str, Any] = {"tool": {"name": "mcp-sentinel", "version": __version__}}
    payload.update(result.to_dict())
    return json.dumps(payload, indent=2, ensure_ascii=False, default=str)


def render_sarif(result: ScanResult, *, config_uri: str = "mcp.json") -> str:
    """SARIF 2.1.0, suitable for upload to a code-scanning service."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in result.findings:
        rule_id = f"mcp-sentinel/{finding.detector}"
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": finding.detector,
                "shortDescription": {"text": f"{finding.detector} detector"},
                "fullDescription": {
                    "text": _detector_description(finding.detector),
                },
                "helpUri": "https://github.com/bryand410/mcp-sentinel#detectors",
                "defaultConfiguration": {"level": _SARIF_LEVEL[finding.severity]},
            },
        )
        results.append(
            {
                "ruleId": rule_id,
                "level": _SARIF_LEVEL[finding.severity],
                "message": {
                    "text": f"{finding.title}. {finding.detail}"
                    + (f" Remediation: {finding.remediation}" if finding.remediation else "")
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": config_uri},
                            "region": {"startLine": 1, "snippet": {"text": finding.location}},
                        }
                    }
                ],
                "properties": {
                    "severity": finding.severity.value,
                    "server": finding.server,
                    "tool": finding.tool,
                    "evidence": finding.evidence,
                },
            }
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcp-sentinel",
                        "version": __version__,
                        "informationUri": "https://github.com/bryand410/mcp-sentinel",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": not result.errors,
                        "toolExecutionNotifications": [
                            {"level": "error", "message": {"text": err}} for err in result.errors
                        ],
                    }
                ],
            }
        ],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False, default=str)


def _detector_description(name: str) -> str:
    return {
        "pinning": "Checks how a server is launched: unpinned packages, floating tags, plain HTTP.",
        "drift": "Diffs tool definitions against the approved baseline to detect rug pulls.",
        "semantic": "Scores descriptions with a trained model to detect tool poisoning.",
        "shadowing": "Detects duplicate tool names and descriptions that reference other servers.",
        "toxic_flow": "Detects capability combinations that form an exfiltration path.",
    }.get(name, name)


def _paint(text: str, severity: Severity, colour: bool) -> str:
    if not colour:
        return text
    return f"{_COLOURS[severity]}{text}{_RESET}"


def _wrap(text: str, width: int = 92) -> list[str]:
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        if not current:
            current = word
        elif len(current) + 1 + len(word) <= width:
            current += " " + word
        else:
            lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines or [""]

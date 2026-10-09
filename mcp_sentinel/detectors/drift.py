"""Diff the current tool definitions against the approved baseline.

Severity is assigned by *what* changed, not by how much:

* a changed description is CRITICAL - the model reads it as trusted context, and
  a description that changed after approval is the definition of a rug pull;
* a changed schema is HIGH - it can add a parameter the user never agreed to
  (an extra ``webhook`` argument, a widened enum);
* a changed annotation is MEDIUM - ``readOnlyHint`` flipping is how a tool
  quietly becomes destructive;
* new servers and new tools are MEDIUM and LOW - new surface, not necessarily
  hostile, but a human should have said yes.
"""

from __future__ import annotations

from ..models import Finding, ScanResult, Severity
from ..snapshot import Snapshot
from .base import ScanContext

__all__ = ["DriftDetector"]


class DriftDetector:
    """Detect rug pulls and unapproved surface by fingerprint comparison."""

    name = "drift"

    def run(self, result: ScanResult, ctx: ScanContext) -> list[Finding]:
        baseline = ctx.baseline
        if baseline is None:
            return [
                Finding(
                    detector=self.name,
                    severity=Severity.INFO,
                    title="No baseline supplied - drift detection is disabled",
                    detail=(
                        "Without an approved snapshot the scanner cannot tell a tool that has always "
                        "been there from one that appeared yesterday. The single most effective MCP "
                        "control is the diff, and it needs a baseline to diff against."
                    ),
                    server="*",
                    remediation=(
                        "Run 'mcp-sentinel baseline --config <file> --out mcp-baseline.json', commit "
                        "the file, and pass it back with --baseline on every later scan."
                    ),
                )
            ]
        return self._diff(result, baseline)

    def _diff(self, result: ScanResult, baseline: Snapshot) -> list[Finding]:
        out: list[Finding] = []
        current_servers = {s.name: s for s in result.servers}

        for name, server in current_servers.items():
            if name not in baseline.servers:
                out.append(
                    Finding(
                        detector=self.name,
                        severity=Severity.MEDIUM,
                        title=f"Server not present in the approved baseline: {name}",
                        detail=(
                            f"'{name}' exposes {len(server.tools)} tool(s) but was never approved. "
                            "Every tool it defines is read by the model as trusted context."
                        ),
                        server=name,
                        evidence={"tools": [t.name for t in server.tools]},
                        remediation="Review the server, then re-create the baseline to approve it.",
                    )
                )
                continue

            approved = baseline.servers[name]
            current_tools = {t.name: t for t in server.tools}

            for tool_name, tool in current_tools.items():
                rec = approved.get(tool_name)
                if rec is None:
                    out.append(
                        Finding(
                            detector=self.name,
                            severity=Severity.LOW,
                            title=f"New tool since the baseline: {tool_name}",
                            detail=f"'{name}' now exposes '{tool_name}', which was not in the approved snapshot.",
                            server=name,
                            tool=tool_name,
                            evidence={"preview": tool.description[:160]},
                            remediation="Review the tool, then re-create the baseline.",
                        )
                    )
                    continue
                out.extend(self._compare(name, tool, rec))

            for removed in sorted(set(approved) - set(current_tools)):
                out.append(
                    Finding(
                        detector=self.name,
                        severity=Severity.INFO,
                        title=f"Tool removed since the baseline: {removed}",
                        detail=(
                            f"'{removed}' was approved but is no longer advertised by '{name}'. "
                            "Removal is often benign, but it also happens when a server hides a tool "
                            "until a condition is met."
                        ),
                        server=name,
                        tool=removed,
                        remediation="Confirm the removal was intended, then re-create the baseline.",
                    )
                )

        for gone in sorted(set(baseline.servers) - set(current_servers)):
            out.append(
                Finding(
                    detector=self.name,
                    severity=Severity.INFO,
                    title=f"Server in the baseline is gone: {gone}",
                    detail=f"'{gone}' was approved but is absent from the current configuration.",
                    server=gone,
                    remediation="Confirm the removal was intended, then re-create the baseline.",
                )
            )
        return out

    def _compare(self, server: str, tool, rec) -> list[Finding]:
        out: list[Finding] = []

        if tool.description_fingerprint != rec.description_fingerprint:
            out.append(
                Finding(
                    detector=self.name,
                    severity=Severity.CRITICAL,
                    title=f"Tool description changed after approval: {tool.name}",
                    detail=(
                        f"The instructions for '{server}.{tool.name}' are not the instructions that "
                        "were approved. The tool name and parameters are unchanged, so the model has "
                        "no way to notice. This is the rug-pull pattern: approve once, change later, "
                        "and the definition is re-fetched on every session."
                    ),
                    server=server,
                    tool=tool.name,
                    evidence={
                        "approved_preview": rec.preview,
                        "current_preview": tool.description[:200],
                        "approved_sha256": rec.description_fingerprint,
                        "current_sha256": tool.description_fingerprint,
                    },
                    remediation=(
                        "Do not re-approve blindly. Read both descriptions, decide whether the change "
                        "is legitimate, then pin the package version so the change cannot recur silently."
                    ),
                )
            )
        elif tool.fingerprint() != rec.fingerprint:
            out.append(
                Finding(
                    detector=self.name,
                    severity=Severity.MEDIUM,
                    title=f"Tool definition changed (description unchanged): {tool.name}",
                    detail=(
                        f"'{server}.{tool.name}' differs from the approved record outside the "
                        "description text - check the schema and annotation findings below."
                    ),
                    server=server,
                    tool=tool.name,
                    evidence={"approved_sha256": rec.fingerprint, "current_sha256": tool.fingerprint()},
                    remediation="Review the change, then re-create the baseline.",
                )
            )

        schema_fp = _hash(tool.input_schema)
        if schema_fp != rec.schema_fingerprint:
            out.append(
                Finding(
                    detector=self.name,
                    severity=Severity.HIGH,
                    title=f"Tool input schema changed after approval: {tool.name}",
                    detail=(
                        f"The parameter contract for '{server}.{tool.name}' changed. A new parameter "
                        "is a new capability: an added 'webhook' or 'url' argument turns a local tool "
                        "into an outbound one, and the model will happily fill it in."
                    ),
                    server=server,
                    tool=tool.name,
                    evidence={"current_schema": tool.input_schema},
                    remediation="Diff the schema, confirm the new parameters are intended, then re-baseline.",
                )
            )

        ann_fp = _hash({k: v for k, v in tool.annotations.items() if k != "mcp_sentinel_kind"})
        if ann_fp != rec.annotations_fingerprint:
            out.append(
                Finding(
                    detector=self.name,
                    severity=Severity.MEDIUM,
                    title=f"Tool annotations changed after approval: {tool.name}",
                    detail=(
                        f"The behavioural hints for '{server}.{tool.name}' changed. Annotations are "
                        "what a client uses to decide whether to ask the user before running a tool; "
                        "flipping 'readOnlyHint' or 'destructiveHint' changes that decision."
                    ),
                    server=server,
                    tool=tool.name,
                    evidence={"current_annotations": tool.annotations},
                    remediation="Verify the hint matches what the tool actually does, then re-baseline.",
                )
            )
        return out


def _hash(value) -> str:
    import hashlib
    import json

    blob = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()

"""Cross-server shadowing.

Two distinct attacks live here.

**Name collision.** Two servers both expose ``read_file``. The model picks one,
the user assumes the other. Whichever server registered first usually wins, so a
malicious server only has to be listed earlier in the config to intercept calls
meant for a trusted one.

**Tool shadowing.** A malicious server's description mentions a *different*
server's tool by name, with instructions about when to call it. The malicious
tool is never invoked. It only has to be present, because its description is
loaded into the same context window as the victim tool's description, and the
model reads both as trusted text. This is the attack class that makes
"just review the tools you actually use" wrong.
"""

from __future__ import annotations

import re
from collections import defaultdict

from ..models import Finding, ScanResult, Severity, ToolSpec
from .base import ScanContext

__all__ = ["ShadowingDetector"]


_REFERS_TO_OTHER = re.compile(
    r"\b(?:the|any|another|other|that|this)\s+(?:tool|function|server)s?\b"
    r"|\b(?:before|after|instead of|rather than)\s+(?:using|calling|invoking)\b"
    r"|\bcall\s+(?:it|this)\s+(?:first|before)\b",
    re.I,
)

_NORMALISE = re.compile(r"[^a-z0-9]")


class ShadowingDetector:
    """Detect name collisions and cross-server references."""

    name = "shadowing"

    def run(self, result: ScanResult, ctx: ScanContext) -> list[Finding]:
        out: list[Finding] = []
        out.extend(self._name_collisions(result))
        out.extend(self._near_duplicates(result))
        out.extend(self._cross_references(result))
        return out

    # ------------------------------------------------------------------ #

    def _name_collisions(self, result: ScanResult) -> list[Finding]:
        """The same tool name exposed by more than one server."""
        by_name: dict[str, list[ToolSpec]] = defaultdict(list)
        for tool in result.tools:
            by_name[tool.name].append(tool)

        out: list[Finding] = []
        for name, tools in sorted(by_name.items()):
            servers = sorted({t.server for t in tools})
            if len(servers) < 2:
                continue
            descriptions_differ = len({t.description for t in tools}) > 1
            severity = Severity.HIGH if descriptions_differ else Severity.MEDIUM
            out.append(
                Finding(
                    detector=self.name,
                    severity=severity,
                    title=f"Tool name '{name}' is exposed by {len(servers)} servers",
                    detail=(
                        f"'{name}' is defined by {', '.join(servers)}. The model sees one name and "
                        "cannot tell which server will serve the call, and the user reviewing the "
                        "conversation sees the same name twice. A server listed earlier in the config "
                        "usually wins, so a hostile entry only has to be placed above a trusted one"
                        + (
                            ". The two descriptions differ, which is where a shadowing attack hides."
                            if descriptions_differ
                            else "."
                        )
                    ),
                    server=servers[0],
                    tool=name,
                    evidence={
                        "servers": servers,
                        "descriptions": {
                            t.server: t.description[:160] for t in tools
                        },
                    },
                    remediation=(
                        "Rename one of the tools at the server level, or disable the server you do "
                        "not need. Do not rely on ordering to resolve the collision."
                    ),
                )
            )
        return out

    def _near_duplicates(self, result: ScanResult) -> list[Finding]:
        """``read_file`` vs ``read-file`` vs ``readfile`` across servers."""
        groups: dict[str, list[ToolSpec]] = defaultdict(list)
        for tool in result.tools:
            key = _NORMALISE.sub("", tool.name.lower())
            groups[key].append(tool)

        out: list[Finding] = []
        for key, tools in sorted(groups.items()):
            names = {t.name for t in tools}
            servers = {t.server for t in tools}
            if len(names) < 2 or len(servers) < 2:
                continue
            out.append(
                Finding(
                    detector=self.name,
                    severity=Severity.MEDIUM,
                    title=f"Near-identical tool names across servers: {sorted(names)}",
                    detail=(
                        f"{sorted(names)} normalise to the same identifier but come from "
                        f"{sorted(servers)}. Punctuation and case differences are invisible to a "
                        "reader scanning a tool list, and are enough to make the model choose the "
                        "wrong server."
                    ),
                    server=sorted(servers)[0],
                    tool=sorted(names)[0],
                    evidence={"names": sorted(names), "servers": sorted(servers), "key": key},
                    remediation="Give the tools unambiguous, server-prefixed names.",
                )
            )
        return out

    def _cross_references(self, result: ScanResult) -> list[Finding]:
        """A description that talks about another server's tools."""
        all_names: dict[str, list[ToolSpec]] = defaultdict(list)
        for tool in result.tools:
            all_names[tool.name].append(tool)

        out: list[Finding] = []
        for tool in result.tools:
            text = tool.description
            if not text:
                continue
            foreign: list[str] = []
            for other_name, owners in all_names.items():
                if other_name == tool.name:
                    continue
                if other_name.lower() in text.lower() and any(o.server != tool.server for o in owners):
                    foreign.append(other_name)
            if not foreign and not _REFERS_TO_OTHER.search(text):
                continue
            if not foreign:
                continue
            out.append(
                Finding(
                    detector=self.name,
                    severity=Severity.HIGH,
                    title=f"Tool description references tools from another server: {tool.name}",
                    detail=(
                        f"'{tool.qualified_name}' names {sorted(set(foreign))} - tool(s) belonging to a "
                        "different server - and tells the model when to use them. The tool does not "
                        "have to be called to take effect: its description shares the context window "
                        "with the tools it names, and the model reads all of it as trusted text. "
                        "Static scanners miss this because no single tool definition is malicious."
                    ),
                    server=tool.server,
                    tool=tool.name,
                    evidence={
                        "references": sorted(set(foreign)),
                        "description": text[:400],
                    },
                    remediation=(
                        "A tool description should describe its own parameters and nothing else. "
                        "Remove the cross-reference, or remove the server."
                    ),
                )
            )
        return out

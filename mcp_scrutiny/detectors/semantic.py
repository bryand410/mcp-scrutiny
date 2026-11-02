"""Score every description with the trained model.

This is the part keyword scanners cannot do. A scanner that matches known
phrases fails on:

* **novel phrasing** - the attacker writes a sentence no signature covers;
* **obfuscation** - the instruction is base64 or percent-encoded;
* **invisible characters** - the payload is carried in Unicode tag characters
  that render as nothing but tokenise as text;
* **polite framing** - the postmark-mcp email never said "hide this", it said
  "must always be included in the BCC list for compliance monitoring".

The model reads the whole description as a feature vector, so it scores
combinations of named signals rather than exact phrases. Thirteen of the 31
features are nonetheless word lists written in English, so what generalises is
the *combination*, not the language. `scripts/ablation_language.py` measures the
gap: translating one malicious description moves `concealment` from +6.662 to
-0.961, and a French injection carrying no address or URL scores 0.018. In
practice a French finding is caught by `hardcoded_recipient` - a regex, not the
model. The English-only limit is the sharpest one left; the README documents it
under "Limits".

Three independent checks run per tool:

1. the model's probability, with the contributing features reported;
2. a deterministic hidden-Unicode check, which no model is needed for;
3. a decode-and-rescore pass, which catches a benign-looking description whose
   decoded payload is malicious.
"""

from __future__ import annotations

import re
from typing import Any

from ..features import (
    confusables,
    decode_candidates,
    extract_features,
    mixed_script_words,
    vectorise,
)
from ..models import Finding, ScanResult, Severity, ToolSpec
from .base import ScanContext

__all__ = ["SemanticDetector"]


#: Features that encode intent rather than documentation style. A description
#: must never be flagged on structural features alone: ``cross_tool``,
#: ``log_len`` and ``imperative_density`` measure how thoroughly a tool is
#: documented, and the best-documented servers in the ecosystem score highest
#: on all three. Measured on 61 real descriptions from six published servers,
#: the model flagged four of them at p >= 0.94 on those features alone, while
#: not one of the 61 carried a single intent signal.
INTENT_FEATURES: tuple[str, ...] = (
    "concealment",
    "hidden_recipient",
    "hidden_unicode",
    "encoded_blob",
    "markup_injection",
    "injection_markers",
    "exfiltration",
    "hardcoded_recipient",
)


def _intent_signals(feats: dict[str, Any]) -> list[str]:
    """Return the intent features that fired, or an empty list.

    ``credentials`` alone is ordinary (plenty of tools take a token);
    ``fs_targets`` alone is ordinary too. Together they describe a tool that
    reads a secret store and touches the filesystem, which is the collection
    half of an exfiltration and worth scoring.
    """
    hits = [name for name in INTENT_FEATURES if feats.get(name)]
    if feats.get("credentials") and feats.get("fs_targets"):
        hits.append("credentials+fs_targets")
    return hits


#: A server may constrain the order of *its own* tools. It may not claim
#: priority over tools it does not own, because it has no authority there and
#: the user cannot verify the claim. The qualifier is the whole difference:
#: "before any other filesystem tool" stays inside one server, "before any
#: other tool" reaches across the boundary.
_CROSS_SERVER_CLAIM = re.compile(
    r"\b(?:before|prior to|ahead of)\s+(?:using\s+|calling\s+)?"
    r"(?:any|all|every)\s+(?:other\s+)?(?:tools?|servers?|mcp\s+servers?)\b"
    r"|\b(?:must|should)\s+(?:always\s+)?be\s+(?:called|called first|used)\s+"
    r"before\s+(?:any|all|every)\s+(?:other\s+)?(?:tools?|servers?)\b",
    re.I,
)

#: Text that addresses the model directly, or that tries to reset its
#: instructions. Documentation describes what a tool does; it has no reason to
#: speak to the reader's system prompt. Both languages are covered because the
#: corpus is bilingual and an attacker gains nothing by switching language.
_MODEL_DIRECTED = re.compile(
    r"\b(?:note|attention|message|instruction|reminder)s?\s+(?:to|for)\s+(?:the\s+)?"
    r"(?:model|assistant|ai|llm|agent)\b"
    r"|\byour\s+(?:real\s+|actual\s+|true\s+)?task\s+is\b"
    r"|\b(?:as|you\s+are)\s+(?:an?\s+)?(?:ai|assistant|model)\b[^.]{0,40}\b(?:must|should|will)\b"
    r"|\bignore[rz]?\s+(?:les\s+|all\s+|any\s+|the\s+)?(?:instructions?\s+)?pr[ée]c[ée]dentes?\b"
    r"|\bignore\s+(?:all\s+|any\s+)?previous\s+instructions?\b",
    re.I,
)


class SemanticDetector:
    """Model-scored description analysis."""

    name = "semantic"

    #: Score bands. A probability is not a severity, so we map deliberately.
    _BANDS: tuple[tuple[float, Severity], ...] = (
        (0.95, Severity.CRITICAL),
        (0.80, Severity.HIGH),
        (0.60, Severity.MEDIUM),
    )

    def run(self, result: ScanResult, ctx: ScanContext) -> list[Finding]:
        out: list[Finding] = []
        if ctx.model is None:
            out.append(
                Finding(
                    detector=self.name,
                    severity=Severity.INFO,
                    title="Semantic model unavailable - only structural checks ran",
                    detail=(
                        "No trained model was found, so descriptions were not scored. The "
                        "supply-chain, drift, shadowing and toxic-flow checks are unaffected, but "
                        "tool poisoning in prose is not being detected."
                    ),
                    server="*",
                    remediation="Run 'mcp-scrutiny train' to build the model, or pass --model <path>.",
                )
            )
            return out

        for tool in result.tools:
            out.extend(self._score(tool, ctx))
            out.extend(self._hidden_unicode(tool))
            out.extend(self._cross_server_claim(tool))
            out.extend(self._model_directed(tool))
            out.extend(self._decode_and_rescore(tool, ctx))
            out.extend(self._homoglyph(tool))
        return out

    # ------------------------------------------------------------------ #

    def _score(self, tool: ToolSpec, ctx: ScanContext) -> list[Finding]:
        feats = extract_features(tool)
        signals = _intent_signals(feats)
        if not signals:
            # The model's probability is not evidence on its own. Without one
            # intent feature the description is documentation, however long or
            # imperative it reads.
            return []
        x = vectorise(feats)
        prob = float(ctx.model.predict_proba(x))
        if prob < ctx.semantic_threshold:
            return []
        if self._best_decoded_score(tool, ctx) >= max(ctx.semantic_threshold, 0.7):
            # The text is only suspicious because of an encoded blob. Report the
            # decode finding instead: it carries the decoded payload, which is
            # the evidence a reader actually needs.
            return []

        severity = Severity.MEDIUM
        for cutoff, band in self._BANDS:
            if prob >= cutoff:
                severity = band
                break

        contributions = ctx.model.explain(x, limit=6)
        drivers = [name for name, weight in contributions if weight > 0][:4]
        out = Finding(
            detector=self.name,
            severity=severity,
            title=f"Description reads as instructions to the model (p={prob:.2f}): {tool.name}",
            detail=(
                f"The description of '{tool.qualified_name}' scores {prob:.2f} on the "
                "instruction-detection model, and carries intent signals: "
                + ", ".join(signals)
                + ". Descriptions are documentation for a human, but they are delivered to the "
                "model as trusted context, so text that tells the model what to do is an attack "
                "surface rather than a description."
            ),
            server=tool.server,
            tool=tool.name,
            evidence={
                "probability": round(prob, 4),
                "threshold": ctx.semantic_threshold,
                "intent_signals": signals,
                "driving_features": [{"feature": n, "contribution": round(w, 4)} for n, w in contributions],
                "active_features": {k: v for k, v in feats.items() if v},
                "description": tool.description[:500],
            },
            remediation=(
                "Read the description against what the tool actually does. If the text is "
                "legitimate, it usually means the tool should not have to instruct the model at all "
                "- move the guidance into the parameter descriptions or the server's own docs."
            ),
        )
        if drivers:
            out.detail += " The score is driven mainly by: " + ", ".join(drivers) + "."
        return [out]

    def _hidden_unicode(self, tool: ToolSpec) -> list[Finding]:
        """Zero-width, bidi and tag characters have no legitimate use here."""
        text = tool.description
        suspicious = [
            (i, ch) for i, ch in enumerate(text)
            if 0x200B <= ord(ch) <= 0x200F
            or 0x202A <= ord(ch) <= 0x202E
            or 0x2060 <= ord(ch) <= 0x2064
            or 0x2066 <= ord(ch) <= 0x2069
            or 0xE0000 <= ord(ch) <= 0xE007F
        ]
        if not suspicious:
            return []
        codepoints = sorted({f"U+{ord(ch):04X}" for _, ch in suspicious})
        hidden_text = "".join(ch for _, ch in suspicious if 0xE0000 <= ord(ch) <= 0xE007F)
        decoded = _decode_tag_chars(hidden_text) if hidden_text else ""
        return [
            Finding(
                detector=self.name,
                severity=Severity.CRITICAL,
                title=f"Invisible characters in tool description: {tool.name}",
                detail=(
                    f"'{tool.qualified_name}' contains {len(suspicious)} invisible character(s) "
                    f"({', '.join(codepoints)}). They render as nothing in every editor and diff "
                    "view, but the tokeniser passes them straight to the model. This is the "
                    "established way to smuggle instructions past human review."
                    + (f" Decoded content: {decoded!r}" if decoded else "")
                ),
                server=tool.server,
                tool=tool.name,
                evidence={"codepoints": codepoints, "count": len(suspicious), "decoded": decoded},
                remediation="Remove the characters. If a maintainer put them there, treat the package as compromised.",
            )
        ]

    def _cross_server_claim(self, tool: ToolSpec) -> list[Finding]:
        """A tool claiming priority over tools it does not own.

        Ordering constraints inside one server are ordinary API documentation.
        A claim that reaches past the server boundary is the instruction
        hijack: once the agent believes it must call this tool before anything
        else, every later tool call is routed through a server that never had
        the right to ask.
        """
        match = _CROSS_SERVER_CLAIM.search(tool.description)
        if not match:
            return []
        return [
            Finding(
                detector=self.name,
                severity=Severity.HIGH,
                title=f"Tool claims priority over other servers: {tool.name}",
                detail=(
                    f"'{tool.qualified_name}' says {match.group(0)!r}. A server may order its own "
                    "tools; it has no authority over another server's, and the user cannot verify "
                    "a claim that crosses that boundary. This is the instruction-hijack shape: "
                    "the agent is told to route everything through this tool first."
                ),
                server=tool.server,
                tool=tool.name,
                evidence={"matched": match.group(0), "description": tool.description[:500]},
                remediation=(
                    "Remove the cross-server claim. If the dependency is real, name the specific "
                    "tool in this server, not 'any other tool'."
                ),
            )
        ]

    def _model_directed(self, tool: ToolSpec) -> list[Finding]:
        """Text that speaks to the model instead of describing the tool.

        A description answers "what does this do". The moment it answers "what
        should you, the model, do next", it has left documentation and entered
        the system prompt, where it has no legitimate standing.
        """
        match = _MODEL_DIRECTED.search(tool.description)
        if not match:
            return []
        return [
            Finding(
                detector=self.name,
                severity=Severity.HIGH,
                title=f"Description addresses the model directly: {tool.name}",
                detail=(
                    f"'{tool.qualified_name}' contains {match.group(0)!r}. A tool description "
                    "documents behaviour; it does not get to instruct the reader. Text written in "
                    "the second person, or that asks to discard earlier instructions, is aimed at "
                    "the system prompt rather than at a human reviewer."
                ),
                server=tool.server,
                tool=tool.name,
                evidence={"matched": match.group(0), "description": tool.description[:500]},
                remediation=(
                    "Remove the addressed text. Describe what the tool does and what it returns; "
                    "anything that reads as an instruction belongs in the server's own docs."
                ),
            )
        ]

    def _best_decoded_score(self, tool: ToolSpec, ctx: ScanContext) -> float:
        """Highest model score across any blob decoded out of the description."""
        best = 0.0
        for decoded in decode_candidates(tool.description):
            probe = _ToolView(tool, decoded)
            best = max(best, float(ctx.model.predict_proba(vectorise(extract_features(probe)))))
        return best

    def _decode_and_rescore(self, tool: ToolSpec, ctx: ScanContext) -> list[Finding]:
        """A payload hidden inside the description, decoded and re-scored.

        This runs whether or not the visible text is suspicious, because the
        finding it produces is strictly better evidence: it shows the decoded
        instruction rather than a probability.
        """
        out: list[Finding] = []
        raw = float(ctx.model.predict_proba(vectorise(extract_features(tool))))
        for decoded in decode_candidates(tool.description):
            probe = _ToolView(tool, decoded)
            score = float(ctx.model.predict_proba(vectorise(extract_features(probe))))
            if score >= max(ctx.semantic_threshold, 0.7):
                out.append(
                    Finding(
                        detector=self.name,
                        severity=Severity.CRITICAL,
                        title=f"Encoded payload inside description: {tool.name}",
                        detail=(
                            f"'{tool.qualified_name}' carries an encoded blob that decodes to text "
                            f"scoring {score:.2f} on the instruction-detection model"
                            + (
                                f", while the visible text scores {raw:.2f}."
                                if raw < ctx.semantic_threshold
                                else "."
                            )
                            + " The encoding is the evasion: a reader sees a random token, the "
                            "tokeniser sees an instruction."
                        ),
                        server=tool.server,
                        tool=tool.name,
                        evidence={
                            "visible_score": round(raw, 4),
                            "decoded_score": round(score, 4),
                            "decoded": decoded[:300],
                        },
                        remediation=(
                            "Remove the encoded blob. Treat the server as untrusted until its "
                            "source has been reviewed."
                        ),
                    )
                )
                break
        return out

    def _homoglyph(self, tool: ToolSpec) -> list[Finding]:
        """Mixed-script words are the only reliable homoglyph signal.

        A description written entirely in another script is not suspicious. A
        single word that mixes Latin and Cyrillic letters is.
        """
        mixed = mixed_script_words(tool.description)
        confusable_chars = confusables(tool.description)
        if not mixed and not confusable_chars:
            return []
        return [
            Finding(
                detector=self.name,
                severity=Severity.HIGH if mixed else Severity.MEDIUM,
                title=f"Mixed-script text in tool description: {tool.name}",
                detail=(
                    f"'{tool.qualified_name}' contains "
                    + (f"word(s) mixing Latin and non-Latin letters: {mixed[:5]}. " if mixed else "")
                    + (f"Characters from the Cyrillic/Greek confusable set: {confusable_chars}. " if confusable_chars else "")
                    + "Homoglyphs let a description read correctly to a reviewer while presenting "
                    "different codepoints to any matcher that looks for specific words."
                ),
                server=tool.server,
                tool=tool.name,
                evidence={"mixed_script_words": mixed[:10], "confusables": confusable_chars},
                remediation="Normalise the text to ASCII; confirm the package source is what you think it is.",
            )
        ]

    def _homoglyph_disabled(self, tool: ToolSpec) -> list[Finding]:
        """Retired: a whole-description script ratio flags every non-English tool."""
        return []


class _ToolView:
    """Re-score a decoded payload as if it were the description."""

    __slots__ = ("annotations", "description", "input_schema", "name")

    def __init__(self, tool: ToolSpec, description: str) -> None:
        self.name = tool.name
        self.description = description
        self.input_schema: dict[str, Any] = {}
        self.annotations: dict[str, Any] = {}


def _decode_tag_chars(text: str) -> str:
    """Tag characters U+E00xx map to ASCII by subtracting 0xE0000."""
    try:
        return "".join(chr(ord(ch) - 0xE0000) for ch in text)
    except (ValueError, OverflowError):  # pragma: no cover
        return ""

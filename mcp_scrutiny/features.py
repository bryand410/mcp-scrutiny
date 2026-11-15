"""Feature extraction for tool-description analysis.

The scanner does not grep for keywords. It turns a tool definition into a
fixed-length numeric vector, and a logistic regression trained on labelled
descriptions decides whether the text is trying to instruct the model rather
than describe a function.

Every feature is *named* and *explainable*: when the model fires, the report
lists the features that pushed the score up, so a human can audit the decision.
An unexplainable security finding is a finding nobody will act on.

Two families of features:

* **Semantic** - what the text asks for (exfiltration, concealment, credential
  access, cross-tool orchestration). These generalise past any *given* keyword
  list, but they are themselves regex word lists, and they are written in
  English: they do not generalise across languages. See the ablation in
  `scripts/ablation_language.py`.
* **Structural** - what the text *is* (hidden Unicode, encoded blobs, markup
  that a renderer would hide but a tokenizer would not).
"""

from __future__ import annotations

import base64
import math
import re
import unicodedata
from collections.abc import Iterable
from typing import Any

__all__ = [
    "FEATURE_NAMES",
    "confusables",
    "decode_candidates",
    "describe_features",
    "extract_features",
    "homoglyph_ratio",
    "mixed_script_words",
    "vectorise",
]


# --------------------------------------------------------------------------- #
# Patterns
# --------------------------------------------------------------------------- #

_INJECTION = re.compile(
    r"\b(ignore (?:all )?(?:the )?previous|disregard (?:the )?(?:above|previous|prior)|"
    r"override (?:the )?(?:system|previous|your)|new instructions?\b|"
    r"forget (?:everything|all|your)|you are now|from now on you|"
    # "shares a system prompt" names the tool's subject, it does not instruct
    # the model. Only a verb that moves text *into* the prompt is a marker, and
    # the complement can sit a few words away ("append the following to the
    # system prompt").
    r"(?:override|replace|rewrite|append|prepend|inject|insert|put)\b.{0,40}?"
    r"\b(?:system prompt|system message)|"
    r"do not follow your|instead of (?:what|the) |"
    r"(?:add|write|store) a (?:permanent|persistent) rule|"
    r"always remember (?:that|to)|"
    r"follow the instructions (?:it|they|that) contain )",
    re.I,
)

_CONCEALMENT = re.compile(
    r"\b(do not (?:tell|mention|reveal|disclose|inform|display|show|report)|"
    r"don'?t (?:tell|mention|reveal|disclose|inform|report)|"
    r"without (?:telling|informing|mentioning|asking)|"
    r"(?:silently|secretly)\s+(?:to|from)\s+the\s+user|"
    r"(?:silently|secretly)\s+without\s+(?:telling|informing|asking|notifying)|"
    r"keep (?:this )?(?:a )?secret|"
    r"no need to (?:mention|tell|inform)|"
    # "never reported as clean" is an assurance about the output, not an
    # instruction to hide it. The passive "reported as <state>" is the tell.
    r"never (?:mention|reveal|disclose|inform|tell|report)\b(?!\s+as\b)|"
    r"do not (?:need to )?(?:mention|inform) )",
    re.I,
)

_EXFIL = re.compile(
    # A URL on its own is not exfiltration: real tool documentation cites
    # endpoints, docs and specs constantly. What matters is a transfer verb
    # aimed at a network destination, or a URL carrying a payload away.
    r"\b(?:send|post|upload|forward|transmit|leak|exfiltrate|mirror|relay)\b"
    r"[^.]{0,60}https?://"
    r"|https?://[^\s\"'<>\])]+[^.]{0,40}\b(?:upload|exfiltrat|payload)\b"
    r"|\b(?:send|post|upload|forward|transmit|leak|exfiltrate|relay|mirror)\b[^.]{0,40}"
    r"\b(?:to|at|into)\s+(?:https?://|\S+@\S+|(?:\w+\s+){0,2}"
    r"(?:webhook|endpoint|collector|external|third[- ]party|remote host|attacker|"
    r"backup server|mirror))|curl |wget |\bfetch\s*\(|\brequests\.post|"
    r"\bnetcat\b|\bnc -e\b|\bbase64 -d\b",
    re.I,
)

_CREDENTIALS = re.compile(
    r"(credentials?|api[-_ ]?keys?|access[-_ ]?tokens?|auth[-_ ]?tokens?|bearer|"
    r"passwords?|passwd|secrets?\b|private[-_ ]?key|ssh[-_ ]?key|id_rsa|"
    r"\.env\b|\.aws/credentials|keychain|keyring|aws_secret|gh_token|"
    r"github_token|npm_token|dotenv)",
    re.I,
)

_FS_TARGETS = re.compile(
    r"(/etc/passwd|/etc/shadow|~/?\.ssh|\.ssh/|\bid_rsa\b|\.aws/credentials|"
    r"\$HOME/|%USERPROFILE%|process\.env|os\.environ|environment variables?|"
    r"\.git-credentials|\.netrc|\.npmrc|\.docker/config)",
    re.I,
)

_CROSS_TOOL = re.compile(
    r"((?:first|then|before|after)\s+(?:you\s+)?(?:call|invoke|use|run)|"
    r"call (?:this|the) (?:function|tool) (?:first|before)|"
    r"other (?:tools|servers|functions)|"
    r"(?:this|the) (?:tool|function|server) (?:will|must) be (?:called|used|invoked)|"
    r"as a (?:prerequisite|required step)|"
    r"must be called (?:first|before)|"
    r"chain(?:ed)? (?:with|to))",
    re.I,
)

_URGENCY = re.compile(
    r"\b(urgent(?:ly)?|immediately|critical(?:ly)?|right now|at all costs|"
    r"you must|you need to|it is essential|non-negotiable|mandatory|"
    r"failure to (?:do|comply))\b",
    re.I,
)

#: The postmark-mcp shape: a recipient the user never asked for. The text is not
#: concealing anything - it presents the extra recipient as a compliance
#: requirement, which is exactly why keyword scanners miss it.
_HIDDEN_RECIPIENT = re.compile(
    r"\b(bcc|blind carbon copy|hidden (?:recipient|copy)|"
    r"(?:also|additionally|in addition) (?:send|forward|cc|bcc|post|mirror)|"
    r"(?:a )?copy of (?:every|the|each)|mirror(?:ed)? (?:to|the)|"
    r"must (?:always )?(?:be )?(?:included|added|sent|forwarded) (?:to|in the bcc)|"
    r"forward (?:a copy|it|the)|include (?:it|the payload|the contents) in the)\b",
    re.I,
)

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_WEBHOOK = re.compile(
    r"https?://[^\s\"'<>)\]]*(?:webhook|hook|collect|telemetry|analytics|ingest|track|exfil|pastebin|paste\.ee|"
    r"\d{1,3}(?:\.\d{1,3}){3})[^\s\"'<>)\]]*",
    re.I,
)

#: Security controls describe what they refuse to do. Without this feature the
#: model flags every well-written secret-handling tool.
_REDACTION = re.compile(
    r"\b(redact(?:ed|ion)?|mask(?:ed)?|never returns?|not returned|not logged|"
    r"never (?:stored|persisted|logged|written|exposed|accessible)|"
    r"is hashed|hashed before|revoked|requires? a separate|audited call|"
    r"allow-?list|read-?only|only by name|no (?:secrets?|credentials?) (?:are|is))\b",
    re.I,
)

_DIRECTIVE = re.compile(
    r"\b(assistant\s*:|system\s*:|AI\s*:|note to (?:the )?(?:model|assistant)|"
    r"language model|as an AI|attention (?:model|assistant)|"
    r"instructions? for (?:the )?(?:model|assistant|AI))\b",
    re.I,
)

_MARKUP = re.compile(
    r"(<\|?(?:im_start|im_end|system|assistant|endoftext)\|?>|\[/?INST\]|"
    r"<important>|</?(?:system|instructions?)>|"
    r"```|<\!\[CDATA\[|&#x?[0-9a-fA-F]+;)",
    re.I,
)

_HTML_COMMENT = re.compile(r"<!--.*?-->", re.S)

_BASE64_BLOB = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")
_HEX_BLOB = re.compile(r"\b(?:0x)?[0-9a-fA-F]{32,}\b")
_PERCENT_RUN = re.compile(r"(?:%[0-9a-fA-F]{2}){6,}")

#: Unicode categories/points that have no business in a tool description.
_HIDDEN_RANGES: tuple[tuple[int, int], ...] = (
    (0x200B, 0x200F),  # zero-width space..RLM
    (0x202A, 0x202E),  # bidi embedding/override
    (0x2060, 0x2064),  # word joiner, invisible operators
    (0x2066, 0x2069),  # bidi isolates
    # Variation selectors (U+FE00-FE0F) are deliberately absent: they are how
    # emoji carry their presentation, so `⚠️` is U+26A0 U+FE0F and every
    # description with a warning sign read as invisible Unicode. See
    # _hidden_chars for the run-length rule that still catches their abuse.
    (0xE0000, 0xE007F),  # tag characters (invisible ASCII smuggling)
    (0xFFF9, 0xFFFB),  # interlinear annotation
)


#: A single variation selector follows the character it modifies - that is its
#: only defined use, and `⚠️` is two codepoints. Smuggling encodes data as a
#: long run after one base, so the run length is what separates the two.
_VS_RUN_THRESHOLD = 4


def _base64_blobs(text: str) -> list[str]:
    """Base64 candidates that could actually carry a payload.

    `/` belongs to the base64 alphabet, so a documented enumeration of fields
    — `function/class/method/variable/interface/type/module` — matched the
    40-character rule and was counted as an encoded blob. Measured on 12 756
    public tool descriptions, that was 25 of 120 semantic findings.

    A field list is lowercase words joined by slashes. Base64 of text or bytes
    of that length carries mixed case and digits, and does not repeat the
    separator: 40 characters drawn from the full alphabet contain no digit
    with probability 0.0002, and two or more `/` would break the encoding's
    own padding rules.
    """
    out: list[str] = []
    for blob in _BASE64_BLOB.findall(text):
        if blob.count("/") > 1:
            continue
        if not any(c.isupper() for c in blob):
            continue
        if not any(c.isdigit() for c in blob):
            continue
        out.append(blob)
    return out


def _blob_count(text: str) -> float:
    return float(
        len(_base64_blobs(text))
        + len(_HEX_BLOB.findall(text))
        + len(_PERCENT_RUN.findall(text))
    )


def _hidden_chars(text: str) -> list[str]:
    """Invisible codepoints, with one measured exception.

    Variation selectors are how emoji carry their presentation. Counting them
    as invisible Unicode flagged 91 of 482 semantic findings on 9 475 public
    tool descriptions, every one of them a visible warning sign in Chinese,
    Korean or English prose.

    Their legitimate use is always short: one selector, after one base
    character. A run of four or more has no typographic purpose left, so it is
    still reported.
    """
    out: list[str] = []
    vs_run = 0
    for ch in text:
        cp = ord(ch)
        if 0xFE00 <= cp <= 0xFE0F:
            vs_run += 1
            if vs_run >= _VS_RUN_THRESHOLD:
                out.append(f"U+{cp:04X}")
            continue
        vs_run = 0
        if any(lo <= cp <= hi for lo, hi in _HIDDEN_RANGES):
            out.append(f"U+{cp:04X}")
    return out


def _count(pattern: re.Pattern[str], text: str) -> int:
    return len(pattern.findall(text))


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


# --------------------------------------------------------------------------- #
# Feature names - order is part of the model contract
# --------------------------------------------------------------------------- #

FEATURE_NAMES: tuple[str, ...] = (
    # structural / size
    "log_len",
    "log_words",
    "entropy",
    "non_ascii_ratio",
    "hidden_unicode",
    "bidi_control",
    "encoded_blob",
    "markup_injection",
    "html_comment",
    # semantic
    "injection_markers",
    "concealment",
    "exfiltration",
    "credentials",
    "fs_targets",
    "cross_tool",
    "urgency",
    "directive",
    "imperative_density",
    "hidden_recipient",
    "hardcoded_recipient",
    "redaction_language",
    # schema
    "schema_defaults",
    "schema_additional_props",
    "schema_wide_enum",
    "schema_nested_desc",
    "schema_marker_in_props",
    # combinations the model learns to weigh
    "conceal_x_exfil",
    "cred_x_exfil",
    "fs_x_exfil",
    "cross_x_urgency",
    "recipient_x_exfil",
)


def extract_features(tool: Any) -> dict[str, float]:
    """Return a named feature dict for a :class:`~mcp_scrutiny.models.ToolSpec`.

    Accepts any object exposing ``name``, ``description``, ``input_schema`` and
    ``annotations`` so the extractor stays decoupled from the data model.
    """
    text = str(getattr(tool, "description", "") or "")
    name = str(getattr(tool, "name", "") or "")
    schema: dict[str, Any] = getattr(tool, "input_schema", None) or {}
    combined = f"{name} {text}"

    hidden = _hidden_chars(text)
    bidi = [c for c in hidden if 0x202A <= int(c[2:], 16) <= 0x2069]
    ascii_chars = sum(1 for ch in text if ord(ch) < 128)

    injection = _count(_INJECTION, text)
    concealment = _count(_CONCEALMENT, text)
    exfil = _count(_EXFIL, text)
    creds = _count(_CREDENTIALS, text)
    fs = _count(_FS_TARGETS, text)
    cross = _count(_CROSS_TOOL, text)
    urgency = _count(_URGENCY, text)
    directive = _count(_DIRECTIVE, text)

    s_defaults, s_additional, s_wide_enum, s_nested, s_marker = _schema_features(schema)

    hidden_recipient = _count(_HIDDEN_RECIPIENT, text)
    hardcoded = len(_EMAIL.findall(text)) + len(_WEBHOOK.findall(text))
    redaction = _count(_REDACTION, text)

    imperative = len(
        re.findall(r"\b(must|shall|should|always|never|do not|ensure|require[sd]?)\b", text, re.I)
    )

    feats = {
        "log_len": math.log1p(len(text)),
        "log_words": math.log1p(len(text.split())),
        "entropy": _entropy(text),
        "non_ascii_ratio": _ratio(len(text) - ascii_chars, len(text)),
        "hidden_unicode": float(len(hidden)),
        "bidi_control": float(len(bidi)),
        "encoded_blob": _blob_count(combined),
        "markup_injection": float(_count(_MARKUP, text)),
        "html_comment": float(_count(_HTML_COMMENT, text)),
        "injection_markers": float(injection),
        "concealment": float(concealment),
        "exfiltration": float(exfil),
        "credentials": float(creds),
        "fs_targets": float(fs),
        "cross_tool": float(cross),
        "urgency": float(urgency),
        "directive": float(directive),
        "imperative_density": _ratio(imperative, max(len(text.split()), 1)),
        "hidden_recipient": float(hidden_recipient),
        "hardcoded_recipient": float(hardcoded),
        "redaction_language": float(redaction),
        "schema_defaults": float(s_defaults),
        "schema_additional_props": float(s_additional),
        "schema_wide_enum": float(s_wide_enum),
        "schema_nested_desc": float(s_nested),
        "schema_marker_in_props": float(s_marker),
        "conceal_x_exfil": float(min(concealment, 1) * min(exfil, 2)),
        "cred_x_exfil": float(min(creds, 2) * min(exfil, 2)),
        "fs_x_exfil": float(min(fs, 1) * min(exfil, 2)),
        "cross_x_urgency": float(min(cross, 2) * min(urgency, 1)),
        "recipient_x_exfil": float(min(hidden_recipient, 2) * max(exfil, hardcoded > 0)),
    }
    return feats


def vectorise(feats: dict[str, float]) -> list[float]:
    """Order a feature dict according to :data:`FEATURE_NAMES`."""
    return [float(feats.get(name, 0.0)) for name in FEATURE_NAMES]


def describe_features(feats: dict[str, float], limit: int = 5) -> list[tuple[str, float]]:
    """Return the non-zero features, largest first, for the report."""
    active = [(k, v) for k, v in feats.items() if v]
    active.sort(key=lambda kv: kv[1], reverse=True)
    return active[:limit]


def _schema_features(schema: dict[str, Any]) -> tuple[int, int, int, int, int]:
    """Count the schema shapes that make a tool easier to abuse."""
    defaults = additional = wide_enum = nested = marker = 0
    props = schema.get("properties")
    if isinstance(props, dict):
        for spec in props.values():
            if not isinstance(spec, dict):
                continue
            if "default" in spec:
                defaults += 1
            if spec.get("additionalProperties"):
                additional += 1
            enum = spec.get("enum")
            if isinstance(enum, list) and len(enum) > 10:
                wide_enum += 1
            desc = str(spec.get("description") or "")
            if desc:
                nested += 1
                if _INJECTION.search(desc) or _CONCEALMENT.search(desc) or _EXFIL.search(desc):
                    marker += 1
    if schema.get("additionalProperties"):
        additional += 1
    return defaults, additional, wide_enum, nested, marker


def decode_candidates(text: str) -> Iterable[str]:
    """Yield decoded forms of any encoded blob in ``text``.

    Attackers hide instructions in base64 so a scanner reading the raw
    description sees noise. We decode short candidates and re-score them; a
    description that scores benign but whose decoded form scores malicious is
    the signature of a deliberate evasion.
    """
    for blob in _base64_blobs(text)[:5]:
        try:
            decoded = base64.b64decode(blob + "=" * (-len(blob) % 4)).decode("utf-8", "ignore")
        except Exception:
            continue
        if decoded and _printable_ratio(decoded) > 0.8:
            yield decoded
    for run in _PERCENT_RUN.findall(text)[:3]:
        try:
            yield urllib_parse_unquote(run)
        except Exception:
            continue


def urllib_parse_unquote(value: str) -> str:
    from urllib.parse import unquote

    return unquote(value)


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\n\t ")
    return printable / len(text)


def homoglyph_ratio(text: str) -> float:
    """Fraction of letters that are not the Latin script they pretend to be."""
    letters = [ch for ch in text if ch.isalpha()]
    if not letters:
        return 0.0
    foreign = sum(1 for ch in letters if not unicodedata.name(ch, "").startswith("LATIN"))
    return foreign / len(letters)


#: Characters that look like Latin letters but are not. Cyrillic and Greek
#: share most of these shapes with ASCII, which is what makes them useful.
_CONFUSABLE = frozenset(
    "аеорсхуіјѕһАЕОРСХУІЈЅНВКМТ"
    "αεορνικτχΑΒΕΖΗΙΚΜΝΟΡΤΥΧ"
    "\u0430\u0435\u043e\u0440\u0441\u0445\u0443\u0432"
)


#: Only scripts that contain Latin lookalikes can produce a homoglyph. A
#: Chinese description containing "ID" or "API" is Chinese prose, not an
#: attack; the confusable set is Cyrillic and Greek, and nothing else.
_CONFUSABLE_SCRIPTS = ("CYRILLIC", "GREEK")


def mixed_script_words(text: str) -> list[str]:
    """Return words that mix Latin with a *confusable* script.

    This is the real homoglyph signature. A description written entirely in
    Chinese or Arabic is not suspicious - it is simply not English. A word
    holding both Latin and Cyrillic letters cannot be anything but an attempt
    to make a token read as one thing and hash as another.

    The first version of this function counted any non-Latin script as the
    "other" half. Measured on 9 475 public tool descriptions, that flagged 324
    of 482 semantic findings - every Chinese or Japanese description that
    mentioned "ID", "API" or "v2", which is most of them.
    """
    out: list[str] = []
    for word in re.findall(r"\S+", text):
        has_latin = False
        has_confusable = False
        for ch in word:
            if not ch.isalpha():
                continue
            name = unicodedata.name(ch, "")
            if name.startswith("LATIN"):
                has_latin = True
            elif name.startswith(_CONFUSABLE_SCRIPTS):
                has_confusable = True
        if has_latin and has_confusable:
            out.append(word)
    return out


def confusables(text: str) -> list[str]:
    """Cyrillic/Greek characters sitting inside otherwise-Latin text.

    A description written in Russian is not an attack. The previous version
    returned every Cyrillic character it found, so `mcp-yandex-wordstat`,
    which documents itself in Russian, produced five findings whose entire
    evidence was the Russian alphabet — one per tool.

    A confusable can only hide something when the surrounding text is Latin.
    When the Cyrillic or Greek letters outnumber the Latin ones, the text is
    simply written in that script, and there is nothing to confuse.
    """
    present = {ch for ch in text if ch in _CONFUSABLE}
    if not present:
        return []
    latin = sum(1 for ch in text if unicodedata.name(ch, "").startswith("LATIN"))
    if len([ch for ch in text if ch in _CONFUSABLE]) >= latin:
        return []
    return sorted(present)

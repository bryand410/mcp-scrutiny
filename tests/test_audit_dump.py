"""The published audit is reproducible, and its numbers are pinned here.

``docs/afrmcp-dump.json`` is the tool-definition dump behind
``docs/2026-10-francophone-mobile-money-mcp-security.md``. If a detector change
alters those numbers, the report is wrong and this test fails — which is the
point. A published finding that no longer reproduces is worse than no finding.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_scrutiny.model import LogisticModel
from mcp_scrutiny.models import Severity
from mcp_scrutiny.scanner import load_tool_dump, scan

DUMP = Path(__file__).resolve().parent.parent / "docs" / "afrmcp-dump.json"


@pytest.fixture(scope="module")
def result(model: LogisticModel):
    # The model is passed explicitly: without it the semantic detector reports
    # "model not built" and the semantic assertions below would pass vacuously.
    return scan(load_tool_dump(DUMP), model=model)


def test_dump_is_present_and_loads() -> None:
    servers = load_tool_dump(DUMP)
    assert len(servers) == 2
    assert sum(len(s.tools) for s in servers) == 12


def test_report_finding_count_is_unchanged(result) -> None:
    """The report states 3 HIGH and 1 INFO. If that moves, update the report."""
    highs = len(result.at_or_above(Severity.HIGH))
    assert highs == 3, f"report says 3 HIGH, got {highs}"
    assert not result.at_or_above(Severity.CRITICAL), "report says 0 critical"


def test_the_unpinned_install_is_still_caught(result) -> None:
    """Finding H1. If this stops firing, the headline finding of the report is gone."""
    pinning = [f for f in result.findings if f.detector == "pinning"]
    assert len(pinning) == 1
    assert "@theyahia/orange-money-mcp" in pinning[0].title
    assert pinning[0].severity >= Severity.HIGH


def test_the_french_false_positive_does_not_come_back(model: LogisticModel) -> None:
    """Finding H4 in the report: the scanner flagged an ordinary French description.

    ``request_payment`` is 513 characters of well-written procedural French. It
    used to score 0.84 because the corpus had never seen a description longer
    than 228 characters or written in any language but English. This test exists
    so that regression can never ship again.
    """
    servers = load_tool_dump(DUMP)
    tools = {t.name: t for s in servers for t in s.tools}
    assert model.score_tool(tools["request_payment"]) < 0.5
    assert model.score_tool(tools["disburse_payment"]) < 0.5


def test_no_semantic_finding_is_raised_on_the_audited_servers(result) -> None:
    """The audited servers are benign; the report says so. A semantic hit here
    means the model is over-firing on real, non-English documentation again."""
    semantic = [f for f in result.findings if f.detector == "semantic"]
    assert semantic == [], f"unexpected semantic findings: {[f.title for f in semantic]}"

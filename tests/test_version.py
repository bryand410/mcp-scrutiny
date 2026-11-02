"""The version the scanner reports must be the version that was installed.

0.1.1 was tagged, built, and attached to a GitHub release whose metadata said
0.1.1 while ``--version`` said 0.1.0, because the number was written down twice
and nothing compared the two. It is not a cosmetic bug: every snapshot this
scanner writes stamps ``scanner_version`` into the evidence file, so the wrong
number travels into the report a customer keeps.

These tests pin the property, not the number: whatever the distribution
declares is what the CLI prints and what the probe announces to a server.
"""

from __future__ import annotations

import re
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as distribution_version
from pathlib import Path

import pytest

import mcp_scrutiny
from mcp_scrutiny.cli import main
from mcp_scrutiny.collectors import probe

ROOT = Path(__file__).resolve().parent.parent


def installed_version() -> str:
    """The version the wheel metadata declares, or skip outside a distribution."""
    try:
        return distribution_version("mcp-scrutiny")
    except PackageNotFoundError:  # pragma: no cover - bare source tree
        pytest.skip("mcp-scrutiny is not installed; this property is about a distribution")


def test_the_package_reports_the_installed_version() -> None:
    assert mcp_scrutiny.__version__ == installed_version()


def test_the_cli_prints_the_installed_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main(["--version"])
    assert capsys.readouterr().out.strip() == f"mcp-scrutiny {installed_version()}"


def test_the_probe_announces_the_installed_version() -> None:
    """The `initialize` handshake identifies the client; it must not lie either."""
    assert probe._CLIENT_INFO["version"] == installed_version()


def test_the_source_tree_does_not_hardcode_a_release_number() -> None:
    """A literal here is precisely how 0.1.1 shipped carrying two versions."""
    source = (ROOT / "mcp_scrutiny" / "__init__.py").read_text(encoding="utf-8")
    literal = re.search(r"^\s*__version__\s*=\s*[\"']\d+\.\d+\.\d+[\"']", source, re.MULTILINE)
    assert literal is None, (
        "mcp_scrutiny/__init__.py hardcodes a version again; read it from the "
        "distribution metadata so it cannot drift from pyproject.toml"
    )

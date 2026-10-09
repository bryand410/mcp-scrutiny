"""The CI helper scripts, tested so a red pipeline names the real cause."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"


def run_script(name: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPTS / name), *args],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )


def test_zero_dependency_check_passes() -> None:
    result = run_script("check_zero_deps.py")
    assert result.returncode == 0, result.stderr
    assert "no site-packages" in result.stdout
    assert "findings" in result.stdout


def test_sarif_check_accepts_a_real_report(poisoned_dump: Path, tmp_path: Path) -> None:
    from mcp_sentinel.cli import main

    out = tmp_path / "results.sarif"
    main(
        [
            "scan",
            "--tools-json",
            str(poisoned_dump),
            "--format",
            "sarif",
            "--output",
            str(out),
            "--fail-on",
            "none",
        ]
    )
    result = run_script("check_sarif.py", str(out))
    assert result.returncode == 0, result.stderr
    assert "SARIF OK" in result.stdout


def test_sarif_check_rejects_a_broken_report(tmp_path: Path) -> None:
    cases = {
        "wrong version": {"version": "2.0.0", "$schema": "x", "runs": []},
        "no runs": {"version": "2.1.0", "$schema": "x", "runs": []},
        "empty results": {
            "version": "2.1.0",
            "$schema": "x",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "mcp-sentinel",
                            "rules": [{"id": "r", "defaultConfiguration": {"level": "error"}}],
                        }
                    },
                    "results": [],
                }
            ],
        },
    }
    for label, payload in cases.items():
        path = tmp_path / f"{label.replace(' ', '_')}.sarif"
        path.write_text(json.dumps(payload), encoding="utf-8")
        result = run_script("check_sarif.py", str(path))
        assert result.returncode == 1, label
        assert "invalid SARIF" in result.stderr, label


def test_sarif_check_rejects_non_json(tmp_path: Path) -> None:
    path = tmp_path / "bad.sarif"
    path.write_text("not json at all", encoding="utf-8")
    result = run_script("check_sarif.py", str(path))
    assert result.returncode == 1
    assert "not valid JSON" in result.stderr


def test_sarif_check_requires_an_argument() -> None:
    result = run_script("check_sarif.py")
    assert result.returncode == 1
    assert "usage" in result.stderr


@pytest.mark.parametrize("name", ["check_zero_deps.py", "check_sarif.py"])
def test_scripts_are_executable_python(name: str) -> None:
    assert (SCRIPTS / name).is_file()

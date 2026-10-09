"""The wheel verifier.

A wheel that installs without its model file is the worst kind of bug: everything
looks fine, and the semantic detector silently does nothing. These tests use
synthetic wheels so they run in milliseconds and do not depend on a build step.
"""

from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

REQUIRED_FILES = (
    "mcp_scrutiny/data/model.json",
    "mcp_scrutiny/cli.py",
    "mcp_scrutiny/features.py",
    "mcp_scrutiny/model.py",
    "mcp_scrutiny/corpus.py",
    "mcp_scrutiny/detectors/semantic.py",
    "mcp_scrutiny/detectors/toxic_flow.py",
)

METADATA = """Metadata-Version: 2.3
Name: mcp-scrutiny
Version: 0.1.0
Summary: Static and semantic security scanner for MCP servers
"""

ENTRY_POINTS = """[console_scripts]
mcp-scrutiny = mcp_scrutiny.cli:main
"""


def build_wheel(
    path: Path,
    *,
    files: tuple[str, ...] = REQUIRED_FILES,
    model_bytes: int = 4000,
    metadata: str = METADATA,
    entry_points: str | None = ENTRY_POINTS,
) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name in files:
            if name == "mcp_scrutiny/data/model.json":
                zf.writestr(name, "x" * model_bytes)
            else:
                zf.writestr(name, "# placeholder\n")
        zf.writestr("mcp_scrutiny-0.1.0.dist-info/METADATA", metadata)
        if entry_points is not None:
            zf.writestr("mcp_scrutiny-0.1.0.dist-info/entry_points.txt", entry_points)
    return path


def run_check(dist: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "check_wheel.py"), str(dist)],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )


def test_a_sound_wheel_passes(tmp_path: Path) -> None:
    build_wheel(tmp_path / "mcp_scrutiny-0.1.0-py3-none-any.whl")
    result = run_check(tmp_path)
    assert result.returncode == 0, result.stderr
    assert "wheel OK" in result.stdout
    assert "none at runtime" in result.stdout


def test_dev_extras_are_not_runtime_dependencies(tmp_path: Path) -> None:
    """Regression: the checker first flagged its own project's [dev] extras."""
    build_wheel(
        tmp_path / "w.whl",
        metadata=METADATA
        + "Requires-Dist: pytest>=8.0; extra == 'dev'\n"
        + "Requires-Dist: ruff>=0.6; extra == 'dev'\n",
    )
    result = run_check(tmp_path)
    assert result.returncode == 0, result.stderr
    assert "2 behind extras" in result.stdout


def test_missing_model_file_is_caught(tmp_path: Path) -> None:
    """The silent-degradation bug this script exists for."""
    build_wheel(
        tmp_path / "w.whl",
        files=tuple(f for f in REQUIRED_FILES if f != "mcp_scrutiny/data/model.json"),
    )
    result = run_check(tmp_path)
    assert result.returncode == 1
    assert "model.json is not in the wheel" in result.stderr


def test_an_empty_model_file_is_caught(tmp_path: Path) -> None:
    build_wheel(tmp_path / "w.whl", model_bytes=10)
    result = run_check(tmp_path)
    assert result.returncode == 1
    assert "looks empty" in result.stderr


def test_a_runtime_dependency_is_caught(tmp_path: Path) -> None:
    build_wheel(
        tmp_path / "w.whl",
        metadata=METADATA + "Requires-Dist: requests>=2.0\n",
    )
    result = run_check(tmp_path)
    assert result.returncode == 1
    assert "declares runtime dependencies" in result.stderr
    assert "requests" in result.stderr


def test_a_missing_console_script_is_caught(tmp_path: Path) -> None:
    build_wheel(tmp_path / "w.whl", entry_points=None)
    result = run_check(tmp_path)
    assert result.returncode == 1
    assert "entry_points.txt" in result.stderr


def test_an_empty_entry_points_is_caught(tmp_path: Path) -> None:
    build_wheel(tmp_path / "w.whl", entry_points="[console_scripts]\nother = other:main\n")
    result = run_check(tmp_path)
    assert result.returncode == 1
    assert "does not declare the console script" in result.stderr


def test_no_wheel_at_all_is_caught(tmp_path: Path) -> None:
    result = run_check(tmp_path)
    assert result.returncode == 1
    assert "no wheel found" in result.stderr


def test_the_real_package_layout_matches_what_the_checker_expects() -> None:
    """Keeps REQUIRED_FILES honest: every path it demands must exist in the tree."""
    for name in REQUIRED_FILES:
        assert (ROOT / name).is_file(), f"{name} does not exist in the source tree"

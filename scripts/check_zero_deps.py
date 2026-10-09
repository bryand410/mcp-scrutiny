#!/usr/bin/env python3
"""Prove the zero-dependency claim instead of asserting it.

The README says the scanner has no third-party dependencies. That is the kind
of claim that quietly stops being true: someone adds ``requests`` for one HTTP
call, the wheel grows, and the CI container now carries a package nobody
reviewed. A security tool that pulls in a supply chain of its own is a bad joke.

This script runs the scanner in a subprocess started with ``-S``, which means
``site`` is never imported and ``site-packages`` never reaches ``sys.path``.
Only the standard library and this repository are importable. If the scanner
works, the claim holds.

Exit codes: 0 = the claim holds, 1 = it does not.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "tools-poisoned.json"


def run(argv: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, env=env, capture_output=True, text=True, check=False)


def main() -> int:
    env = dict(os.environ, PYTHONPATH=str(ROOT))

    # 1. Confirm the isolation actually happened, so a green result means something.
    probe = run(
        [
            sys.executable,
            "-S",
            "-c",
            "import sys;"
            "leaked=[p for p in sys.path if 'site-packages' in p or 'dist-packages' in p];"
            "print('LEAKED:' + ';'.join(leaked))",
        ],
        env,
    )
    if probe.returncode != 0:
        print(f"could not start an isolated interpreter: {probe.stderr}", file=sys.stderr)
        return 1
    leaked = probe.stdout.strip().removeprefix("LEAKED:")
    if leaked:
        print(f"isolation failed, these paths are still importable: {leaked}", file=sys.stderr)
        return 1
    print("isolated interpreter: no site-packages on sys.path")

    # 2. Run the real scanner under that interpreter.
    with tempfile.TemporaryDirectory() as tmp:
        out = pathlib.Path(tmp) / "report.json"
        result = run(
            [
                sys.executable,
                "-S",
                "-m",
                "mcp_sentinel",
                "scan",
                "--tools-json",
                str(FIXTURE),
                "--format",
                "json",
                "--output",
                str(out),
                "--fail-on",
                "none",
            ],
            env,
        )
        if result.returncode != 0:
            print("the scanner failed without third-party packages:", file=sys.stderr)
            print(result.stdout, file=sys.stderr)
            print(result.stderr, file=sys.stderr)
            return 1

        report = json.loads(out.read_text(encoding="utf-8"))
        summary = report["summary"]
        if summary["findings"] == 0:
            print("the scanner ran but found nothing in a fixture built to be found", file=sys.stderr)
            return 1
        if not report["findings"]:
            print("report has no findings array", file=sys.stderr)
            return 1

    print(
        f"zero-dependency run OK: {summary['servers']} servers, "
        f"{summary['tools']} tools, {summary['findings']} findings"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

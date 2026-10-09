#!/usr/bin/env python3
"""Check the built wheel before it is published.

Two failure modes this catches, both silent:

1. **The model file is missing from the wheel.** A wheel without
   ``mcp_scrutiny/data/model.json`` installs fine and runs fine, but the semantic
   detector quietly does nothing and every scan reports "model unavailable". A
   security tool that silently stops detecting is worse than one that crashes.
2. **A dependency crept in.** The zero-dependency claim is checked in CI against
   the source tree; this checks it against the artifact people actually install.

Exit codes: 0 = the wheel is sound, 1 = it is not.
"""

from __future__ import annotations

import sys
import zipfile
from pathlib import Path

REQUIRED = (
    "mcp_scrutiny/data/model.json",
    "mcp_scrutiny/cli.py",
    "mcp_scrutiny/features.py",
    "mcp_scrutiny/model.py",
    "mcp_scrutiny/corpus.py",
    "mcp_scrutiny/detectors/semantic.py",
    "mcp_scrutiny/detectors/toxic_flow.py",
)


def fail(message: str) -> int:
    print(f"wheel check FAILED: {message}", file=sys.stderr)
    return 1


def main(argv: list[str]) -> int:
    dist = Path(argv[1]) if len(argv) > 1 else Path("dist")
    wheels = sorted(dist.glob("*.whl"))
    if not wheels:
        return fail(f"no wheel found in {dist}")

    wheel = wheels[-1]
    print(f"checking {wheel.name}")

    with zipfile.ZipFile(wheel) as zf:
        names = set(zf.namelist())

        for required in REQUIRED:
            if required not in names:
                return fail(f"{required} is not in the wheel")

        # 1. The model must be non-trivial, not a zero-byte placeholder.
        info = zf.getinfo("mcp_scrutiny/data/model.json")
        if info.file_size < 500:
            return fail(f"model.json is only {info.file_size} bytes; it looks empty")
        print(f"  model.json present, {info.file_size} bytes")

        # 2. Metadata must declare no runtime dependencies.
        metadata_name = next((n for n in names if n.endswith(".dist-info/METADATA")), None)
        if metadata_name is None:
            return fail("no .dist-info/METADATA in the wheel")
        metadata = zf.read(metadata_name).decode("utf-8", "replace")
        requires = [
            line.removeprefix("Requires-Dist:").strip()
            for line in metadata.splitlines()
            if line.startswith("Requires-Dist:")
        ]
        # A requirement gated by "extra == '...'" is installed only on request
        # (`pip install mcp-scrutiny[dev]`), so it does not travel with a plain
        # `pip install mcp-scrutiny` and is not a runtime dependency.
        runtime = [r for r in requires if "extra ==" not in r]
        extras = [r for r in requires if "extra ==" in r]
        if runtime:
            return fail(f"the wheel declares runtime dependencies: {runtime}")
        print(f"  Requires-Dist: none at runtime, {len(extras)} behind extras")

        # 3. The console script must be declared, or 'pip install' gives no command.
        entry_points = next((n for n in names if n.endswith(".dist-info/entry_points.txt")), None)
        if entry_points is None:
            return fail("no entry_points.txt: the 'mcp-scrutiny' command would not be installed")
        scripts = zf.read(entry_points).decode("utf-8", "replace")
        if "mcp-scrutiny" not in scripts:
            return fail(f"entry_points.txt does not declare the console script:\n{scripts}")
        print("  console script declared")

    print("wheel OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

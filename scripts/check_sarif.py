#!/usr/bin/env python3
"""Validate a SARIF report before it is uploaded.

A malformed SARIF file makes ``upload-sarif`` fail with a message about the
schema, several steps away from the code that produced it. Checking the shape
here means a failure names the scanner, not the uploader.

This validates the parts of SARIF 2.1.0 that the scanner actually emits and that
code-scanning services require. It is not a full schema validation.

Exit codes: 0 = valid, 1 = invalid.
"""

from __future__ import annotations

import json
import pathlib
import sys

LEVELS = {"error", "warning", "note"}


def fail(message: str) -> int:
    print(f"invalid SARIF: {message}", file=sys.stderr)
    return 1


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: check_sarif.py <results.sarif>", file=sys.stderr)
        return 1

    path = pathlib.Path(argv[1])
    if not path.is_file():
        return fail(f"{path} does not exist")

    try:
        sarif = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return fail(f"{path} is not valid JSON: {exc}")

    if sarif.get("version") != "2.1.0":
        return fail(f"version must be 2.1.0, got {sarif.get('version')!r}")
    if "$schema" not in sarif:
        return fail("missing $schema")

    runs = sarif.get("runs")
    if not isinstance(runs, list) or not runs:
        return fail("runs must be a non-empty list")

    run = runs[0]
    driver = run.get("tool", {}).get("driver", {})
    if driver.get("name") != "mcp-scrutiny":
        return fail(f"tool.driver.name is {driver.get('name')!r}")

    rules = driver.get("rules")
    if not isinstance(rules, list) or not rules:
        return fail("tool.driver.rules must be a non-empty list")
    rule_ids = set()
    for rule in rules:
        if not rule.get("id"):
            return fail("a rule is missing an id")
        if rule.get("defaultConfiguration", {}).get("level") not in LEVELS:
            return fail(f"rule {rule['id']} has an invalid default level")
        rule_ids.add(rule["id"])

    results = run.get("results")
    if not isinstance(results, list) or not results:
        # A scanner that finds nothing in a fixture built to be found is broken.
        return fail("results is empty")

    for i, result in enumerate(results):
        if result.get("ruleId") not in rule_ids:
            return fail(f"result {i} references unknown rule {result.get('ruleId')!r}")
        if result.get("level") not in LEVELS:
            return fail(f"result {i} has invalid level {result.get('level')!r}")
        if not result.get("message", {}).get("text"):
            return fail(f"result {i} has an empty message")
        locations = result.get("locations")
        if not isinstance(locations, list) or not locations:
            return fail(f"result {i} has no locations")
        uri = locations[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri")
        if not uri:
            return fail(f"result {i} has no artifact uri")

    by_level: dict[str, int] = {}
    for result in results:
        by_level[result["level"]] = by_level.get(result["level"], 0) + 1
    summary = ", ".join(f"{k}={v}" for k, v in sorted(by_level.items()))
    print(f"SARIF OK: {len(results)} results, {len(rules)} rules ({summary})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

"""Command line interface.

Exit codes are part of the contract, because CI depends on them:

* ``0`` - nothing at or above the failure threshold
* ``1`` - at least one finding at or above the threshold
* ``2`` - the scan could not be completed (bad config, missing file)
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .collectors.config import ConfigError, discover_configs, load_config
from .collectors.probe import ProbeError, probe_server
from .corpus import corpus_stats, holdout_samples, samples
from .detectors import ALL_DETECTORS
from .model import MODEL_PATH, LogisticModel, cross_validate, evaluate, load_default_model, train
from .models import ScanResult, ServerSpec, Severity
from .report import render_json, render_sarif, render_text
from .scanner import dump_tools, load_tool_dump, scan
from .snapshot import Snapshot

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

_FAIL_ON = {
    "none": None,
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-sentinel",
        description=(
            "Static and semantic security scanner for Model Context Protocol servers. "
            "Finds unpinned packages, rug pulls, tool poisoning, shadowing and toxic flows."
        ),
    )
    parser.add_argument("--version", action="version", version=f"mcp-sentinel {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    # -- scan ----------------------------------------------------------- #
    p_scan = sub.add_parser("scan", help="scan a configuration for risks")
    src = p_scan.add_argument_group("input")
    src.add_argument("--config", action="append", default=[], metavar="PATH",
                     help="MCP config file (repeatable)")
    src.add_argument("--discover", action="store_true",
                     help="also scan every known config location on this machine")
    src.add_argument("--tools-json", metavar="PATH",
                     help="use a captured tool dump instead of launching the servers")
    src.add_argument("--probe", action="store_true",
                     help="start each server and ask it for its tools")
    src.add_argument("--timeout", type=float, default=20.0, help="probe timeout in seconds")

    det = p_scan.add_argument_group("detection")
    det.add_argument("--baseline", metavar="PATH", help="approved snapshot to diff against")
    det.add_argument("--model", metavar="PATH", help="trained model file (default: bundled)")
    det.add_argument("--semantic-threshold", type=float, default=0.5, metavar="P",
                     help="probability above which a description is flagged (default: 0.5)")
    det.add_argument("--enable", action="append", default=[], metavar="NAME",
                     help=f"run only these detectors ({', '.join(d.name for d in ALL_DETECTORS)})")
    det.add_argument("--disable", action="append", default=[], metavar="NAME",
                     help="skip these detectors")

    out = p_scan.add_argument_group("output")
    out.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    out.add_argument("--output", metavar="PATH", help="write the report to a file")
    out.add_argument("--fail-on", choices=tuple(_FAIL_ON), default="high",
                     help="exit 1 if a finding at or above this severity exists (default: high)")
    out.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    out.add_argument("--evidence", action="store_true", help="include raw evidence in text output")

    # -- baseline ------------------------------------------------------- #
    p_base = sub.add_parser("baseline", help="record the approved state of every tool")
    p_base.add_argument("--config", action="append", default=[], metavar="PATH")
    p_base.add_argument("--tools-json", metavar="PATH")
    p_base.add_argument("--probe", action="store_true")
    p_base.add_argument("--timeout", type=float, default=20.0)
    p_base.add_argument("--out", default="mcp-baseline.json", metavar="PATH")

    # -- capture -------------------------------------------------------- #
    p_cap = sub.add_parser("capture", help="dump live tool definitions to JSON (run on a trusted host)")
    p_cap.add_argument("--config", action="append", default=[], metavar="PATH")
    p_cap.add_argument("--out", default="mcp-tools.json", metavar="PATH")
    p_cap.add_argument("--timeout", type=float, default=20.0)

    # -- train ---------------------------------------------------------- #
    p_train = sub.add_parser("train", help="train the semantic model on the bundled corpus")
    p_train.add_argument("--out", default=str(MODEL_PATH), metavar="PATH")
    p_train.add_argument("--epochs", type=int, default=4000)
    p_train.add_argument("--lr", type=float, default=0.5)
    p_train.add_argument("--l2", type=float, default=1e-3)
    p_train.add_argument("--cv", type=int, default=5, metavar="K",
                         help="k-fold cross-validation to report (0 to skip)")

    # -- detectors ------------------------------------------------------ #
    sub.add_parser("detectors", help="list the available detectors")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "scan":
            return _cmd_scan(args)
        if args.command == "baseline":
            return _cmd_baseline(args)
        if args.command == "capture":
            return _cmd_capture(args)
        if args.command == "train":
            return _cmd_train(args)
        if args.command == "detectors":
            return _cmd_detectors()
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_ERROR


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #


def _cmd_scan(args: argparse.Namespace) -> int:
    if args.tools_json:
        servers: list[ServerSpec] = load_tool_dump(args.tools_json)
        errors: list[str] = []
    else:
        servers, errors = _load_servers(args)
    if not servers:
        print("error: no servers to scan (pass --config, --discover or --tools-json)", file=sys.stderr)
        return EXIT_ERROR

    baseline = Snapshot.load(args.baseline) if args.baseline else None
    model = LogisticModel.load(args.model) if args.model else load_default_model()

    result = scan(
        servers,
        baseline=baseline,
        model=model,
        semantic_threshold=args.semantic_threshold,
        probe=bool(args.probe) and not args.tools_json,
        timeout=args.timeout,
        enable=args.enable,
        disable=args.disable,
    )
    result.errors.extend(errors)

    if args.format == "json":
        text = render_json(result)
    elif args.format == "sarif":
        text = render_sarif(result, config_uri=_primary_uri(args))
    else:
        colour = not args.no_color and sys.stdout.isatty() and not args.output
        text = render_text(result, colour=colour, show_evidence=args.evidence)

    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
        print(f"report written to {args.output}")
    else:
        print(text)

    threshold = _FAIL_ON[args.fail_on]
    if threshold is None:
        return EXIT_OK
    return EXIT_FINDINGS if result.at_or_above(threshold) else EXIT_OK


def _cmd_baseline(args: argparse.Namespace) -> int:
    if args.tools_json:
        servers: list[ServerSpec] = load_tool_dump(args.tools_json)
        errors: list[str] = []
    else:
        servers, errors = _load_servers(args)
    if not servers:
        print("error: no servers found", file=sys.stderr)
        return EXIT_ERROR

    for server in servers:
        if args.probe and not server.tools:
            try:
                server.tools = probe_server(server, timeout=args.timeout)
            except ProbeError as exc:
                print(f"warning: {exc}", file=sys.stderr)
    for err in errors:
        print(f"warning: {err}", file=sys.stderr)

    tools = sum(len(s.tools) for s in servers)
    if tools == 0:
        print(
            "error: no tool definitions available, so the baseline would be empty and "
            "every tool would look new on the next scan. Use --probe or --tools-json.",
            file=sys.stderr,
        )
        return EXIT_ERROR

    snapshot = Snapshot.from_result(ScanResult(servers=servers), scanner_version=__version__)
    path = snapshot.save(args.out)
    print(f"baseline written to {path} ({len(servers)} server(s), {tools} tool(s))")
    print("Commit this file. Pass it back with --baseline on every later scan.")
    return EXIT_OK


def _cmd_capture(args: argparse.Namespace) -> int:
    servers, errors = _load_servers(args)
    if not servers:
        print("error: no servers found", file=sys.stderr)
        return EXIT_ERROR
    for err in errors:
        print(f"warning: {err}", file=sys.stderr)
    for server in servers:
        try:
            server.tools = probe_server(server, timeout=args.timeout)
            print(f"  {server.name}: {len(server.tools)} tool(s)")
        except ProbeError as exc:
            print(f"  {server.name}: FAILED - {exc}", file=sys.stderr)
    path = dump_tools(servers, args.out)
    print(f"tool definitions written to {path}")
    print("Scan this file in CI so the pipeline never executes the servers themselves.")
    return EXIT_OK


def _cmd_train(args: argparse.Namespace) -> int:
    data = samples()
    stats = corpus_stats()
    print(f"corpus: {stats['malicious']} malicious, {stats['benign']} benign, "
          f"{stats['holdout']} held out")

    model = train(data, epochs=args.epochs, lr=args.lr, l2=args.l2)
    train_metrics = dict(model.metrics)

    if args.cv:
        print(f"running {args.cv}-fold cross-validation ...")
        cv = cross_validate(data, k=args.cv, epochs=max(args.epochs // 2, 500), lr=args.lr, l2=args.l2)
        model.metrics["cross_validation"] = cv

    holdout = holdout_samples()
    from .features import extract_features, vectorise
    from .model import _FakeTool

    rows = [vectorise(extract_features(_FakeTool(text))) for text, _ in holdout]
    labels = [label for _, label in holdout]
    model.metrics["holdout"] = evaluate(model, rows, labels)

    path = model.save(args.out)
    print(f"model written to {path}")
    print(f"  training        precision={train_metrics['precision']} recall={train_metrics['recall']} "
          f"f1={train_metrics['f1']} auc={train_metrics['roc_auc']}")
    if args.cv:
        cv = model.metrics["cross_validation"]
        print(f"  {args.cv}-fold CV     precision={cv['precision']} recall={cv['recall']} "
              f"f1={cv['f1']} accuracy={cv['accuracy']}   <- the honest number")
    hold = model.metrics["holdout"]
    print(f"  holdout         precision={hold['precision']} recall={hold['recall']} f1={hold['f1']}")
    print("")
    print("Training accuracy is not the number to quote: a 31-feature model on a 100-example")
    print("corpus can reach 1.00 on data it was fitted to. Quote the cross-validation figure.")
    return EXIT_OK


def _cmd_detectors() -> int:
    from .report import _detector_description

    print("")
    for detector in ALL_DETECTORS:
        print(f"  {detector.name:<12} {_detector_description(detector.name)}")
    print("")
    return EXIT_OK


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def _load_servers(args: argparse.Namespace) -> tuple[list[ServerSpec], list[str]]:
    explicit = [Path(p) for p in args.config]
    paths = list(explicit)
    if getattr(args, "discover", False):
        for found in discover_configs(os.getcwd()):
            if found not in paths:
                paths.append(found)
    if not paths:
        paths = discover_configs(os.getcwd())
        if paths:
            print(f"using discovered config: {', '.join(str(p) for p in paths)}", file=sys.stderr)

    explicit_set = set(explicit)
    servers: list[ServerSpec] = []
    errors: list[str] = []
    seen: set[str] = set()
    for path in paths:
        try:
            for server in load_config(path):
                key = f"{path}::{server.name}"
                if key in seen:
                    continue
                seen.add(key)
                servers.append(server)
        except ConfigError as exc:
            # A discovered file with no server table is a normal machine state
            # (the client exists, nothing is configured). Only a path the user
            # named explicitly is worth failing loudly on.
            if path in explicit_set:
                errors.append(str(exc))
    return servers, errors


def _primary_uri(args: argparse.Namespace) -> str:
    if args.config:
        return str(args.config[0])
    if args.tools_json:
        return str(args.tools_json)
    return "mcp.json"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

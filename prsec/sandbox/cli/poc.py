"""prsec-poc: check and try a PoC (poc.yaml / poc.json) against the running app.

    prsec-poc validate <file>              schema check against PoC; exit 0 ok, 1 invalid
    prsec-poc run <file> [--spec ...]      run it exactly like the replay does (app must be up:
                                           prsec-env up); prints steps + oracle results;
                                           exit 0 = fired, 1 = did not fire, 2 = unreadable/invalid

The run uses the session's canaries (`prsec-canary new` rotates them).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml
from pydantic import ValidationError

from prsec.dynamic.app import load_or_create_canaries
from prsec.dynamic.poc import PoC
from prsec.dynamic.replay import PocEngine, PocRun, run_poc, sink_url_default
from prsec.sandbox.cli.env import add_spec_arg, default_spec_path, readable_errors, runner_from


class PocFileError(Exception):
    """The file could not be read or is not a valid PoC; `lines` explains why."""

    def __init__(self, lines: list[str]) -> None:
        super().__init__("; ".join(lines))
        self.lines = lines


def load_poc_file(path: Path) -> PoC:
    try:
        doc = yaml.safe_load(path.read_text())  # NOSONAR(S8707) agent's own sandbox, no privilege boundary (YAML parses JSON too)
    except OSError as e:
        raise PocFileError([f"cannot read {path}: {e}"]) from None
    except yaml.YAMLError as e:
        raise PocFileError([f"cannot parse {path}: {e}"]) from None
    try:
        return PoC.model_validate(doc)
    except ValidationError as e:
        raise PocFileError(readable_errors(e)) from None


def _print_run(run: PocRun) -> None:
    for s in run.steps:
        who = f" as {s.user}" if s.user else ""
        status = s.status if s.status is not None else "-"
        print(f"step {s.name}{who}: {s.method} {s.url} -> {status}" + (f"  ERROR: {s.error}" if s.error else ""))
    if run.aborted:
        print(f"run aborted: {run.aborted}")
    for r in run.oracle_results:
        print(f"oracle {r.index} {r.type}: {'PASS' if r.passed else 'fail'}  {r.detail}")
    print("FIRED" if run.fired else "NOT FIRED")


def _cmd_validate(args: argparse.Namespace) -> int:
    try:
        poc = load_poc_file(args.file)
    except PocFileError as e:
        print(f"invalid PoC {args.file}:")
        for line in e.lines:
            print(f"  {line}")
        return 1
    print(f"ok: {poc.kind} PoC with {len(poc.steps)} step(s), {len(poc.oracles)} oracle(s)")
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    try:
        poc = load_poc_file(args.file)
    except PocFileError as e:
        print(f"invalid PoC {args.file}:", file=sys.stderr)
        for line in e.lines:
            print(f"  {line}", file=sys.stderr)
        return 2
    try:
        runner = runner_from(args.spec or default_spec_path())
    except (OSError, ValueError, yaml.YAMLError) as e:
        print(f"prsec-poc: cannot load EnvSpec: {e}", file=sys.stderr)
        return 2
    engine = PocEngine(poc.users, runner.base_url, load_or_create_canaries(runner.app_root), runner.workdir,
                       env=runner.app_env(), sink_url=sink_url_default(),
                       services=[sv.name for sv in runner.spec.services])
    try:
        run = run_poc(poc, engine)
    finally:
        engine.close()
    if args.json:
        print(json.dumps({"fired": run.fired, "aborted": run.aborted,
                          "oracle_results": [r.model_dump() for r in run.oracle_results],
                          "steps": [s.model_dump() for s in run.steps]}, indent=2))
    else:
        _print_run(run)
    return 0 if run.fired else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="prsec-poc", description="Validate or run a PoC file.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    val = sub.add_parser("validate", help="check a poc.yaml/json against the PoC schema")
    val.add_argument("file", type=Path)
    run = sub.add_parser("run", help="run the PoC against the running app and evaluate its oracles")
    run.add_argument("file", type=Path)
    run.add_argument("--json", action="store_true", help="machine-readable output")
    add_spec_arg(run)
    args = ap.parse_args(argv)
    return _cmd_validate(args) if args.cmd == "validate" else _cmd_run(args)

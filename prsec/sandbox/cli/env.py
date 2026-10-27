"""prsec-env: drive the PR's app inside the workbench.

    prsec-env up      [--spec /work/in/envspec.json]   copy src, install, build, start, wait for health
    prsec-env status  [--spec ...]                     running / healthy / pid / url (JSON)
    prsec-env logs    [-n 100] [--spec ...]            tail of the app log
    prsec-env reset   [--spec ...]                     stop, throw away the app copy, up again
    prsec-env down    [--spec ...]                     stop the app

Exit 0 = ok, 1 = the app failed (message + log tail on stderr), 2 = usage / unreadable spec.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import yaml
from pydantic import ValidationError

from prsec.dynamic.app import AppRunner, EnvError, load_or_create_canaries
from prsec.dynamic.envspec import EnvSpec
from prsec.dynamic.results import ENVSPEC_FILE


def default_spec_path() -> Path:
    return Path(os.environ.get("PRSEC_ENVSPEC", f"/work/in/{ENVSPEC_FILE}"))


def load_envspec(path: Path) -> EnvSpec:
    """Reads an EnvSpec (JSON or YAML; a bare EnvOutput with an `envspec` key works too)."""
    doc = yaml.safe_load(path.read_text())
    if isinstance(doc, dict) and "envspec" in doc and "start" not in doc:
        doc = doc["envspec"]
    return EnvSpec.model_validate(doc)


def readable_errors(e: ValidationError) -> list[str]:
    return [f"{'.'.join(map(str, err['loc'])) or '<root>'}: {err['msg']}" for err in e.errors()]


def runner_from(spec_path: Path) -> AppRunner:
    """AppRunner for the CLIs (app/src dirs from PRSEC_APP_DIR / PRSEC_SRC_DIR or the defaults)."""
    return AppRunner(load_envspec(spec_path))


def add_spec_arg(p: argparse.ArgumentParser) -> None:
    p.add_argument("--spec", type=Path, default=None, help="EnvSpec file (default /work/in/envspec.json)")


def _cmd_up(runner: AppRunner, _: argparse.Namespace) -> int:
    status = runner.up(load_or_create_canaries(runner.app_root))
    print(json.dumps(status.as_dict()))
    print(f"app is up at {status.url} (logs: prsec-env logs)")
    return 0


def _cmd_status(runner: AppRunner, _: argparse.Namespace) -> int:
    print(json.dumps(runner.status().as_dict()))
    return 0


def _cmd_logs(runner: AppRunner, args: argparse.Namespace) -> int:
    print(runner.logs(args.n))
    return 0


def _cmd_reset(runner: AppRunner, args: argparse.Namespace) -> int:
    runner.reset()
    return _cmd_up(runner, args)


def _cmd_down(runner: AppRunner, _: argparse.Namespace) -> int:
    runner.stop()
    print("app stopped")
    return 0


COMMANDS = {"up": _cmd_up, "status": _cmd_status, "logs": _cmd_logs, "reset": _cmd_reset, "down": _cmd_down}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="prsec-env", description="Start, inspect and stop the PR's app.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in COMMANDS:
        p = sub.add_parser(name)
        add_spec_arg(p)
        if name == "logs":
            p.add_argument("-n", type=int, default=100, help="number of lines")
    args = ap.parse_args(argv)

    spec_path = args.spec or default_spec_path()
    try:
        runner = runner_from(spec_path)
    except OSError as e:
        print(f"prsec-env: cannot read {spec_path}: {e}", file=sys.stderr)
        return 2
    except ValidationError as e:
        print(f"prsec-env: invalid EnvSpec {spec_path}:", file=sys.stderr)
        for line in readable_errors(e):
            print(f"  {line}", file=sys.stderr)
        return 2
    except yaml.YAMLError as e:
        print(f"prsec-env: cannot parse {spec_path}: {e}", file=sys.stderr)
        return 2
    try:
        return COMMANDS[args.cmd](runner, args)
    except EnvError as e:
        print(f"prsec-env: {args.cmd} failed: {e}", file=sys.stderr)
        return 1


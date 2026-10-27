"""prsec-debug: re-run one stage locally, or trigger a manual scan with debugging on.

    prsec-debug rerun-stage /var/lib/prsec/work/42/in/42-static_verify-H3/task.json
        Re-runs that stage as a host process through LocalRunner, in dev mode: the harness uses
        its own login (gateway env is dropped unless --gateway). The original in/out dirs are
        never touched: the context files are copied to <out>/in and the run writes to <out>/out.

    prsec-debug scan acme/shop 7 <head_sha> --keep 30
        POST /scans with debug={log_level: debug, keep_minutes: 30}; then `prsec-trace <id> -f`.
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any

import httpx

from prsec.adapters.protocols import WorkbenchSpec
from prsec.adapters.runner.common import RESULT_FILE, TASK_FILE
from prsec.adapters.runner.local import LOG_FILE, LocalRunner, host_task
from prsec.models import ScanDebug, StageResult, StageStatus, StageTask
from prsec.obs.logging import setup_logging

GATEWAY_ENV = ("PRSEC_GATEWAY_URL", "PRSEC_GATEWAY_KEY", "PRSEC_GATEWAY_MODEL", "PRSEC_GATEWAY_KEY_SCOPE")
DEFAULT_API = "http://127.0.0.1:8080"
EVENTS_FILE = "events.jsonl"
TRANSCRIPT_FILE = "transcript.jsonl"


class DevRunner(LocalRunner):
    """LocalRunner without the gateway env, so the harness falls back to its own login."""

    def __init__(self, *, keep_gateway: bool = False, python: str | None = None):
        super().__init__(python=python)
        self.keep_gateway = keep_gateway

    def _env(self, spec: WorkbenchSpec) -> dict[str, str]:
        env = super()._env(spec)
        if not self.keep_gateway:
            for k in GATEWAY_ENV:
                env.pop(k, None)
        return env


# ------------------------------------------------------------------ rerun-stage


def _default_src(task: StageTask, in_dir: Path) -> Path:
    """The task's own workdir when it exists on this host, else `<scan work dir>/src` (in/<task_id>/../../src)."""
    own = Path(task.workdir)
    return own if own.is_dir() else in_dir.parent.parent / "src"


def _default_skills(task: StageTask) -> Path:
    own = Path(task.skills_dir)
    if own.is_dir():
        return own
    from prsec.config import settings

    return settings().skills_dir


def _default_out(task: StageTask, in_dir: Path) -> Path:
    return in_dir.parent.parent / "debug" / f"{task.task_id}-{time.strftime('%Y%m%d-%H%M%S')}"


def load_task(path: Path, harness: str | None, model: str | None) -> StageTask:
    task = StageTask.model_validate_json(path.read_text())
    updates = {k: v for k, v in (("harness", harness), ("model_alias", model)) if v}
    return task.model_copy(update=updates) if updates else task


def prepare_spec(args: argparse.Namespace) -> WorkbenchSpec:
    """Fresh debug dirs (<out>/in copied from the original in dir, empty <out>/out) and the spec to run."""
    task_path = Path(args.task).resolve()
    task = load_task(task_path, args.harness, args.model)
    orig_in = Path(args.in_dir).resolve() if args.in_dir else task_path.parent
    root = Path(args.out).resolve() if args.out else _default_out(task, orig_in)
    in_dir, out_dir = root / "in", root / "out"
    if in_dir.exists():
        shutil.rmtree(in_dir)
    shutil.copytree(orig_in, in_dir, ignore=shutil.ignore_patterns(TASK_FILE), symlinks=True)
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    return WorkbenchSpec(
        scan_id=task.scan_id, task=task, image="local", harness_volume=None,
        src_dir=Path(args.src).resolve() if args.src else _default_src(task, orig_in),
        in_dir=in_dir, out_dir=out_dir,
        skills_dir=Path(args.skills).resolve() if args.skills else _default_skills(task),
    )


def describe(result: StageResult, spec: WorkbenchSpec) -> list[str]:
    out = Path(spec.out_dir)
    lines = [
        f"status:     {result.status}",
        f"harness:    {result.harness} {result.harness_version or ''}".rstrip(),
        f"model:      {result.model}",
        f"attempts:   {result.attempts}",
        f"duration:   {result.duration_s:.1f}s",
        f"usd:        {result.usage.usd:.4f}",
        f"output:     {host_task(spec).output_path}",
        f"result:     {out / RESULT_FILE}",
        f"transcript: {out / TRANSCRIPT_FILE}",
        f"events:     {out / EVENTS_FILE}",
        f"log:        {out / LOG_FILE}",
    ]
    lines += [f"error:      {e}" for e in result.errors]
    return lines


def rerun_stage(args: argparse.Namespace, runner: LocalRunner | None = None) -> int:
    try:
        spec = prepare_spec(args)
    except (OSError, ValueError) as e:
        print(f"prsec-debug: {e}", file=sys.stderr)
        return 2
    runner = runner or DevRunner(keep_gateway=args.gateway)
    mode = "gateway" if args.gateway else "dev mode (harness's own login)"
    print(f"re-running {spec.task.task_id} ({spec.task.stage}) with {spec.task.harness} [{mode}]")
    print(f"src: {spec.src_dir}  in: {spec.in_dir}  out: {spec.out_dir}")
    result = runner.run_workbench(spec)
    print("\n".join(describe(result, spec)))
    return 0 if result.status == StageStatus.ok else 1


# ------------------------------------------------------------------ scan


def scan_body(args: argparse.Namespace) -> dict[str, Any]:
    debug = ScanDebug(log_level="debug", keep_minutes=args.keep)
    body: dict[str, Any] = {"repo": args.repo, "pr": args.pr, "head_sha": args.head_sha,
                            "debug": debug.model_dump()}
    if args.base_sha:
        body["base_sha"] = args.base_sha
    return body


def trigger_scan(args: argparse.Namespace, transport: httpx.BaseTransport | None = None) -> int:
    token = args.token or os.environ.get("PRSEC_ADMIN_TOKEN", "")
    if not token:
        print("prsec-debug: no admin token (--token or PRSEC_ADMIN_TOKEN)", file=sys.stderr)
        return 2
    url = args.api.rstrip("/") + "/scans"
    try:
        with httpx.Client(transport=transport, timeout=30) as client:
            r = client.post(url, json=scan_body(args), headers={"X-Prsec-Admin": token})
    except httpx.HTTPError as e:
        print(f"prsec-debug: {url}: {e}", file=sys.stderr)
        return 1
    if r.status_code >= 400:
        print(f"prsec-debug: {url} returned {r.status_code}: {r.text[:500]}", file=sys.stderr)
        return 1
    body = r.json()
    if "scan_id" not in body:
        print(f"not queued: {body}")
        return 1
    print(f"queued scan {body['scan_id']} (debug log level, keep {args.keep} min)")
    print(f"follow it with: prsec-trace {body['scan_id']} --follow")
    return 0


# ------------------------------------------------------------------ CLI


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="prsec-debug", description="Debug helpers for PRSec scans.")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("rerun-stage", help="re-run one stage locally from its task.json (dev mode)")
    r.add_argument("task", help="path to the stage's task.json (<work>/in/<task_id>/task.json)")
    r.add_argument("--src", help="checked-out source dir (default: task workdir, else <work>/src)")
    r.add_argument("--in", dest="in_dir", help="context files dir (default: the task.json's dir)")
    r.add_argument("--skills", help="skills dir (default: task skills_dir, else PRSEC_SKILLS_DIR)")
    r.add_argument("--harness", help="override the harness adapter (claude-code, codex, opencode, pi, raw)")
    r.add_argument("--model", help="override the model alias")
    r.add_argument("--out", help="debug run dir; gets in/ and out/ (default: <work>/debug/<task_id>-<time>)")
    r.add_argument("--gateway", action="store_true", help="keep PRSEC_GATEWAY_* env instead of the harness login")

    s = sub.add_parser("scan", help="trigger a manual scan with debug logging through POST /scans")
    s.add_argument("repo")
    s.add_argument("pr", type=int)
    s.add_argument("head_sha")
    s.add_argument("--base-sha", help="base commit (default: resolved by the worker)")
    s.add_argument("--keep", type=int, default=0, metavar="MINUTES",
                   help="keep the work dir and environments this long after the scan (max 1440)")
    s.add_argument("--api", default=os.environ.get("PRSEC_API_URL", DEFAULT_API), help="API base URL")
    s.add_argument("--token", help="admin token (default: PRSEC_ADMIN_TOKEN)")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    setup_logging("debug")
    if args.cmd == "rerun-stage":
        return rerun_stage(args)
    if not 0 <= args.keep <= 24 * 60:
        print("prsec-debug: --keep must be between 0 and 1440 minutes", file=sys.stderr)
        return 2
    return trigger_scan(args)


if __name__ == "__main__":
    sys.exit(main())

"""prsec-stage <task.json>: run one StageTask inside the workbench.

Gateway from env PRSEC_GATEWAY_URL / PRSEC_GATEWAY_KEY / PRSEC_GATEWAY_MODEL (model defaults to
task.model_alias), PRSEC_GATEWAY_KEY_SCOPE=task when the key was minted for this task only
(its gateway spend is then the authoritative stage cost); without PRSEC_GATEWAY_URL the harness keeps its own login (dev mode).
PRSEC_ADAPTER_MODULES (comma-separated) imports extra adapter modules before lookup (tests, plugins).
Writes <out_dir>/result.json (StageResult) and <out_dir>/transcript.jsonl.
"""
from __future__ import annotations

import importlib
import json
import os
import sys
import traceback
from pathlib import Path

from prsec.adapters.harness.base import GatewayConfig, get_adapter
from prsec.models import StageResult, StageStatus, StageTask
from prsec.sandbox.entrypoint.run import run_task

RESULT_FILE = "result.json"
TRANSCRIPT_FILE = "transcript.jsonl"


def gateway_from_env(task: StageTask) -> GatewayConfig | None:
    url = os.environ.get("PRSEC_GATEWAY_URL")
    if not url:
        return None
    return GatewayConfig(
        base_url=url,
        api_key=os.environ.get("PRSEC_GATEWAY_KEY", ""),
        model=os.environ.get("PRSEC_GATEWAY_MODEL") or task.model_alias,
        per_task_key=os.environ.get("PRSEC_GATEWAY_KEY_SCOPE") == "task",
    )


def _load_extra_adapters() -> None:
    for mod in filter(None, (m.strip() for m in os.environ.get("PRSEC_ADAPTER_MODULES", "").split(","))):
        importlib.import_module(mod)


def write_outputs(result: StageResult, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    with (out_dir / TRANSCRIPT_FILE).open("w", encoding="utf-8") as f:
        for ev in result.transcript:
            f.write(ev.model_dump_json() + "\n")
    tmp = out_dir / f".{RESULT_FILE}.tmp"
    tmp.write_text(result.model_dump_json(indent=2))
    tmp.replace(out_dir / RESULT_FILE)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: prsec-stage <task.json>", file=sys.stderr)
        return 2
    try:
        task = StageTask.model_validate(json.loads(Path(args[0]).read_text()))
    except Exception as e:
        print(f"prsec-stage: invalid task file {args[0]}: {e}", file=sys.stderr)
        return 2

    gw = gateway_from_env(task)
    try:
        _load_extra_adapters()
        adapter = get_adapter(task.harness)
    except Exception as e:
        result = StageResult(
            task_id=task.task_id, stage=task.stage, status=StageStatus.harness_error,
            errors=[f"cannot load harness adapter {task.harness!r}: {e}"],
            harness=task.harness, model=gw.model if gw else task.model_alias, attempts=0,
        )
    else:
        try:
            result = run_task(task, adapter, gw)
        except Exception as e:  # run_task should not raise; still never leave the runner without a result
            result = StageResult(
                task_id=task.task_id, stage=task.stage, status=StageStatus.harness_error,
                errors=[f"entrypoint crashed: {type(e).__name__}: {e}", traceback.format_exc()[-4000:]],
                harness=task.harness, model=gw.model if gw else task.model_alias,
            )
    write_outputs(result, Path(task.out_dir))
    print(f"prsec-stage: {task.task_id} -> {result.status} ({result.attempts} attempt(s), {result.duration_s}s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

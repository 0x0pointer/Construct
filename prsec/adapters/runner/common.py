"""Shared runner helpers: task.json in, result.json out."""
from __future__ import annotations

from pathlib import Path

from prsec.models import Event, EventKind, StageResult, StageStatus, StageTask

TASK_FILE = "task.json"
RESULT_FILE = "result.json"
GRACE_S = 60


def write_task(task: StageTask, in_dir: Path) -> Path:
    in_dir.mkdir(parents=True, exist_ok=True)
    path = in_dir / TASK_FILE
    path.write_text(task.model_dump_json(indent=2))
    return path


def load_result(
    task: StageTask, out_dir: Path, *, killed: bool, exit_code: int | None, log_tail: str, duration_s: float
) -> StageResult:
    """Parse <out_dir>/result.json; synthesise a failure result if it is missing or unreadable."""
    path = out_dir / RESULT_FILE
    reason: str
    try:
        return StageResult.model_validate_json(path.read_text())
    except FileNotFoundError:
        reason = "workbench produced no result.json"
    except (OSError, ValueError) as e:
        reason = f"unreadable result.json: {e}"
    if killed:
        status = StageStatus.timeout
        reason = f"workbench killed after wall clock {task.limits.wall_clock_s}s + grace; {reason}"
    else:
        status = StageStatus.harness_error
        reason = f"{reason} (exit code {exit_code})"
    errors = [reason] + ([f"workbench log tail:\n{log_tail}"] if log_tail else [])
    return StageResult(
        task_id=task.task_id, stage=task.stage, status=status, errors=errors,
        transcript=[Event(kind=EventKind.error, text=reason)],
        harness=task.harness, model=task.model_alias, attempts=0, duration_s=round(duration_s, 3),
    )


def tail(text: str, n: int = 4000) -> str:
    return text[-n:]

"""Shared runner helpers: task.json in, result.json out.

out_dir is bind-mounted read-write into the container, and in phase 2 the container runs the PR's
own code. Everything the worker reads from or writes into it after the container exits therefore
goes through `read_nofollow` / `write_nofollow`, which refuse symlinks planted by the container.

While a stage runs, prsec-stage appends each normalised transcript Event to <out_dir>/events.jsonl;
`EventTail` reads what is new in it (same no-follow rules) so the worker can stream it live.
"""
from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from prsec.models import Event, EventKind, StageResult, StageStatus, StageTask

TASK_FILE = "task.json"
RESULT_FILE = "result.json"
EVENTS_FILE = "events.jsonl"  # written live by prsec.sandbox.entrypoint.run
TAIL_READ_MAX = 1 << 20  # bytes read per EventTail.read()
TAIL_LINE_MAX = 256 * 1024  # a partial line longer than this is dropped
GRACE_S = 60


def write_task(task: StageTask, in_dir: Path) -> Path:
    in_dir.mkdir(parents=True, exist_ok=True)
    path = in_dir / TASK_FILE
    write_nofollow(path, task.model_dump_json(indent=2))
    return path


def write_nofollow(path: Path, text: str) -> None:
    """Replace `path` with a new regular file; a symlink at `path` is removed, never followed."""
    path.unlink(missing_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)


def read_nofollow(path: Path) -> str:
    """Read a regular file without following a symlink at `path` (OSError otherwise)."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise OSError(f"{path.name} is not a regular file")
        return f.read().decode("utf-8", errors="replace")


def describe_error(e: Exception) -> str:
    """An error message that never echoes the parsed input (it may be a file the container pointed at)."""
    if isinstance(e, ValidationError):
        return "; ".join(f"{'.'.join(map(str, err['loc'])) or 'document'}: {err['msg']}"
                         for err in e.errors(include_input=False, include_url=False))[:1000]
    return f"{type(e).__name__}: {e}"[:1000]


def load_result(
    task: StageTask, out_dir: Path, *, killed: bool, exit_code: int | None, log_tail: str, duration_s: float
) -> StageResult:
    """Parse <out_dir>/result.json; synthesise a failure result if it is missing or unreadable."""
    path = out_dir / RESULT_FILE
    reason: str
    try:
        return StageResult.model_validate_json(read_nofollow(path))
    except FileNotFoundError:
        reason = "workbench produced no result.json"
    except (OSError, ValueError) as e:
        reason = f"unreadable result.json: {describe_error(e)}"
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


class EventTail:
    """Incremental reader of <out_dir>/events.jsonl: each read() returns the complete new lines as dicts.

    The file is container-written: a symlink or non-regular file is ignored, unparsable lines are
    skipped, and a file that shrank (rewritten) is read again from the start."""

    def __init__(self, out_dir: Path):
        self.path = Path(out_dir) / EVENTS_FILE
        self.pos = 0
        self.partial = b""

    def _chunk(self) -> bytes:
        try:
            fd = os.open(self.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        except OSError:
            return b""
        with os.fdopen(fd, "rb") as f:
            st = os.fstat(f.fileno())
            if not stat.S_ISREG(st.st_mode):
                return b""
            if st.st_size < self.pos:
                self.pos, self.partial = 0, b""
            f.seek(self.pos)
            chunk = f.read(TAIL_READ_MAX)
        self.pos += len(chunk)
        return chunk

    def read(self) -> list[dict[str, Any]]:
        lines = (self.partial + self._chunk()).split(b"\n")
        self.partial = lines.pop()
        if len(self.partial) > TAIL_LINE_MAX:
            self.partial = b""
        out = []
        for line in lines:
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            if isinstance(ev, dict):
                out.append(ev)
        return out

"""Harness-agnostic run loop for one StageTask.

install_skills -> compose prompt -> run harness (subprocess or in-process) -> validate output
-> repair loop (resume if supported, else fresh call) -> StageResult. Never raises for harness failures.

Every transcript event is also appended, as it happens, to <out_dir>/events.jsonl (one JSON line
each), which the worker tails to show the agent's progress live.
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator

from prsec.adapters.harness.base import GatewayConfig, HarnessAdapter, Invocation
from prsec.models import Event, EventKind, StageResult, StageStatus, StageTask, Usage
from prsec.sandbox.entrypoint import contract

STDERR_TAIL_BYTES = 4000
KILL_GRACE_S = 5.0
EVENTS_FILE = "events.jsonl"  # = prsec.adapters.runner.common.EVENTS_FILE (the worker tails it)


class EventLog:
    """Appends events to <out_dir>/events.jsonl as they happen. Never raises: a live stream that
    cannot be written (disk full, out_dir gone) only stops streaming."""

    def __init__(self, path: Path | None):
        self.path = path
        self._lock = threading.Lock()
        self._f: Any = None
        self._broken = path is None

    def write(self, ev: Event) -> None:
        if self._broken:
            return
        with self._lock:
            try:
                if self._f is None:
                    self._f = self.path.open("a", encoding="utf-8")  # type: ignore[union-attr]
                self._f.write(ev.model_dump_json() + "\n")
                self._f.flush()
            except (OSError, ValueError):
                self._broken = True

    def close(self) -> None:
        with self._lock:
            if self._f is not None:
                try:
                    self._f.close()
                except OSError:
                    pass
                self._f = None


@dataclass
class Attempt:
    events: list[Event] = field(default_factory=list)
    exit_code: int | None = None
    timed_out: bool = False
    spawn_error: str | None = None
    stderr_tail: str = ""


def _now() -> datetime:
    return datetime.now(UTC)


def _sys_event(text: str, **data: Any) -> Event:
    return Event(kind=EventKind.system, text=text, data=data, ts=_now())


def _err_event(text: str, **data: Any) -> Event:
    return Event(kind=EventKind.error, text=text, data=data, ts=_now())


def _tail(path: Path, n: int = STDERR_TAIL_BYTES) -> str:
    try:
        with path.open("rb") as f:
            f.seek(0, os.SEEK_END)
            f.seek(max(f.tell() - n, 0))
            return f.read().decode("utf-8", errors="replace")
    except OSError:
        return ""


def _kill_group(proc: subprocess.Popen) -> None:
    for sig, wait in ((signal.SIGTERM, KILL_GRACE_S), (signal.SIGKILL, KILL_GRACE_S)):
        try:
            os.killpg(proc.pid, sig)
        except (ProcessLookupError, PermissionError):
            return
        try:
            proc.wait(timeout=wait)
            return
        except subprocess.TimeoutExpired:
            continue


def _invocation_env(task: StageTask, inv: Invocation) -> dict[str, str]:
    env = dict(os.environ)
    for name in inv.unset_env:
        env.pop(name, None)
    env.update(inv.env)
    env.setdefault("PRSEC_CITE_ROOT", task.workdir)
    bindir = str(Path(sys.executable).parent)
    path = env.get("PATH", "")
    if bindir not in path.split(os.pathsep):
        env["PATH"] = os.pathsep.join(p for p in (bindir, path) if p)
    return env


def _spawn(task: StageTask, inv: Invocation, stderr_log: Path) -> subprocess.Popen:
    with stderr_log.open("wb") as err_f:
        return subprocess.Popen(
            inv.argv,
            cwd=inv.cwd or task.workdir,
            env=_invocation_env(task, inv),
            stdin=subprocess.PIPE if inv.stdin is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=err_f,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            start_new_session=True,
        )


def _tee_lines(proc: subprocess.Popen, stdout_log: Path) -> Iterator[str]:
    assert proc.stdout is not None
    with stdout_log.open("w", encoding="utf-8") as raw:
        for line in proc.stdout:
            raw.write(line)
            yield line.rstrip("\r\n")


def _pump(adapter: HarnessAdapter, lines: Iterator[str], att: Attempt, live: EventLog | None = None) -> None:
    try:
        for ev in adapter.parse_events(lines):
            if ev.ts is None:
                ev = ev.model_copy(update={"ts": _now()})
            att.events.append(ev)
            if live is not None:
                live.write(ev)
    except Exception as e:  # adapters must not raise, but a buggy one must not hang the pipe
        att.events.append(_err_event(f"parse_events raised: {e!r}"))
        deque(lines, maxlen=0)  # drain the rest so the harness never blocks on a full stdout pipe


def _feed_stdin(proc: subprocess.Popen, data: str) -> None:
    try:
        assert proc.stdin is not None
        proc.stdin.write(data)
        proc.stdin.close()
    except (OSError, ValueError):  # BrokenPipeError is an OSError: the harness closed stdin early
        return


def _run_subprocess(
    adapter: HarnessAdapter, task: StageTask, inv: Invocation, deadline: float, n: int, live: EventLog | None = None
) -> Attempt:
    att = Attempt()
    out_dir = Path(task.out_dir)
    stdout_log = out_dir / f"harness.attempt{n}.stdout"
    stderr_log = out_dir / f"harness.attempt{n}.stderr"
    try:
        proc = _spawn(task, inv, stderr_log)
    except OSError as e:
        att.spawn_error = f"failed to start harness {inv.argv[:1]}: {e}"
        return att

    reader = threading.Thread(
        target=_pump, args=(adapter, _tee_lines(proc, stdout_log), att, live), name="harness-stdout", daemon=True
    )
    reader.start()
    if inv.stdin is not None:
        threading.Thread(target=_feed_stdin, args=(proc, inv.stdin), name="harness-stdin", daemon=True).start()

    try:
        att.exit_code = proc.wait(timeout=max(deadline - time.monotonic(), 0.01))
    except subprocess.TimeoutExpired:
        att.timed_out = True
        _kill_group(proc)
        att.exit_code = proc.poll()
    reader.join(timeout=10)
    att.stderr_tail = _tail(stderr_log)
    return att


def _run_inprocess(adapter: HarnessAdapter, task: StageTask, gw: GatewayConfig | None, prompt: str, deadline: float) -> Attempt:
    att = Attempt()
    fn = getattr(adapter, "run_inprocess", None)
    if fn is None:
        att.spawn_error = f"adapter {adapter.name!r} has caps.subprocess=False but no run_inprocess()"
        return att
    box: dict[str, Any] = {}

    def target() -> None:
        try:
            ret = fn(task, gw, prompt)
            if isinstance(ret, tuple):  # (output, events, usage): output already written by the adapter
                ret = ret[1]
            box["events"] = list(ret or [])
        except Exception as e:
            box["error"] = f"{type(e).__name__}: {e}"

    t = threading.Thread(target=target, name="harness-inprocess", daemon=True)
    t.start()
    t.join(timeout=max(deadline - time.monotonic(), 0.01))
    if t.is_alive():
        att.timed_out = True
        return att
    att.events = [e if e.ts else e.model_copy(update={"ts": _now()}) for e in box.get("events", [])]
    if "error" in box:
        att.exit_code = 1
        att.stderr_tail = box["error"]
    else:
        att.exit_code = 0
    return att


def _safe(fn: Any, default: Any, *args: Any) -> Any:
    try:
        return fn(*args)
    except Exception:
        return default


def _stash_invalid(task: StageTask, n: int) -> str | None:
    src = Path(task.output_path)
    if not src.exists():
        return None
    dst = src.with_name(f"{src.stem}.attempt{n}.invalid{src.suffix or '.json'}")
    try:
        shutil.move(src, dst)
        return str(dst)
    except OSError:
        return None


def gateway_spend(gw: GatewayConfig) -> float | None:
    """Spend the gateway booked on this task's key; None when unknown or the key is shared."""
    if not gw.per_task_key:
        return None
    from prsec.gateway import self_spend

    return _safe(self_spend, None, gw.base_url, gw.api_key)


def _attempt_mode(n: int, prompt: str | None) -> str:
    if n == 1:
        return "fresh"
    return "resume" if prompt is None else "repair-fresh"


@dataclass
class _Run:
    """Mutable state of one run_task call; result() snapshots it as a StageResult."""

    task: StageTask
    adapter: HarnessAdapter
    gw: GatewayConfig | None
    deadline: float
    started: float = field(default_factory=time.monotonic)
    version: str | None = None
    transcript: list[Event] = field(default_factory=list)
    usage: Usage = field(default_factory=Usage)
    errors: list[str] = field(default_factory=list)
    output: dict[str, Any] | None = None
    status: StageStatus = StageStatus.output_invalid
    attempts: int = 0
    # repair-loop inputs for the next attempt: prompt None means "resume session with resume_prompt"
    prompt: str | None = None
    session: str | None = None
    resume_prompt: str = ""
    prev_raw: str | None = None
    live: EventLog = field(default_factory=lambda: EventLog(None))

    def record(self, *events: Event) -> None:
        """Add events to the transcript and stream them (subprocess events are streamed by _pump)."""
        for ev in events:
            self.transcript.append(ev)
            self.live.write(ev)

    def result(self) -> StageResult:
        task = self.task
        return StageResult(
            task_id=task.task_id, stage=task.stage, status=self.status, output=self.output, errors=self.errors,
            transcript=self.transcript, usage=self.usage, harness=self.adapter.name, harness_version=self.version,
            model=self.gw.model if self.gw else task.model_alias, attempts=self.attempts,
            duration_s=round(time.monotonic() - self.started, 3),
        )

    def fail(self, status: StageStatus, errors: list[str], **data: Any) -> StageResult:
        self.status, self.errors = status, errors
        self.record(_err_event(errors[0], **data))
        return self.result()

    def setup(self) -> None:
        task = self.task
        Path(task.out_dir).mkdir(parents=True, exist_ok=True)
        Path(task.output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(task.output_path).unlink(missing_ok=True)
        (Path(task.out_dir) / EVENTS_FILE).unlink(missing_ok=True)
        self.live = EventLog(Path(task.out_dir) / EVENTS_FILE)
        contract.write_schema(task)
        self.adapter.install_skills(task)

    def _build_invocation(self) -> Invocation:
        task, adapter, gw, prompt = self.task, self.adapter, self.gw, self.prompt
        inv: Invocation | None = None
        if prompt is None:
            inv = adapter.build_resume(task, gw, self.session, self.resume_prompt)  # type: ignore[arg-type]
            if inv is None:  # resume refused: fall back to a fresh repair call
                prompt = contract.repair_prompt_fresh(task, self.errors, self.prev_raw)
        if inv is None:
            inv = adapter.build(task, gw, prompt)  # type: ignore[arg-type]
        return inv

    def run_attempt(self) -> Attempt:
        task, adapter = self.task, self.adapter
        if not adapter.caps.subprocess:
            prompt = self.prompt or contract.repair_prompt_fresh(task, self.errors, self.prev_raw)
            att = _run_inprocess(adapter, task, self.gw, prompt, self.deadline)
            for ev in att.events:  # in-process adapters hand over their events at the end
                self.live.write(ev)
            return att
        try:
            inv = self._build_invocation()
        except Exception as e:
            return Attempt(spawn_error=f"adapter failed to build invocation: {type(e).__name__}: {e}")
        return _run_subprocess(adapter, task, inv, self.deadline, self.attempts, self.live)

    def add_usage(self, events: list[Event]) -> None:
        self.usage = self.usage + _safe(self.adapter.usage, Usage(), events)
        # Harness-reported cost is best effort (several harnesses report $0 behind the gateway);
        # the gateway's spend on a per-task key is authoritative.
        booked = gateway_spend(self.gw) if self.gw is not None else None
        if booked is not None and booked > self.usage.usd:
            self.usage = self.usage.model_copy(update={"usd": booked})

    def stop(self, att: Attempt, errs: list[str], max_attempts: int) -> StageResult | None:
        """The final result when an invalid attempt must not be repaired, else None."""
        limits = self.task.limits
        if att.timed_out or time.monotonic() >= self.deadline:
            return self.fail(StageStatus.timeout, [f"wall clock limit of {limits.wall_clock_s}s exceeded", *errs])
        if self.usage.usd > limits.usd_budget:
            return self.fail(
                StageStatus.budget_exceeded,
                [f"usage ${self.usage.usd:.4f} exceeds budget ${limits.usd_budget:.4f}", *errs],
            )
        if att.exit_code not in (0, None) and self.prev_raw is None:
            errors = [f"harness exited with code {att.exit_code} without writing output"]
            if att.stderr_tail:
                errors.append(f"stderr tail:\n{att.stderr_tail}")
            return self.fail(StageStatus.harness_error, errors, stderr_tail=att.stderr_tail)
        if self.attempts >= max_attempts:
            self.status = StageStatus.output_invalid
            return self.result()
        return None

    def prepare_repair(self, att: Attempt) -> None:
        moved_to = _stash_invalid(self.task, self.attempts)
        adapter = self.adapter
        self.session = _safe(adapter.session_id, None, att.events) if adapter.caps.subprocess else None
        if adapter.caps.resume and self.session:
            self.prompt, self.resume_prompt = None, contract.repair_prompt_resume(self.task, self.errors, moved_to)
        else:
            self.prompt = contract.repair_prompt_fresh(self.task, self.errors, self.prev_raw)


def run_task(task: StageTask, adapter: HarnessAdapter, gw: GatewayConfig | None) -> StageResult:
    started = time.monotonic()
    run = _Run(task, adapter, gw, deadline=started + task.limits.wall_clock_s, started=started)
    run.version = _safe(adapter.version, None)
    try:
        return _run_loop(run)
    finally:
        run.live.close()


def _run_loop(run: _Run) -> StageResult:
    task = run.task

    try:
        run.setup()
    except Exception as e:
        return run.fail(StageStatus.harness_error, [f"setup failed: {type(e).__name__}: {e}"])

    run.prompt = contract.compose_prompt(task)
    max_attempts = 1 + max(task.limits.repair_attempts, 0)

    while True:
        run.attempts += 1
        mode = _attempt_mode(run.attempts, run.prompt)
        run.record(_sys_event(f"attempt {run.attempts} ({mode})", attempt=run.attempts, mode=mode))

        att = run.run_attempt()
        run.transcript.extend(att.events)
        run.add_usage(att.events)
        if att.spawn_error:
            return run.fail(StageStatus.harness_error, [att.spawn_error])

        run.output, errs, run.prev_raw = contract.validate_output(task)
        if not errs:
            run.status, run.errors = StageStatus.ok, []
            return run.result()
        run.errors = errs
        run.record(_sys_event("output invalid", attempt=run.attempts, errors=errs))

        final = run.stop(att, errs, max_attempts)
        if final is not None:
            return final
        run.prepare_repair(att)

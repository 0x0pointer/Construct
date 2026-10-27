"""Harness-agnostic run loop for one StageTask.

install_skills -> compose prompt -> run harness (subprocess or in-process) -> validate output
-> repair loop (resume if supported, else fresh call) -> StageResult. Never raises for harness failures.
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator

from prsec.adapters.harness.base import GatewayConfig, HarnessAdapter, Invocation
from prsec.models import Event, EventKind, StageResult, StageStatus, StageTask, Usage
from prsec.sandbox.entrypoint import contract

STDERR_TAIL_BYTES = 4000
KILL_GRACE_S = 5.0


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


def _run_subprocess(adapter: HarnessAdapter, task: StageTask, inv: Invocation, deadline: float, n: int) -> Attempt:
    att = Attempt()
    out_dir = Path(task.out_dir)
    stdout_log = out_dir / f"harness.attempt{n}.stdout"
    stderr_log = out_dir / f"harness.attempt{n}.stderr"
    try:
        with stderr_log.open("wb") as err_f:
            proc = subprocess.Popen(
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
    except OSError as e:
        att.spawn_error = f"failed to start harness {inv.argv[:1]}: {e}"
        return att

    def lines() -> Iterator[str]:
        assert proc.stdout is not None
        with stdout_log.open("w", encoding="utf-8") as raw:
            for line in proc.stdout:
                raw.write(line)
                yield line.rstrip("\r\n")

    def pump() -> None:
        it = lines()
        try:
            for ev in adapter.parse_events(it):
                if ev.ts is None:
                    ev = ev.model_copy(update={"ts": _now()})
                att.events.append(ev)
        except Exception as e:  # adapters must not raise, but a buggy one must not hang the pipe
            att.events.append(_err_event(f"parse_events raised: {e!r}"))
            for _ in it:
                pass

    reader = threading.Thread(target=pump, name="harness-stdout", daemon=True)
    reader.start()
    if inv.stdin is not None:
        def feed() -> None:
            try:
                assert proc.stdin is not None
                proc.stdin.write(inv.stdin)
                proc.stdin.close()
            except (BrokenPipeError, OSError, ValueError):
                pass

        threading.Thread(target=feed, name="harness-stdin", daemon=True).start()

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


def run_task(task: StageTask, adapter: HarnessAdapter, gw: GatewayConfig | None) -> StageResult:
    started = time.monotonic()
    deadline = started + task.limits.wall_clock_s
    transcript: list[Event] = []
    usage = Usage()
    errors: list[str] = []
    output: dict[str, Any] | None = None
    status = StageStatus.output_invalid
    attempts = 0
    model = gw.model if gw else task.model_alias
    version = _safe(adapter.version, None)

    def result() -> StageResult:
        return StageResult(
            task_id=task.task_id, stage=task.stage, status=status, output=output, errors=errors,
            transcript=transcript, usage=usage, harness=adapter.name, harness_version=version,
            model=model, attempts=attempts, duration_s=round(time.monotonic() - started, 3),
        )

    try:
        Path(task.out_dir).mkdir(parents=True, exist_ok=True)
        Path(task.output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(task.output_path).unlink(missing_ok=True)
        contract.write_schema(task)
        adapter.install_skills(task)
    except Exception as e:
        status, errors = StageStatus.harness_error, [f"setup failed: {type(e).__name__}: {e}"]
        transcript.append(_err_event(errors[0]))
        return result()

    prompt = contract.compose_prompt(task)
    session: str | None = None
    resume_prompt = ""
    prev_raw: str | None = None
    max_attempts = 1 + max(task.limits.repair_attempts, 0)

    while True:
        attempts += 1
        mode = "fresh" if attempts == 1 else ("resume" if prompt is None else "repair-fresh")
        transcript.append(_sys_event(f"attempt {attempts} ({mode})", attempt=attempts, mode=mode))

        if adapter.caps.subprocess:
            inv: Invocation | None = None
            try:
                if prompt is None:
                    inv = adapter.build_resume(task, gw, session, resume_prompt)  # type: ignore[arg-type]
                    if inv is None:  # resume refused: fall back to a fresh repair call
                        prompt = contract.repair_prompt_fresh(task, errors, prev_raw)
                if inv is None:
                    inv = adapter.build(task, gw, prompt)  # type: ignore[arg-type]
            except Exception as e:
                att = Attempt(spawn_error=f"adapter failed to build invocation: {type(e).__name__}: {e}")
            else:
                att = _run_subprocess(adapter, task, inv, deadline, attempts)
        else:
            att = _run_inprocess(adapter, task, gw, prompt or contract.repair_prompt_fresh(task, errors, prev_raw), deadline)

        transcript.extend(att.events)
        usage = usage + _safe(adapter.usage, Usage(), att.events)
        # Harness-reported cost is best effort (several harnesses report $0 behind the gateway);
        # the gateway's spend on a per-task key is authoritative.
        booked = gateway_spend(gw) if gw is not None else None
        if booked is not None and booked > usage.usd:
            usage = usage.model_copy(update={"usd": booked})

        if att.spawn_error:
            status, errors = StageStatus.harness_error, [att.spawn_error]
            transcript.append(_err_event(att.spawn_error))
            return result()

        output, errs, prev_raw = contract.validate_output(task)
        if not errs:
            status, errors = StageStatus.ok, []
            return result()
        errors = errs
        transcript.append(_sys_event("output invalid", attempt=attempts, errors=errs))

        if att.timed_out or time.monotonic() >= deadline:
            status = StageStatus.timeout
            errors = [f"wall clock limit of {task.limits.wall_clock_s}s exceeded", *errs]
            transcript.append(_err_event(errors[0]))
            return result()
        if usage.usd > task.limits.usd_budget:
            status = StageStatus.budget_exceeded
            errors = [f"usage ${usage.usd:.4f} exceeds budget ${task.limits.usd_budget:.4f}", *errs]
            transcript.append(_err_event(errors[0]))
            return result()
        if att.exit_code not in (0, None) and prev_raw is None:
            status = StageStatus.harness_error
            errors = [f"harness exited with code {att.exit_code} without writing output"]
            if att.stderr_tail:
                errors.append(f"stderr tail:\n{att.stderr_tail}")
            transcript.append(_err_event(errors[0], stderr_tail=att.stderr_tail))
            return result()
        if attempts >= max_attempts:
            status = StageStatus.output_invalid
            return result()

        # ---- repair
        moved_to = _stash_invalid(task, attempts)
        session = _safe(adapter.session_id, None, att.events) if adapter.caps.subprocess else None
        if adapter.caps.resume and session:
            prompt, resume_prompt = None, contract.repair_prompt_resume(task, errors, moved_to)
        else:
            prompt = contract.repair_prompt_fresh(task, errors, prev_raw)

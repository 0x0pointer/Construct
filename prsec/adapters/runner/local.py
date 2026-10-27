"""LocalRunner: runs the stage entrypoint as a host subprocess (dev mode, conformance suite).

No network isolation: the harness reaches whatever the host reaches. Phase 2 dynamic environments
are not supported (the orchestrator skips dynamic validation with reason `runner_unsupported`).
"""
from __future__ import annotations

import logging
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path, PurePosixPath

import prsec
from prsec.adapters.protocols import WorkbenchSpec
from prsec.adapters.runner.common import GRACE_S, RESULT_FILE, load_result, tail, write_task
from prsec.dynamic.results import EnvInfo, EnvRequest, ReplayResult
from prsec.models import StageResult, StageTask

log = logging.getLogger(__name__)
LOG_FILE = "workbench.log"


def _remap(path: str, old_root: str, new_root: Path) -> str:
    p, old = PurePosixPath(path), PurePosixPath(old_root)
    if p == old or old in p.parents:
        return str(new_root / p.relative_to(old))
    return str(new_root / p.name)


def _rewrite_prompt(prompt: str, roots: dict[str, Path]) -> str:
    """Replace container roots rendered into the prompt (e.g. `/work/in/diff.patch`) by host dirs."""
    for old in sorted(roots, key=len, reverse=True):
        pattern = re.compile(r"(?<![\w./-])" + re.escape(old.rstrip("/")) + r"(?![\w-]|\.\w)")
        prompt = pattern.sub(lambda _m, new=str(roots[old]): new, prompt)
    return prompt


def host_task(spec: WorkbenchSpec) -> StageTask:
    """Rewrite the container paths of spec.task (fields and the rendered prompt) to the host dirs of spec."""
    t = spec.task
    roots = {t.workdir: spec.src_dir, t.in_dir: spec.in_dir, t.out_dir: spec.out_dir, t.skills_dir: spec.skills_dir}
    return t.model_copy(update={
        "prompt_md": _rewrite_prompt(t.prompt_md, roots),
        "workdir": str(spec.src_dir),
        "in_dir": str(spec.in_dir),
        "out_dir": str(spec.out_dir),
        "skills_dir": str(spec.skills_dir),
        "output_path": _remap(t.output_path, t.out_dir, spec.out_dir),
    })


class LocalRunner:
    name = "local"
    supports_envs = False  # no containers: create_env/run_replay raise NotImplementedError

    def __init__(self, python: str | None = None, grace_s: float = GRACE_S):
        self.python = python or sys.executable
        self.grace_s = grace_s

    def create_scan_network(self, scan_id: int) -> str:
        log.warning("LocalRunner provides no network isolation (scan %s)", scan_id)
        return "host"

    def destroy_scan(self, scan_id: int) -> None:
        log.debug("LocalRunner has nothing to tear down (scan %s)", scan_id)

    def create_env(self, scan_id: int, env_name: str, req: EnvRequest) -> EnvInfo:
        raise NotImplementedError("runner_unsupported")

    def destroy_env(self, scan_id: int, env_name: str) -> None:
        log.debug("LocalRunner has no dynamic envs (scan %s, env %s)", scan_id, env_name)

    def run_replay(self, spec: WorkbenchSpec) -> ReplayResult:
        raise NotImplementedError("runner_unsupported")

    def _env(self, spec: WorkbenchSpec) -> dict[str, str]:
        env = dict(os.environ)
        env.update(spec.env)
        if spec.harness_volume:
            env["PRSEC_HARNESS_HOME"] = str(spec.harness_volume)
        root = str(Path(prsec.__file__).resolve().parent.parent)
        env["PYTHONPATH"] = os.pathsep.join(p for p in (root, env.get("PYTHONPATH", "")) if p)
        env["PRSEC_CITE_ROOT"] = str(spec.src_dir)
        return env

    def run_workbench(self, spec: WorkbenchSpec) -> StageResult:
        task = host_task(spec)
        for d in (spec.in_dir, spec.out_dir):
            Path(d).mkdir(parents=True, exist_ok=True)
        task_json = write_task(task, Path(spec.in_dir))
        (Path(spec.out_dir) / RESULT_FILE).unlink(missing_ok=True)
        log_path = Path(spec.out_dir) / LOG_FILE
        started = time.monotonic()
        killed = False
        with log_path.open("wb") as logf:
            proc = subprocess.Popen(
                [self.python, "-m", "prsec.sandbox.entrypoint.main", str(task_json)],
                cwd=str(spec.src_dir), env=self._env(spec), stdin=subprocess.DEVNULL,
                stdout=logf, stderr=subprocess.STDOUT, start_new_session=True,
            )
            try:
                code = proc.wait(timeout=task.limits.wall_clock_s + self.grace_s)
            except subprocess.TimeoutExpired:
                killed = True
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                code = proc.wait()
        log_tail = tail(log_path.read_text(encoding="utf-8", errors="replace"))
        return load_result(
            task, Path(spec.out_dir), killed=killed, exit_code=code, log_tail=log_tail,
            duration_s=time.monotonic() - started,
        )

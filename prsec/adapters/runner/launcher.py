"""LauncherRunner: DockerRunner without the Docker socket.

The worker keeps preparing task.json and reading result.json in the shared work dir; starting
containers and networks is delegated over HTTP to the launcher service (prsec.launcher), which
holds the socket and only runs the fixed workbench recipe.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import httpx

from prsec.adapters.protocols import WorkbenchSpec
from prsec.adapters.runner.common import GRACE_S, RESULT_FILE, load_result, tail, write_task
from prsec.adapters.runner.docker import LOG_FILE
from prsec.config import settings
from prsec.models import StageResult

HTTP_SLACK_S = 60  # on top of the container timeout: kill, log collection and removal


class LauncherError(RuntimeError):
    pass


class LauncherRunner:
    name = "launcher"

    def __init__(self, url: str | None = None, token: str | None = None, grace_s: float = GRACE_S,
                 transport: httpx.BaseTransport | None = None):
        s = settings()
        self.url = (url or s.launcher_url).rstrip("/")
        self.token = token if token is not None else s.launcher_token
        self.grace_s = grace_s
        self._transport = transport

    def _call(self, method: str, path: str, timeout: float = 30, **kw: Any) -> dict[str, Any]:
        with httpx.Client(base_url=self.url, transport=self._transport, timeout=timeout,
                          headers={"Authorization": f"Bearer {self.token}"}) as c:
            r = c.request(method, path, **kw)
        if r.status_code >= 400:
            raise LauncherError(f"launcher {method} {path} -> {r.status_code}: {r.text[:500]}")
        return r.json()

    def create_scan_network(self, scan_id: int) -> str:
        return str(self._call("POST", f"/scans/{int(scan_id)}/network")["network"])

    def destroy_scan(self, scan_id: int) -> None:
        self._call("DELETE", f"/scans/{int(scan_id)}")

    def run_container(self, spec: WorkbenchSpec, timeout_s: float) -> tuple[int | None, str, bool]:
        body = {
            "scan_id": spec.scan_id, "task": spec.task.model_dump(mode="json"), "image": spec.image,
            "harness_volume": spec.harness_volume, "src_dir": str(spec.src_dir), "in_dir": str(spec.in_dir),
            "out_dir": str(spec.out_dir), "skills_dir": str(spec.skills_dir), "env": spec.env,
            "network": spec.network, "timeout_s": timeout_s,
        }
        r = self._call("POST", "/run", timeout=timeout_s + HTTP_SLACK_S, json=body)
        return r["exit_code"], r["logs"], bool(r["killed"])

    def run_workbench(self, spec: WorkbenchSpec) -> StageResult:
        t = spec.task
        write_task(t, Path(spec.in_dir))
        (Path(spec.out_dir) / RESULT_FILE).unlink(missing_ok=True)
        started = time.monotonic()
        try:
            code, logs, killed = self.run_container(spec, t.limits.wall_clock_s + self.grace_s)
        except Exception as e:
            code, logs, killed = None, f"failed to run workbench container: {type(e).__name__}: {e}", False
        Path(spec.out_dir).mkdir(parents=True, exist_ok=True)
        (Path(spec.out_dir) / LOG_FILE).write_text(logs)
        return load_result(
            t, Path(spec.out_dir), killed=killed, exit_code=code, log_tail=tail(logs),
            duration_s=time.monotonic() - started,
        )

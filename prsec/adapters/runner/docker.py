"""DockerRunner: one hardened workbench container per StageTask on a per-scan internal network.

The scan network is an internal bridge (no route out); the LLM gateway container is attached to it,
so the gateway is the only reachable service. Optional gVisor via PRSEC_DOCKER_RUNTIME=runsc.
"""
from __future__ import annotations

import logging
import os
import re
import secrets
import time
from pathlib import Path
from typing import Any

from prsec.adapters.protocols import WorkbenchSpec
from prsec.adapters.runner.common import GRACE_S, RESULT_FILE, load_result, tail, write_task
from prsec.models import StageResult

log = logging.getLogger(__name__)

LOG_FILE = "workbench.log"
NONROOT = "65532:65532"
LABEL_SCAN = "prsec.scan_id"
LABEL_TASK = "prsec.task_id"
ENTRYPOINT = ["prsec-stage"]  # set explicitly: per-repo workbench images need not declare it


def network_name(scan_id: int) -> str:
    return f"prsec-scan-{scan_id}"


def container_name(task_id: str) -> str:
    return f"prsec-wb-{re.sub(r'[^a-zA-Z0-9_.-]', '_', task_id)[:100]}-{secrets.token_hex(3)}"


def harness_mount(harness: str) -> str:
    return f"/opt/harness/{harness}/current"


class DockerRunner:
    name = "docker"

    def __init__(self, client: Any = None, grace_s: float = GRACE_S):
        self._client = client
        self.grace_s = grace_s
        self.gateway_container = os.environ.get("PRSEC_GATEWAY_CONTAINER", "prsec-llm-gateway")
        self.gateway_alias = os.environ.get("PRSEC_GATEWAY_ALIAS", "llm-gateway")
        self.runtime = os.environ.get("PRSEC_DOCKER_RUNTIME") or None
        self.mem_limit = os.environ.get("PRSEC_DOCKER_MEM", "4g")
        self.cpus = float(os.environ.get("PRSEC_DOCKER_CPUS", "2"))
        self.pids_limit = int(os.environ.get("PRSEC_DOCKER_PIDS", "512"))
        self.tmp_size = os.environ.get("PRSEC_DOCKER_TMP_SIZE", "1g")

    @property
    def client(self) -> Any:
        if self._client is None:
            import docker

            self._client = docker.from_env()
        return self._client

    # ------------------------------------------------------------- network

    def create_scan_network(self, scan_id: int) -> str:
        from docker.errors import APIError, NotFound

        name = network_name(scan_id)
        try:
            net = self.client.networks.get(name)
        except NotFound:
            net = self.client.networks.create(
                name, driver="bridge", internal=True,
                labels={LABEL_SCAN: str(scan_id), "prsec": "scan-network"},
            )
        if not net.attrs.get("Internal", True):
            raise RuntimeError(f"network {name} exists but is not internal; refusing to use it")
        try:
            net.connect(self.gateway_container, aliases=[self.gateway_alias])
        except NotFound:
            # without the gateway every stage would fail and the scan would look clean: fail the scan
            raise RuntimeError(f"gateway container {self.gateway_container!r} not found; scan network {name} would have no LLM access") from None
        except APIError as e:
            if "already exists" not in str(e) and "already attached" not in str(e):
                raise
        return name

    def destroy_scan(self, scan_id: int) -> None:
        from docker.errors import APIError, NotFound

        for c in self.client.containers.list(all=True, filters={"label": f"{LABEL_SCAN}={scan_id}"}):
            try:
                c.remove(force=True)
            except (NotFound, APIError):
                pass
        try:
            net = self.client.networks.get(network_name(scan_id))
        except NotFound:
            return
        try:
            net.disconnect(self.gateway_container, force=True)
        except (NotFound, APIError):
            pass
        try:
            net.remove()
        except NotFound:
            pass

    # ----------------------------------------------------------- container

    def _user(self) -> str:
        if u := os.environ.get("PRSEC_DOCKER_USER"):
            return u
        uid = os.getuid()
        return f"{uid}:{os.getgid()}" if uid != 0 else NONROOT

    def container_kwargs(self, spec: WorkbenchSpec, command: list[str], entrypoint: list[str] | None = None) -> dict[str, Any]:
        t = spec.task
        home = f"{t.out_dir.rstrip('/')}/.home"
        volumes: dict[str, dict[str, str]] = {
            str(spec.src_dir): {"bind": t.workdir, "mode": "ro"},
            str(spec.skills_dir): {"bind": t.skills_dir, "mode": "ro"},
            str(spec.in_dir): {"bind": t.in_dir, "mode": "rw"},
            str(spec.out_dir): {"bind": t.out_dir, "mode": "rw"},
        }
        env = {
            **spec.env,
            "HOME": home,
            "XDG_CONFIG_HOME": f"{home}/.config",
            "XDG_CACHE_HOME": f"{home}/.cache",
            "TMPDIR": "/tmp",
            "PRSEC_CITE_ROOT": t.workdir,
        }
        if spec.harness_volume:
            volumes[str(spec.harness_volume)] = {"bind": harness_mount(t.harness), "mode": "ro"}
            env["PRSEC_HARNESS_HOME"] = harness_mount(t.harness)
        kw: dict[str, Any] = {
            "image": spec.image,
            "command": command,
            "detach": True,
            "name": container_name(t.task_id),
            "labels": {LABEL_SCAN: str(spec.scan_id), LABEL_TASK: t.task_id},
            "user": self._user(),
            "working_dir": t.workdir,
            "environment": env,
            "volumes": volumes,
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "read_only": True,
            "tmpfs": {"/tmp": f"rw,nosuid,nodev,size={self.tmp_size},mode=1777"},
            "pids_limit": self.pids_limit,
            "mem_limit": self.mem_limit,
            "memswap_limit": self.mem_limit,
            "nano_cpus": int(self.cpus * 1e9),
            "ipc_mode": "private",
            "init": True,
        }
        if entrypoint is not None:  # explicit, so the image's own ENTRYPOINT is never prepended twice
            kw["entrypoint"] = entrypoint
        if spec.network:
            kw["network"] = spec.network
        else:
            kw["network_mode"] = "none"
        if self.runtime:
            kw["runtime"] = self.runtime
        return kw

    def _prepare_dirs(self, spec: WorkbenchSpec) -> None:
        for d in (Path(spec.in_dir), Path(spec.out_dir), Path(spec.out_dir) / ".home"):
            d.mkdir(parents=True, exist_ok=True)
            if self._user() == NONROOT:
                os.chmod(d, 0o777)

    def run_container(self, spec: WorkbenchSpec, command: list[str], timeout_s: float,
                      entrypoint: list[str] | None = None) -> tuple[int | None, str, bool]:
        """Run one container to completion. Returns (exit code, combined logs, killed)."""
        from docker.errors import APIError, NotFound

        self._prepare_dirs(spec)
        container = self.client.containers.run(**self.container_kwargs(spec, command, entrypoint))
        killed = False
        code: int | None = None
        try:
            try:
                code = int(container.wait(timeout=timeout_s).get("StatusCode", -1))
            except Exception:  # requests ReadTimeout / ConnectionError on wall-clock expiry
                killed = True
                try:
                    container.kill()
                except (NotFound, APIError):
                    pass
            try:
                logs = container.logs(stdout=True, stderr=True).decode("utf-8", errors="replace")
            except (NotFound, APIError):
                logs = ""
        finally:
            try:
                container.remove(force=True)
            except (NotFound, APIError):
                pass
        return code, logs, killed

    def run_workbench(self, spec: WorkbenchSpec) -> StageResult:
        t = spec.task
        write_task(t, Path(spec.in_dir))
        (Path(spec.out_dir) / RESULT_FILE).unlink(missing_ok=True)
        started = time.monotonic()
        command = [f"{t.in_dir.rstrip('/')}/task.json"]
        try:
            code, logs, killed = self.run_container(spec, command, t.limits.wall_clock_s + self.grace_s, entrypoint=ENTRYPOINT)
        except Exception as e:
            code, logs, killed = None, f"failed to run workbench container: {type(e).__name__}: {e}", False
        (Path(spec.out_dir) / LOG_FILE).write_text(logs)
        return load_result(
            t, Path(spec.out_dir), killed=killed, exit_code=code, log_tail=tail(logs),
            duration_s=time.monotonic() - started,
        )

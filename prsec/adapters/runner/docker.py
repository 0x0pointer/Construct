"""DockerRunner: one hardened workbench container per StageTask on a per-scan internal network.

The scan network is an internal bridge (no route out); the LLM gateway container is attached to it,
so the gateway is the only reachable service. Optional gVisor via PRSEC_DOCKER_RUNTIME=runsc.

Phase 2 dynamic environments get their own internal network (prsec-scan-<id>-<env>) with a sink
container (DNS for the workbench, catch-all HTTP/TLS recorder), catalog services, and optionally
the LLM gateway and the egress proxy attached.
"""
from __future__ import annotations

import logging
import os
import re
import secrets
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from prsec.adapters.protocols import WorkbenchSpec
from prsec.adapters.runner.common import GRACE_S, RESULT_FILE, load_result, tail, write_nofollow, write_task
from prsec.adapters.runner.env import (
    EGRESS_ALIAS,
    LABEL_ENV,
    LABEL_ENV_DIR,
    LABEL_LLM,
    REPLAY_COMMAND,
    REPLAY_ENTRYPOINT,
    SINK_ALIAS,
    SINK_MOUNT,
    check_env_name,
    check_env_request,
    checked_resolv,
    checked_sink_dir,
    env_network_name,
    load_replay_result,
    make_sink_dir,
    replay_result_path,
    replay_run_id,
    write_hosts,
    write_resolv,
    write_stubs,
)
from prsec.config import settings
from prsec.dynamic.catalog import CatalogEntry, load_catalog
from prsec.dynamic.results import APP_DIR, EnvInfo, EnvRequest, ReplayResult, ServiceRequest
from prsec.models import StageResult

log = logging.getLogger(__name__)

LOG_FILE = "workbench.log"
NONROOT = "65532:65532"
LABEL_SCAN = "prsec.scan_id"
LABEL_TASK = "prsec.task_id"
LABEL_SERVICE = "prsec.service"
SINK_COMMAND = ["prsec-sink", "--data-dir", SINK_MOUNT]
SINK_READY = b"sink up on"  # logged by prsec-sink once DNS, HTTP and TLS listen
HARDENED = {"cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"]}
ENTRYPOINT = ["prsec-stage"]  # set explicitly: per-repo workbench images need not declare it


def network_name(scan_id: int) -> str:
    return f"prsec-scan-{scan_id}"


def container_name(task_id: str) -> str:
    return f"prsec-wb-{re.sub(r'[^a-zA-Z0-9_.-]', '_', task_id)[:100]}-{secrets.token_hex(3)}"


def harness_mount(harness: str) -> str:
    return f"/opt/harness/{harness}/current"


def _give_to_nonroot(d: Path, uid_remapped: bool) -> None:
    """Make a bind-mounted dir writable for the container's NONROOT uid.

    A root runner on a plain daemon chowns the dir to NONROOT, so it never has to be world-writable.
    A runner that cannot chown (non-root with PRSEC_DOCKER_USER=NONROOT), or a daemon that remaps
    uids (userns-remap / rootless, where container 65532 is a different host uid), falls back to a
    world-writable dir as before; the dir is a fresh per-task dir under the private work root.
    """
    if not uid_remapped:
        uid, gid = (int(x) for x in NONROOT.split(":"))
        try:
            os.chown(d, uid, gid)
            return
        except PermissionError:
            log.info("cannot chown %s to %s; making it world-writable instead", d, NONROOT)
    os.chmod(d, 0o777)  # NOSONAR(S2612) fallback only: see the docstring for why chown cannot work here


class DockerRunner:
    name = "docker"
    supports_envs = True

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
        # phase 2: per-env infrastructure
        self.egress_container = os.environ.get("PRSEC_EGRESS_CONTAINER", "prsec-egress-proxy")
        self.sink_image = os.environ.get("PRSEC_SINK_IMAGE") or os.environ.get("PRSEC_IMAGE") or "prsec/prsec:latest"
        self.service_mem = os.environ.get("PRSEC_SERVICE_MEM", "1g")
        self.service_pids = int(os.environ.get("PRSEC_SERVICE_PIDS", "512"))
        self.service_cpus = float(os.environ.get("PRSEC_SERVICE_CPUS", "1"))
        self.service_health_s = float(os.environ.get("PRSEC_SERVICE_HEALTH_S", "120"))
        # The sink parses untrusted traffic: same runtime as the workbench unless overridden (set
        # PRSEC_SINK_RUNTIME=runc if the configured runtime cannot apply the port sysctl below).
        self.sink_runtime = os.environ.get("PRSEC_SINK_RUNTIME", self.runtime or "") or None
        self.sink_cpus = float(os.environ.get("PRSEC_SINK_CPUS", "1"))
        self.poll_s = 1.0

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
        from docker.errors import NotFound

        for c in self.client.containers.list(all=True, filters={"label": f"{LABEL_SCAN}={scan_id}"}):
            _remove_container(c)
        for net in self.client.networks.list(filters={"label": [f"{LABEL_SCAN}={scan_id}", LABEL_ENV]}):
            self._remove_network(net, (self.gateway_container, self.egress_container))
        try:
            net = self.client.networks.get(network_name(scan_id))
        except NotFound:
            return
        self._remove_network(net, (self.gateway_container,))

    def _remove_network(self, net: Any, attached: tuple[str, ...]) -> None:
        """Detach the shared infrastructure containers, then remove the network."""
        from docker.errors import APIError, NotFound

        for name in attached:
            try:
                net.disconnect(name, force=True)
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
            # '/tmp' is inside the container: the per-container tmpfs below, never a shared host dir.
            "TMPDIR": "/tmp",  # NOSONAR(S5443)
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
            "tmpfs": {"/tmp": f"rw,nosuid,nodev,size={self.tmp_size},mode=1777"},  # NOSONAR(S5443) private per-container tmpfs
            "pids_limit": self.pids_limit,
            "mem_limit": self.mem_limit,
            "memswap_limit": self.mem_limit,
            "nano_cpus": int(self.cpus * 1e9),
            "ipc_mode": "private",
            "init": True,
        }
        if entrypoint is not None:  # explicit, so the image's own ENTRYPOINT is never prepended twice
            kw["entrypoint"] = entrypoint
        if spec.env_name:
            self._join_env(spec, kw)
        elif spec.network:
            kw["network"] = spec.network
        else:
            kw["network_mode"] = "none"
        if self.runtime:
            kw["runtime"] = self.runtime
        return kw

    def _join_env(self, spec: WorkbenchSpec, kw: dict[str, Any]) -> None:
        """Workbench inside a dynamic env: env network, the sink as DNS, app_dir writable at /work/app."""
        env_dir = self._env_label(spec.scan_id, check_env_name(spec.env_name or ""), LABEL_ENV_DIR)
        if not env_dir:
            raise RuntimeError(f"dynamic env {spec.env_name!r} of scan {spec.scan_id} does not exist")
        kw["network"] = env_network_name(spec.scan_id, spec.env_name or "")
        kw["volumes"][str(checked_resolv(env_dir))] = {"bind": "/etc/resolv.conf", "mode": "ro"}
        if spec.app_dir is not None:
            kw["volumes"][str(spec.app_dir)] = {"bind": APP_DIR, "mode": "rw"}

    def _uid_remapped(self) -> bool:
        """True when the daemon maps container uids to other host uids (userns-remap or rootless)."""
        try:
            opts = self.client.info().get("SecurityOptions")
        except Exception:  # unreachable daemon: run_container fails right after with the real error
            return False
        return isinstance(opts, list) and any("name=userns" in o or "name=rootless" in o for o in opts if isinstance(o, str))

    def _prepare_dirs(self, spec: WorkbenchSpec) -> None:
        nonroot = self._user() == NONROOT
        remapped = nonroot and self._uid_remapped()
        dirs = [Path(spec.in_dir), Path(spec.out_dir), Path(spec.out_dir) / ".home"]
        if spec.app_dir is not None:
            dirs.append(Path(spec.app_dir))
        for d in dirs:
            d.mkdir(parents=True, exist_ok=True)
            if nonroot:
                _give_to_nonroot(d, remapped)

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
        write_nofollow(Path(spec.out_dir) / LOG_FILE, logs)
        return load_result(
            t, Path(spec.out_dir), killed=killed, exit_code=code, log_tail=tail(logs),
            duration_s=time.monotonic() - started,
        )

    def run_replay(self, spec: WorkbenchSpec) -> ReplayResult:
        """Run `prsec-replay /work/in/replay.json` (written by the orchestrator) in the spec's env."""
        run_id = replay_run_id(spec.in_dir, spec.task.task_id)
        replay_result_path(spec.out_dir).unlink(missing_ok=True)
        refusal = self.replay_refusal(spec)
        if refusal:
            return ReplayResult(run_id=run_id, env_ok=False, env_error=refusal)
        try:
            code, logs, killed = self.run_container(
                spec, REPLAY_COMMAND, spec.task.limits.wall_clock_s + self.grace_s, entrypoint=REPLAY_ENTRYPOINT)
        except Exception as e:
            code, logs, killed = None, f"failed to run replay container: {type(e).__name__}: {e}", False
        Path(spec.out_dir).mkdir(parents=True, exist_ok=True)
        write_nofollow(Path(spec.out_dir) / LOG_FILE, logs)
        return load_replay_result(spec.out_dir, run_id, exit_code=code, killed=killed, log_tail=tail(logs))

    def replay_refusal(self, spec: WorkbenchSpec) -> str | None:
        """Why a replay may not run in this env, or None. Replays are agent-free: no LLM gateway."""
        if not spec.env_name:
            return "replay needs a dynamic env"
        if self.env_has_llm(spec.scan_id, spec.env_name):
            return f"replay env {spec.env_name!r} has the LLM gateway attached"
        return None

    # -------------------------------------------------------- dynamic envs

    def _env_label(self, scan_id: int, env_name: str, label: str) -> str | None:
        from docker.errors import NotFound

        try:
            net = self.client.networks.get(env_network_name(scan_id, env_name))
        except NotFound:
            return None
        return (net.attrs.get("Labels") or {}).get(label)

    def env_has_llm(self, scan_id: int, env_name: str) -> bool:
        return self._env_label(scan_id, check_env_name(env_name), LABEL_LLM) == "1"

    def create_env(self, scan_id: int, env_name: str, req: EnvRequest) -> EnvInfo:
        """Fresh env: internal network, sink (started first), catalog services, gateway/proxy if asked."""
        check_env_name(env_name)
        catalog = load_catalog()
        req = check_env_request(req, catalog, settings().work_root)
        self.destroy_env(scan_id, env_name)
        try:
            return self._build_env(scan_id, env_name, req, {s.name: catalog.services[s.kind] for s in req.services})
        except Exception:
            self.destroy_env(scan_id, env_name)
            raise

    def destroy_env(self, scan_id: int, env_name: str) -> None:
        from docker.errors import NotFound

        check_env_name(env_name)
        labels = [f"{LABEL_SCAN}={scan_id}", f"{LABEL_ENV}={env_name}"]
        for c in self.client.containers.list(all=True, filters={"label": labels}):
            _remove_container(c)
        try:
            net = self.client.networks.get(env_network_name(scan_id, env_name))
        except NotFound:
            return
        self._remove_network(net, (self.gateway_container, self.egress_container))

    def reap_envs(self, max_age_s: float) -> list[str]:
        """Remove dynamic-env containers and networks created more than `max_age_s` ago.

        Env containers (sink, catalog databases) never exit on their own; a worker that is killed
        mid-stage, or a create_env the client gave up on, leaves them without an owner. No env lives
        anywhere near max_age_s in normal operation. Returns the names of removed containers."""
        cutoff = time.time() - max_age_s
        removed = []
        for c in self.client.containers.list(all=True, filters={"label": LABEL_ENV}):
            if _created(c.attrs) < cutoff:
                _remove_container(c)
                removed.append(str(c.name))
        for net in self.client.networks.list(filters={"label": LABEL_ENV}):
            if _created(net.attrs) < cutoff:
                self._remove_network(net, (self.gateway_container, self.egress_container))
        if removed:
            log.warning("reaped %d orphaned env container(s): %s", len(removed), ", ".join(removed))
        return removed

    def _build_env(self, scan_id: int, env_name: str, req: EnvRequest, entries: dict[str, CatalogEntry]) -> EnvInfo:
        network = env_network_name(scan_id, env_name)
        labels = {LABEL_SCAN: str(scan_id), LABEL_ENV: env_name}
        net = self.client.networks.create(network, driver="bridge", internal=True, labels={
            **labels, LABEL_ENV_DIR: req.env_dir, LABEL_LLM: "1" if req.llm else "0", "prsec": "env-network"})
        self._prepare_sink_dir(req)
        sink = self._start_sink(network, labels, req)
        sink_ip = _ip_on(sink, network)
        self._wait_sink(sink)
        hosts = {SINK_ALIAS: sink_ip}
        write_hosts(req.env_dir, hosts)
        write_resolv(req.env_dir, sink_ip)
        started = {s.name: self._start_service(network, labels, s, entries[s.name]) for s in req.services}
        hosts.update({name: _ip_on(c, network) for name, c in started.items()})
        hosts.update(self._attach_infra(net, network, req))
        write_hosts(req.env_dir, hosts)
        status = self._wait_healthy({name: (c, entries[name].health) for name, c in started.items()})
        return EnvInfo(network=network, sink_ip=sink_ip, hosts=hosts, services=status)

    def _prepare_sink_dir(self, req: EnvRequest) -> None:
        d = make_sink_dir(req.env_dir)  # refuses a symlink: it is chowned and mounted rw below
        if self._user() == NONROOT:
            _give_to_nonroot(d, self._uid_remapped())
        write_stubs(req.env_dir, req)

    def _wait_sink(self, sink: Any) -> None:
        """Until the sink logs that it serves: before that, the workbench would have no DNS."""
        deadline = time.monotonic() + self.service_health_s
        while True:
            sink.reload()
            if SINK_READY in sink.logs(stdout=True, stderr=True):
                return
            if sink.status in ("exited", "dead") or time.monotonic() >= deadline:
                raise RuntimeError(f"sink {sink.name} did not start ({sink.status})")
            time.sleep(self.poll_s)

    def _endpoint(self, network: str, aliases: list[str]) -> dict[str, Any]:
        return {network: self.client.api.create_endpoint_config(aliases=aliases)}

    def _start_sink(self, network: str, labels: dict[str, str], req: EnvRequest) -> Any:
        kw: dict[str, Any] = {
            "image": self.sink_image, "command": SINK_COMMAND, "detach": True,
            "name": f"prsec-sink-{labels[LABEL_SCAN]}-{labels[LABEL_ENV]}", "labels": {**labels, LABEL_SERVICE: SINK_ALIAS},
            "user": self._user(), "environment": {"PRSEC_SINK_DIR": SINK_MOUNT, **_log_env()},
            "volumes": {str(checked_sink_dir(req.env_dir)): {"bind": SINK_MOUNT, "mode": "rw"}},
            "read_only": True, "tmpfs": {"/tmp": "rw,nosuid,nodev,size=64m"},  # NOSONAR(S5443) private per-container tmpfs
            "sysctls": {"net.ipv4.ip_unprivileged_port_start": "0"},  # DNS :53, HTTP :80, TLS :443 as non-root
            "pids_limit": 128, "mem_limit": "256m", "memswap_limit": "256m", "nano_cpus": int(self.sink_cpus * 1e9),
            "init": True, "network": network, "networking_config": self._endpoint(network, [SINK_ALIAS]), **HARDENED,
        }
        if self.sink_runtime:
            kw["runtime"] = self.sink_runtime
        return self.client.containers.run(**kw)

    def _start_service(self, network: str, labels: dict[str, str], s: ServiceRequest, entry: CatalogEntry) -> Any:
        """A catalog service: image, env, caps and seed mount come from the catalog entry only."""
        kw: dict[str, Any] = {
            "image": entry.image, "detach": True, "environment": dict(entry.env),
            "name": f"prsec-svc-{labels[LABEL_SCAN]}-{labels[LABEL_ENV]}-{s.name}",
            "labels": {**labels, LABEL_SERVICE: s.name}, "cap_add": list(entry.caps),
            "pids_limit": self.service_pids, "mem_limit": self.service_mem, "memswap_limit": self.service_mem,
            "nano_cpus": int(self.service_cpus * 1e9), "network": network, "networking_config": self._endpoint(network, [s.name]), **HARDENED,
        }
        if s.seed_dir and entry.seed_path:
            kw["volumes"] = {s.seed_dir: {"bind": entry.seed_path, "mode": "ro"}}
        if self.runtime:
            kw["runtime"] = self.runtime
        return self.client.containers.run(**kw)

    def _attach_infra(self, net: Any, network: str, req: EnvRequest) -> dict[str, str]:
        """Attach the LLM gateway (agent envs) and the egress proxy (package installs) when asked."""
        hosts: dict[str, str] = {}
        if req.llm:
            hosts[self.gateway_alias] = self._attach(net, network, self.gateway_container, self.gateway_alias)
        if req.packages:
            try:
                hosts[EGRESS_ALIAS] = self._attach(net, network, self.egress_container, EGRESS_ALIAS)
            except RuntimeError as e:  # installs fail visibly in the env stage; the app may not need any
                log.warning("%s", e)
        return hosts

    def _attach(self, net: Any, network: str, container: str, alias: str) -> str:
        from docker.errors import APIError, NotFound

        try:
            net.connect(container, aliases=[alias])
        except NotFound:
            raise RuntimeError(f"container {container!r} not found; cannot attach it to {network}") from None
        except APIError as e:
            if "already exists" not in str(e) and "already attached" not in str(e):
                raise
        return _ip_on(self.client.containers.get(container), network)

    def _wait_healthy(self, started: dict[str, tuple[Any, list[str]]]) -> dict[str, str]:
        """Exec each service's health command until it succeeds; never fatal, reported per service."""
        status: dict[str, str] = {}
        pending = dict(started)
        deadline = time.monotonic() + self.service_health_s
        while pending:
            for name, (c, health) in list(pending.items()):
                result = _probe(c, health)
                if result is not None:
                    status[name] = result
                    del pending[name]
            if not pending or time.monotonic() >= deadline:
                break
            time.sleep(self.poll_s)
        status.update({name: f"unhealthy: not healthy after {self.service_health_s:.0f}s" for name in pending})
        return status


def _remove_container(c: Any) -> None:
    """Force-remove; env containers also drop their anonymous volumes (database data dirs)."""
    from docker.errors import APIError, NotFound

    try:
        if LABEL_ENV in (c.labels or {}):
            c.remove(force=True, v=True)
        else:
            c.remove(force=True)
    except (NotFound, APIError):
        pass


def _log_env() -> dict[str, str]:
    """This process's PRSEC_LOG_FORMAT / PRSEC_LOG_LEVEL, for the sink (started here, so not from compose)."""
    return {k: os.environ[k] for k in ("PRSEC_LOG_FORMAT", "PRSEC_LOG_LEVEL") if os.environ.get(k)}


def _created(attrs: dict[str, Any] | None) -> float:
    """Creation time (epoch s) from inspect ('2026-01-02T03:04:05.123456789Z') or list (int) attrs;
    +inf when unknown, so an unparseable object is never reaped."""
    raw = (attrs or {}).get("Created")
    if isinstance(raw, (int, float)) and not isinstance(raw, bool):
        return float(raw)
    try:
        return datetime.strptime(str(raw)[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=UTC).timestamp()
    except ValueError:
        return float("inf")


def _ip_on(container: Any, network: str) -> str:
    container.reload()
    nets = (container.attrs.get("NetworkSettings") or {}).get("Networks") or {}
    ip = (nets.get(network) or {}).get("IPAddress")
    if not ip:
        raise RuntimeError(f"container {container.name} has no address on {network}")
    return str(ip)


def _probe(c: Any, health: list[str]) -> str | None:
    """'healthy' / 'unhealthy: <why>' when decided, None to try again."""
    from docker.errors import APIError, NotFound

    try:
        c.reload()
        if c.status in ("exited", "dead"):
            return f"unhealthy: container {c.status}"
        if c.status != "running":
            return None
        if not health:
            return "healthy"
        return "healthy" if c.exec_run(health).exit_code == 0 else None
    except NotFound:
        return "unhealthy: container gone"
    except APIError:  # e.g. exec while the container restarts: try again
        return None

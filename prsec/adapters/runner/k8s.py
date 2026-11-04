"""K8sRunner: workbenches, dynamic environments and replays as pods in one namespace (docs/design/k8s.md).

Same Runner contract as DockerRunner. The launcher runs it (PRSEC_LAUNCHER_BACKEND=k8s) with a
ServiceAccount limited to the scans namespace; the worker never talks to Kubernetes itself.

- Files: worker, launcher and workbench share one RWX volume mounted at PRSEC_K8S_DATA_ROOT
  (/var/lib/prsec); a workbench pod mounts only its own dirs from it, by subPath, at the same
  container paths as with Docker.
- Static stages: pods labelled prsec.net=scan-<id>; a NetworkPolicy lets them reach the LLM gateway
  pods only. No DNS at all (a dead nameserver); `llm-gateway` comes from hostAliases.
- Dynamic envs: a sink Pod + Service (the env's DNS: dnsPolicy None, nameserver = its ClusterIP),
  one Pod + Service per catalog service, a ConfigMap with hosts.json/stubs.json (complete before any
  pod starts: Service ClusterIPs are allocated at creation) and a NetworkPolicy that keeps the env's
  pods to each other, plus the gateway (llm) and the egress proxy (packages) when asked.
- A namespace-wide default-deny NetworkPolicy (Helm chart) is the baseline under all of this.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import secrets
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from prsec.adapters.protocols import WorkbenchSpec
from prsec.adapters.runner.common import (
    GRACE_S,
    RESULT_FILE,
    harness_mount,
    load_result,
    tail,
    workbench_env,
    write_nofollow,
    write_task,
)
from prsec.adapters.runner.env import (
    EGRESS_ALIAS,
    HOSTS_FILE,
    LABEL_ENV,
    REPLAY_COMMAND,
    REPLAY_ENTRYPOINT,
    SINK_ALIAS,
    SINK_MOUNT,
    STUBS_FILE,
    check_env_name,
    check_env_request,
    load_replay_result,
    replay_result_path,
    replay_run_id,
    stubs_json,
)
from prsec.config import settings
from prsec.dynamic.catalog import CatalogEntry, load_catalog
from prsec.dynamic.results import APP_DIR, EnvInfo, EnvRequest, ReplayResult, ServiceRequest
from prsec.models import StageResult

log = logging.getLogger(__name__)

LOG_FILE = "workbench.log"
ENTRYPOINT = ["prsec-stage"]
LABEL_SCAN = "prsec.scan_id"
LABEL_TASK = "prsec.task_id"
LABEL_NET = "prsec.net"  # the NetworkPolicy group: scan-<id>, env-<id>-<env>, or none
LABEL_ROLE = "prsec.role"  # workbench | sink | service
LABEL_SERVICE = "prsec.service"
LABEL_LLM = "prsec.llm"  # "1": may reach the gateway (the gateway's own ingress policy selects on it)
LABEL_PACKAGES = "prsec.packages"  # "1": may reach the egress proxy
ANN_ENV_DIR = "prsec/env-dir"
ANN_SINK_IP = "prsec/sink-ip"
WORKBENCH = "workbench"
DEAD_DNS = "127.0.0.1"  # nothing listens there: every lookup fails fast (static stages get no DNS)
FATAL_WAITING = frozenset({"InvalidImageName", "CreateContainerConfigError", "CreateContainerError", "ErrImageNeverPull"})
PULL_WAITING = frozenset({"ErrImagePull", "ImagePullBackOff"})
NAME_MAX = 63


def network_name(scan_id: int) -> str:
    return f"prsec-scan-{scan_id}"


def _dns_name(raw: str, limit: int = NAME_MAX) -> str:
    """A DNS-1123 label from `raw` (lowercase, [a-z0-9-]); over-long names keep a hash of the original."""
    name = re.sub(r"[^a-z0-9-]+", "-", raw.lower()).strip("-") or "x"
    if len(name) > limit:
        digest = hashlib.sha256(raw.encode()).hexdigest()[:8]
        name = f"{name[:limit - 9].rstrip('-')}-{digest}"
    return name


def _label_value(raw: str) -> str:
    """A label value: <= 63 chars of [A-Za-z0-9_.-], alphanumeric at both ends."""
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", raw)[:NAME_MAX].strip("_.-")
    return value or "x"


def env_prefix(scan_id: int, env_name: str) -> str:
    return f"env-{scan_id}-{env_name}"


def _created(obj: dict[str, Any]) -> float:
    raw = (obj.get("metadata") or {}).get("creationTimestamp")
    try:
        return datetime.strptime(str(raw)[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=UTC).timestamp()
    except ValueError:
        return float("inf")  # unknown age: never reaped


# ---------------------------------------------------------------- API seam


class Kube:
    """The Kubernetes calls K8sRunner makes, dicts in and out (tests swap in a fake)."""

    KINDS = ("pod", "service", "configmap", "networkpolicy")

    def __init__(self, namespace: str):
        from kubernetes import client, config
        from kubernetes.config.config_exception import ConfigException

        try:
            config.load_incluster_config()
        except ConfigException:
            config.load_kube_config(context=os.environ.get("PRSEC_K8S_CONTEXT") or None)
        self.namespace = namespace
        self.core = client.CoreV1Api()
        self.net = client.NetworkingV1Api()
        self._ser = client.ApiClient()

    def _plain(self, obj: Any) -> dict[str, Any]:
        return self._ser.sanitize_for_serialization(obj)

    def _fn(self, verb: str, kind: str) -> Any:
        api = self.net if kind == "networkpolicy" else self.core
        name = {"pod": "pod", "service": "service", "configmap": "config_map", "networkpolicy": "network_policy"}[kind]
        return getattr(api, f"{verb}_namespaced_{name}")

    def create(self, kind: str, body: dict[str, Any]) -> dict[str, Any]:
        return self._plain(self._fn("create", kind)(self.namespace, body))

    def get(self, kind: str, name: str, namespace: str | None = None) -> dict[str, Any] | None:
        from kubernetes.client.exceptions import ApiException

        try:
            return self._plain(self._fn("read", kind)(name, namespace or self.namespace))
        except ApiException as e:
            if e.status == 404:
                return None
            raise

    def delete(self, kind: str, name: str) -> None:
        from kubernetes.client.exceptions import ApiException

        try:
            self._fn("delete", kind)(name, self.namespace, grace_period_seconds=0)
        except ApiException as e:
            if e.status != 404:
                raise

    def list(self, kind: str, selector: str) -> list[dict[str, Any]]:
        return [self._plain(o) for o in self._fn("list", kind)(self.namespace, label_selector=selector).items]

    def logs(self, pod: str, container: str) -> str:
        from kubernetes.client.exceptions import ApiException

        try:
            return str(self.core.read_namespaced_pod_log(pod, self.namespace, container=container))
        except ApiException:
            return ""


# ------------------------------------------------------------------ runner


class K8sRunner:
    name = "k8s"
    supports_envs = True

    def __init__(self, kube: Any = None, grace_s: float = GRACE_S):
        self.namespace = os.environ.get("PRSEC_K8S_NAMESPACE", "prsec-scans")
        self.control_ns = os.environ.get("PRSEC_K8S_CONTROL_NAMESPACE", "prsec")
        self._kube = kube
        self.grace_s = grace_s
        self.data_claim = os.environ.get("PRSEC_K8S_DATA_CLAIM", "prsec-data")
        self.data_root = Path(os.environ.get("PRSEC_K8S_DATA_ROOT", "/var/lib/prsec"))
        self.gateway_service = os.environ.get("PRSEC_K8S_GATEWAY_SERVICE", "llm-gateway")
        self.gateway_alias = os.environ.get("PRSEC_GATEWAY_ALIAS", "llm-gateway")
        self.gateway_app = os.environ.get("PRSEC_K8S_GATEWAY_APP", "llm-gateway")
        self.gateway_port = int(os.environ.get("PRSEC_K8S_GATEWAY_PORT", "4000"))
        self.egress_service = os.environ.get("PRSEC_K8S_EGRESS_SERVICE", "egress-proxy")
        self.egress_app = os.environ.get("PRSEC_K8S_EGRESS_APP", "egress-proxy")
        self.runtime_class = os.environ.get("PRSEC_K8S_RUNTIME_CLASS") or None
        self.uid = int(os.environ.get("PRSEC_K8S_UID", "10001"))  # = the prsec and workbench images' user
        self.mem = os.environ.get("PRSEC_K8S_MEM", "4Gi")
        self.cpus = os.environ.get("PRSEC_K8S_CPUS", "2")
        self.tmp_size = os.environ.get("PRSEC_K8S_TMP_SIZE", "1Gi")
        self.service_mem = os.environ.get("PRSEC_K8S_SERVICE_MEM", "1Gi")
        self.service_cpus = os.environ.get("PRSEC_K8S_SERVICE_CPUS", "1")
        self.service_health_s = float(os.environ.get("PRSEC_SERVICE_HEALTH_S", "120"))
        self.start_s = float(os.environ.get("PRSEC_K8S_START_S", "600"))  # scheduling + image pull, before the wall clock
        self.sink_image = os.environ.get("PRSEC_SINK_IMAGE") or os.environ.get("PRSEC_IMAGE") or "prsec/prsec:latest"
        # IfNotPresent: images loaded into the nodes (kind) or pinned by digest are never re-pulled
        self.pull_policy = os.environ.get("PRSEC_K8S_PULL_POLICY", "IfNotPresent")
        self.poll_s = 1.0
        self._ips: dict[str, str] = {}

    @property
    def kube(self) -> Any:
        if self._kube is None:
            self._kube = Kube(self.namespace)
        return self._kube

    # ------------------------------------------------------------ helpers

    def _sub(self, path: str | Path, what: str) -> str:
        """subPath on the data volume for a host path (symlinks resolved: kubelet refuses them)."""
        resolved = Path(path).resolve()
        root = self.data_root.resolve()
        if resolved == root or not resolved.is_relative_to(root):
            raise RuntimeError(f"{what} {path} is not under the data volume {root}")
        return str(resolved.relative_to(root))

    def _control_ip(self, service: str) -> str:
        """ClusterIP of a control-plane Service (gateway, egress proxy), cached."""
        if service not in self._ips:
            svc = self.kube.get("service", service, namespace=self.control_ns)
            ip = ((svc or {}).get("spec") or {}).get("clusterIP")
            if not ip or ip == "None":
                raise RuntimeError(f"service {self.control_ns}/{service} not found or has no ClusterIP")
            self._ips[service] = ip
        return self._ips[service]

    def _pod_security(self) -> dict[str, Any]:
        return {"runAsNonRoot": True, "runAsUser": self.uid, "runAsGroup": self.uid,
                "seccompProfile": {"type": "RuntimeDefault"}}

    @staticmethod
    def _container_security() -> dict[str, Any]:
        return {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                "capabilities": {"drop": ["ALL"]}}

    def _pod_common(self) -> dict[str, Any]:
        spec: dict[str, Any] = {"restartPolicy": "Never", "automountServiceAccountToken": False,
                                "enableServiceLinks": False, "terminationGracePeriodSeconds": 5}
        if self.runtime_class:
            spec["runtimeClassName"] = self.runtime_class
        return spec

    @staticmethod
    def _meta(name: str, labels: dict[str, str], annotations: dict[str, str] | None = None) -> dict[str, Any]:
        meta: dict[str, Any] = {"name": name, "labels": labels}
        if annotations:
            meta["annotations"] = annotations
        return meta

    # ------------------------------------------------------------ static network

    def create_scan_network(self, scan_id: int) -> str:
        """The scan's NetworkPolicy: its workbenches may reach the gateway pods, nothing else."""
        self._control_ip(self.gateway_service)  # fail the scan now if there is no gateway
        name = network_name(scan_id)
        if self.kube.get("networkpolicy", name) is None:
            self.kube.create("networkpolicy", self.scan_policy(scan_id))
        return name

    def scan_policy(self, scan_id: int) -> dict[str, Any]:
        return {
            "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": self._meta(network_name(scan_id), {LABEL_SCAN: str(scan_id), "prsec": "scan-network"}),
            "spec": {
                "podSelector": {"matchLabels": {LABEL_NET: f"scan-{scan_id}"}},
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [],
                "egress": [self._to_control(self.gateway_app, self.gateway_port)],
            },
        }

    def _to_control(self, app: str, port: int) -> dict[str, Any]:
        return {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": self.control_ns}},
                        "podSelector": {"matchLabels": {"app.kubernetes.io/name": app}}}],
                "ports": [{"protocol": "TCP", "port": port}]}

    def destroy_scan(self, scan_id: int) -> None:
        self._delete_all(f"{LABEL_SCAN}={scan_id}")

    def _delete_all(self, selector: str) -> None:
        for kind in ("pod", "service", "configmap", "networkpolicy"):
            for obj in self.kube.list(kind, selector):
                self.kube.delete(kind, obj["metadata"]["name"])

    # ------------------------------------------------------------ workbench pods

    def workbench_pod(self, spec: WorkbenchSpec, command: list[str], entrypoint: list[str] | None) -> dict[str, Any]:
        t = spec.task
        mounts = [
            {"name": "data", "mountPath": t.workdir, "subPath": self._sub(spec.src_dir, "src_dir"), "readOnly": True},
            {"name": "data", "mountPath": t.skills_dir, "subPath": self._sub(spec.skills_dir, "skills_dir"), "readOnly": True},
            {"name": "data", "mountPath": t.in_dir, "subPath": self._sub(spec.in_dir, "in_dir")},
            {"name": "data", "mountPath": t.out_dir, "subPath": self._sub(spec.out_dir, "out_dir")},
            {"name": "tmp", "mountPath": "/tmp"},  # NOSONAR(S5443) private per-pod emptyDir
        ]
        if spec.harness_volume:
            mounts.append({"name": "data", "mountPath": harness_mount(t.harness),
                           "subPath": self._sub(spec.harness_volume, "harness_volume"), "readOnly": True})
        labels = {LABEL_SCAN: str(spec.scan_id), LABEL_TASK: _label_value(t.task_id), LABEL_ROLE: WORKBENCH}
        pod_spec = {
            **self._pod_common(),
            "shareProcessNamespace": True,  # the pause container is PID 1 and reaps zombies (docker --init)
            "securityContext": self._pod_security(),
            "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": self.data_claim}},
                        {"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": self.tmp_size}}],
            "containers": [{
                "name": WORKBENCH, "image": spec.image, "imagePullPolicy": self.pull_policy, "workingDir": t.workdir,
                **({"command": entrypoint} if entrypoint is not None else {}), "args": command,
                "env": [{"name": k, "value": v} for k, v in sorted(workbench_env(spec).items())],
                "volumeMounts": mounts, "securityContext": self._container_security(),
                "resources": {"limits": {"memory": self.mem, "cpu": self.cpus},
                              "requests": {"memory": "512Mi", "cpu": "250m"}},
            }],
        }
        if spec.env_name:
            self._join_env(spec, labels, pod_spec, mounts)
        else:
            self._static_net(spec, labels, pod_spec)
        name = _dns_name(f"wb-{t.task_id}-{secrets.token_hex(3)}")
        return {"apiVersion": "v1", "kind": "Pod", "metadata": self._meta(name, labels), "spec": pod_spec}

    def _static_net(self, spec: WorkbenchSpec, labels: dict[str, str], pod_spec: dict[str, Any]) -> None:
        """Static stage: no DNS; the scan network (if any) reaches the gateway through hostAliases."""
        pod_spec["dnsPolicy"] = "None"
        pod_spec["dnsConfig"] = {"nameservers": [DEAD_DNS], "searches": [], "options": [{"name": "ndots", "value": "0"}]}
        if spec.network:
            if spec.network != network_name(spec.scan_id):
                raise RuntimeError(f"network {spec.network!r} is not scan {spec.scan_id}'s")
            labels[LABEL_NET] = f"scan-{spec.scan_id}"
            labels[LABEL_LLM] = "1"
            pod_spec["hostAliases"] = [{"ip": self._control_ip(self.gateway_service), "hostnames": [self.gateway_alias]}]
        else:
            labels[LABEL_NET] = "none"  # only the namespace's default deny applies: no network at all

    def _env_meta(self, scan_id: int, env_name: str) -> dict[str, Any] | None:
        cm = self.kube.get("configmap", f"{env_prefix(scan_id, check_env_name(env_name))}-sink")
        return (cm or {}).get("metadata")

    def _join_env(self, spec: WorkbenchSpec, labels: dict[str, str], pod_spec: dict[str, Any],
                  mounts: list[dict[str, Any]]) -> None:
        """Workbench in a dynamic env: the env's NetworkPolicy group, the sink as DNS, app_dir writable."""
        meta = self._env_meta(spec.scan_id, spec.env_name or "")
        if meta is None:
            raise RuntimeError(f"dynamic env {spec.env_name!r} of scan {spec.scan_id} does not exist")
        ann, env_labels = meta.get("annotations") or {}, meta.get("labels") or {}
        labels.update({LABEL_ENV: spec.env_name or "", LABEL_NET: env_labels.get(LABEL_NET, ""),
                       LABEL_LLM: env_labels.get(LABEL_LLM, "0"), LABEL_PACKAGES: env_labels.get(LABEL_PACKAGES, "0")})
        pod_spec["dnsPolicy"] = "None"
        pod_spec["dnsConfig"] = {"nameservers": [ann[ANN_SINK_IP]], "searches": [],
                                 "options": [{"name": "ndots", "value": "0"}, {"name": "timeout", "value": "2"},
                                             {"name": "attempts", "value": "2"}]}
        if spec.app_dir is not None:
            mounts.append({"name": "data", "mountPath": APP_DIR, "subPath": self._sub(spec.app_dir, "app_dir")})

    def env_has_llm(self, scan_id: int, env_name: str) -> bool:
        meta = self._env_meta(scan_id, env_name) or {}
        return (meta.get("labels") or {}).get(LABEL_LLM) == "1"

    def _prepare_dirs(self, spec: WorkbenchSpec) -> None:
        """Same uid as the workbench on the shared volume: creating the dirs is enough (no chown)."""
        for d in (Path(spec.in_dir), Path(spec.out_dir), Path(spec.out_dir) / ".home",
                  *([Path(spec.app_dir)] if spec.app_dir is not None else [])):
            d.mkdir(parents=True, exist_ok=True)

    def run_container(self, spec: WorkbenchSpec, command: list[str], timeout_s: float,
                      entrypoint: list[str] | None = None) -> tuple[int | None, str, bool]:
        """Run one pod to completion. Returns (exit code, logs, killed)."""
        self._prepare_dirs(spec)
        body = self.workbench_pod(spec, command, entrypoint)
        body["spec"]["activeDeadlineSeconds"] = int(timeout_s + self.start_s + self.grace_s)  # backstop
        name = body["metadata"]["name"]
        self.kube.create("pod", body)
        try:
            code, killed, why = self._wait_pod(name, timeout_s)
            logs = self.kube.logs(name, WORKBENCH)
            if why:
                logs = f"{logs}\n[prsec k8s] {why}".lstrip()
            return code, logs, killed
        finally:
            self.kube.delete("pod", name)

    def _wait_pod(self, name: str, timeout_s: float) -> tuple[int | None, bool, str]:
        """(exit code, killed, why). The wall clock starts once the container runs; scheduling and the
        image pull get PRSEC_K8S_START_S of their own."""
        start_deadline = time.monotonic() + self.start_s
        run_deadline: float | None = None
        while True:
            pod = self.kube.get("pod", name)
            if pod is None:
                return None, False, "pod disappeared"
            ended = _ended(pod)
            if ended is not None:
                return ended
            phase, state = _pod_state(pod)
            now = time.monotonic()
            if run_deadline is None and "running" in state:
                run_deadline = now + timeout_s
            if run_deadline is not None and now >= run_deadline:
                return None, True, f"killed after {timeout_s:.0f}s"
            if run_deadline is None and now >= start_deadline:
                return None, False, f"pod did not start within {self.start_s:.0f}s ({_waiting_reason(phase, state)})"[:500]
            time.sleep(self.poll_s)

    def run_workbench(self, spec: WorkbenchSpec) -> StageResult:
        t = spec.task
        write_task(t, Path(spec.in_dir))
        (Path(spec.out_dir) / RESULT_FILE).unlink(missing_ok=True)
        started = time.monotonic()
        try:
            code, logs, killed = self.run_container(spec, [f"{t.in_dir.rstrip('/')}/task.json"],
                                                    t.limits.wall_clock_s + self.grace_s, entrypoint=ENTRYPOINT)
        except Exception as e:
            code, logs, killed = None, f"failed to run workbench pod: {type(e).__name__}: {e}", False
        write_nofollow(Path(spec.out_dir) / LOG_FILE, logs)
        return load_result(t, Path(spec.out_dir), killed=killed, exit_code=code, log_tail=tail(logs),
                           duration_s=time.monotonic() - started)

    def run_replay(self, spec: WorkbenchSpec) -> ReplayResult:
        """`prsec-replay /work/in/replay.json` (written by the orchestrator) in the spec's env."""
        run_id = replay_run_id(spec.in_dir, spec.task.task_id)
        replay_result_path(spec.out_dir).unlink(missing_ok=True)
        if not spec.env_name:
            return ReplayResult(run_id=run_id, env_ok=False, env_error="replay needs a dynamic env")
        if self.env_has_llm(spec.scan_id, spec.env_name):
            return ReplayResult(run_id=run_id, env_ok=False,
                                env_error=f"replay env {spec.env_name!r} has the LLM gateway attached")
        try:
            code, logs, killed = self.run_container(spec, REPLAY_COMMAND, spec.task.limits.wall_clock_s + self.grace_s,
                                                    entrypoint=REPLAY_ENTRYPOINT)
        except Exception as e:
            code, logs, killed = None, f"failed to run replay pod: {type(e).__name__}: {e}", False
        Path(spec.out_dir).mkdir(parents=True, exist_ok=True)
        write_nofollow(Path(spec.out_dir) / LOG_FILE, logs)
        return load_replay_result(spec.out_dir, run_id, exit_code=code, killed=killed, log_tail=tail(logs))

    # ------------------------------------------------------------ dynamic envs

    def create_env(self, scan_id: int, env_name: str, req: EnvRequest) -> EnvInfo:
        """Fresh env: Services first (their ClusterIPs make hosts.json complete), then the sink's
        ConfigMap, the pods and the env's NetworkPolicy."""
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
        self._delete_all(f"{LABEL_SCAN}={scan_id},{LABEL_ENV}={check_env_name(env_name)}")

    def reap_envs(self, max_age_s: float) -> list[str]:
        """Delete dynamic-env objects created more than `max_age_s` ago (orphans of killed workers)."""
        cutoff = time.time() - max_age_s
        removed: list[str] = []
        for kind in ("pod", "service", "configmap", "networkpolicy"):
            for obj in self.kube.list(kind, LABEL_ENV):
                if _created(obj) < cutoff:
                    self.kube.delete(kind, obj["metadata"]["name"])
                    if kind == "pod":
                        removed.append(obj["metadata"]["name"])
        if removed:
            log.warning("reaped %d orphaned env pod(s): %s", len(removed), ", ".join(removed))
        return removed

    def _env_labels(self, scan_id: int, env_name: str, req: EnvRequest) -> dict[str, str]:
        return {LABEL_SCAN: str(scan_id), LABEL_ENV: env_name, LABEL_NET: env_prefix(scan_id, env_name),
                LABEL_LLM: "1" if req.llm else "0", LABEL_PACKAGES: "1" if req.packages else "0"}

    def _build_env(self, scan_id: int, env_name: str, req: EnvRequest, entries: dict[str, CatalogEntry]) -> EnvInfo:
        prefix = env_prefix(scan_id, env_name)
        labels = self._env_labels(scan_id, env_name, req)
        sink_svc = self.kube.create("service", self.service(f"{prefix}-sink", labels, {LABEL_ROLE: "sink"},
                                                            [("dns-udp", 53, "UDP"), ("dns-tcp", 53, "TCP"),
                                                             ("http", 80, "TCP"), ("tls", 443, "TCP")]))
        sink_ip = sink_svc["spec"]["clusterIP"]
        hosts = {SINK_ALIAS: sink_ip}
        for s in req.services:
            e = entries[s.name]
            ports = [(f"p{p}", p, "TCP") for p in [e.port, *e.extra_ports]]
            svc = self.kube.create("service", self.service(_dns_name(f"{prefix}-{s.name}"), labels,
                                                           {LABEL_ROLE: "service", LABEL_SERVICE: s.name}, ports))
            hosts[s.name] = svc["spec"]["clusterIP"]
        if req.llm:
            hosts[self.gateway_alias] = self._control_ip(self.gateway_service)
        if req.packages:
            try:
                hosts[EGRESS_ALIAS] = self._control_ip(self.egress_service)
            except RuntimeError as e:  # installs fail visibly in the env stage; the app may not need any
                log.warning("%s", e)
        self.kube.create("configmap", {
            "apiVersion": "v1", "kind": "ConfigMap",
            "metadata": self._meta(f"{prefix}-sink", labels, {ANN_ENV_DIR: req.env_dir, ANN_SINK_IP: sink_ip}),
            "data": {HOSTS_FILE: json.dumps(hosts, indent=2, sort_keys=True), STUBS_FILE: stubs_json(req)},
        })
        self.kube.create("networkpolicy", self.env_policy(prefix, labels, req))
        self.kube.create("pod", self.sink_pod(prefix, labels, sink_ip))
        for s in req.services:
            self.kube.create("pod", self.service_pod(prefix, labels, s, entries[s.name], sink_ip))
        self._wait_ready({f"{prefix}-sink": SINK_ALIAS}, fatal=True)
        status = self._wait_ready({_dns_name(f"{prefix}-{s.name}"): s.name for s in req.services}, fatal=False)
        return EnvInfo(network=prefix, sink_ip=sink_ip, hosts=hosts, services=status)

    def service(self, name: str, labels: dict[str, str], select: dict[str, str],
                ports: list[tuple[str, int, str]]) -> dict[str, Any]:
        return {"apiVersion": "v1", "kind": "Service", "metadata": self._meta(name, labels),
                "spec": {"type": "ClusterIP", "selector": {LABEL_NET: labels[LABEL_NET], **select},
                         "ports": [{"name": n, "port": p, "targetPort": p, "protocol": proto} for n, p, proto in ports]}}

    def env_policy(self, prefix: str, labels: dict[str, str], req: EnvRequest) -> dict[str, Any]:
        """The env's pods talk to each other; out of the env only the gateway (llm) and the egress proxy (packages)."""
        same_env = {"podSelector": {"matchLabels": {LABEL_NET: labels[LABEL_NET]}}}
        egress: list[dict[str, Any]] = [{"to": [same_env]}]
        if req.llm:
            egress.append(self._to_control(self.gateway_app, self.gateway_port))
        if req.packages:
            egress.append(self._to_control(self.egress_app, 3128))
        return {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": self._meta(prefix, labels),
                "spec": {"podSelector": {"matchLabels": {LABEL_NET: labels[LABEL_NET]}},
                         "policyTypes": ["Ingress", "Egress"], "ingress": [{"from": [same_env]}], "egress": egress}}

    def sink_pod(self, prefix: str, labels: dict[str, str], sink_ip: str) -> dict[str, Any]:
        return {"apiVersion": "v1", "kind": "Pod",
                "metadata": self._meta(f"{prefix}-sink", {**labels, LABEL_ROLE: "sink", LABEL_SERVICE: SINK_ALIAS}),
                "spec": {
                    **self._pod_common(),
                    "securityContext": {**self._pod_security(),
                                        # DNS :53, HTTP :80, TLS :443 as non-root (a namespaced safe sysctl)
                                        "sysctls": [{"name": "net.ipv4.ip_unprivileged_port_start", "value": "0"}]},
                    "dnsPolicy": "None", "dnsConfig": {"nameservers": [DEAD_DNS]},
                    "volumes": [{"name": "config", "configMap": {"name": f"{prefix}-sink"}},
                                {"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "64Mi"}}],
                    "containers": [{
                        "name": "sink", "image": self.sink_image, "imagePullPolicy": self.pull_policy,
                        "command": ["prsec-sink", "--data-dir", SINK_MOUNT, "--self-ip", sink_ip],
                        "volumeMounts": [{"name": "config", "mountPath": SINK_MOUNT, "readOnly": True},
                                         {"name": "tmp", "mountPath": "/tmp"}],  # NOSONAR(S5443) private emptyDir
                        "securityContext": self._container_security(),
                        "readinessProbe": {"httpGet": {"path": "/__prsec/health", "port": 80,
                                                       "httpHeaders": [{"name": "Host", "value": SINK_ALIAS}]},
                                           "periodSeconds": 1, "failureThreshold": 600},
                        "resources": {"limits": {"memory": "256Mi", "cpu": "1"}, "requests": {"memory": "64Mi", "cpu": "50m"}},
                    }],
                }}

    def service_pod(self, prefix: str, labels: dict[str, str], s: ServiceRequest, entry: CatalogEntry,
                    sink_ip: str) -> dict[str, Any]:
        """A catalog service: image, env, caps and seed mount come from the catalog entry only."""
        container: dict[str, Any] = {
            "name": "service", "image": entry.image, "imagePullPolicy": self.pull_policy,
            "env": [{"name": k, "value": v} for k, v in sorted(entry.env.items())],
            "ports": [{"containerPort": p} for p in [entry.port, *entry.extra_ports]],
            "securityContext": {"allowPrivilegeEscalation": False,
                                "capabilities": {"drop": ["ALL"], "add": list(entry.caps)}},
            "readinessProbe": ({"exec": {"command": list(entry.health)}} if entry.health
                               else {"tcpSocket": {"port": entry.port}}) | {"periodSeconds": 2, "failureThreshold": 600},
            "resources": {"limits": {"memory": self.service_mem, "cpu": self.service_cpus},
                          "requests": {"memory": "128Mi", "cpu": "100m"}},
        }
        pod_spec: dict[str, Any] = {**self._pod_common(), "securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
                                    "dnsPolicy": "None", "dnsConfig": {"nameservers": [sink_ip]}, "containers": [container]}
        if s.seed_dir and entry.seed_path:
            pod_spec["volumes"] = [{"name": "data", "persistentVolumeClaim": {"claimName": self.data_claim, "readOnly": True}}]
            container["volumeMounts"] = [{"name": "data", "mountPath": entry.seed_path,
                                          "subPath": self._sub(s.seed_dir, f"seed_dir of {s.name}"), "readOnly": True}]
        return {"apiVersion": "v1", "kind": "Pod",
                "metadata": self._meta(_dns_name(f"{prefix}-{s.name}"),
                                       {**labels, LABEL_ROLE: "service", LABEL_SERVICE: s.name}),
                "spec": pod_spec}

    def _wait_ready(self, pods: dict[str, str], *, fatal: bool) -> dict[str, str]:
        """pod name -> service name, waited for Ready up to service_health_s: {service: healthy | unhealthy: why}.
        With `fatal`, anything not ready raises (the sink: without it the env has no DNS)."""
        status: dict[str, str] = {}
        pending = dict(pods)
        deadline = time.monotonic() + self.service_health_s
        while pending:
            for pod_name, svc in list(pending.items()):
                result = _readiness(self.kube.get("pod", pod_name))
                if result is not None:
                    status[svc] = result
                    del pending[pod_name]
            if not pending or time.monotonic() >= deadline:
                break
            time.sleep(self.poll_s)
        status.update({svc: f"unhealthy: not ready after {self.service_health_s:.0f}s" for svc in pending.values()})
        if fatal and any(v != "healthy" for v in status.values()):
            raise RuntimeError(f"sink did not start: {status}")
        return status


def _pod_state(pod: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """(phase, state of the first container: {waiting|running|terminated: {...}})."""
    st = pod.get("status") or {}
    containers = st.get("containerStatuses") or []
    return str(st.get("phase") or "Pending"), ((containers[0] if containers else {}).get("state") or {})


def _ended(pod: dict[str, Any]) -> tuple[int | None, bool, str] | None:
    """(exit code, killed=False, why) once the pod finished or can never start; None while it may still run."""
    phase, state = _pod_state(pod)
    if phase in ("Succeeded", "Failed"):
        term = state.get("terminated") or {}
        return term.get("exitCode"), False, "" if term else f"pod {phase.lower()}: {_status_reason(pod)}"
    waiting = state.get("waiting") or {}
    if waiting.get("reason") in FATAL_WAITING:
        return None, False, f"{waiting['reason']}: {waiting.get('message', '')}"[:500]
    return None


def _waiting_reason(phase: str, state: dict[str, Any]) -> str:
    waiting = state.get("waiting") or {}
    return f"{waiting.get('reason', phase)}: {waiting.get('message', '')}" if waiting else phase


def _status_reason(pod: dict[str, Any]) -> str:
    st = pod.get("status") or {}
    return f"{st.get('reason') or ''} {st.get('message') or ''}".strip() or "no reason given"


def _readiness(pod: dict[str, Any] | None) -> str | None:
    """'healthy' / 'unhealthy: <why>' once decided, None to keep waiting."""
    if pod is None:
        return "unhealthy: pod gone"
    phase, state = _pod_state(pod)
    if phase in ("Succeeded", "Failed"):
        return f"unhealthy: pod {phase.lower()}"
    waiting = state.get("waiting") or {}
    if waiting.get("reason") in FATAL_WAITING:
        return f"unhealthy: {waiting['reason']}"
    conditions = (pod.get("status") or {}).get("conditions") or []
    if any(c.get("type") == "Ready" and c.get("status") == "True" for c in conditions):
        return "healthy"
    return None

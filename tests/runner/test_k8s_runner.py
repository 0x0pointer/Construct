"""K8sRunner against a fake Kubernetes API: the objects it creates, and its pod lifecycle."""
import json
from pathlib import Path

import pytest

from prsec.adapters.protocols import WorkbenchSpec
from prsec.adapters.runner import k8s as k8s_mod
from prsec.adapters.runner.k8s import DEAD_DNS, K8sRunner
from prsec.config import settings
from prsec.dynamic.results import EnvRequest, ServiceRequest
from prsec.models import Limits, Stage, StageResult, StageStatus, StageTask

GW_IP, EGRESS_IP = "10.96.0.10", "10.96.0.11"


def default_status(body):
    """Workbenches run to completion; env pods (sink, services) keep running and are Ready."""
    if body["metadata"]["labels"].get("prsec.role") == "workbench":
        return {"phase": "Succeeded", "containerStatuses": [{"state": {"terminated": {"exitCode": 0}}}]}
    return {"phase": "Running", "containerStatuses": [{"state": {"running": {"startedAt": "now"}}}],
            "conditions": [{"type": "Ready", "status": "True"}]}


class FakeKube:
    """In-memory objects. Pods get their status from `pod_status(body)` on every read."""

    def __init__(self, pod_status=None):
        self.objs: dict[tuple[str, str], dict] = {}
        self.created: list[tuple[str, str]] = []
        self.deleted: list[tuple[str, str]] = []
        self.control = {"llm-gateway": GW_IP, "egress-proxy": EGRESS_IP}
        self.pod_status = pod_status or default_status
        self.on_create = None
        self.next_ip = 100

    def create(self, kind, body):
        name = body["metadata"]["name"]
        body = json.loads(json.dumps(body))
        body["metadata"]["creationTimestamp"] = "2026-11-04T10:00:00Z"
        if kind == "service":
            body["spec"]["clusterIP"] = f"10.96.1.{self.next_ip}"
            self.next_ip += 1
        self.objs[(kind, name)] = body
        self.created.append((kind, name))
        if self.on_create:
            self.on_create(kind, body)
        return body

    def get(self, kind, name, namespace=None):
        if namespace == "prsec" and kind == "service":
            ip = self.control.get(name)
            return {"spec": {"clusterIP": ip}} if ip else None
        obj = self.objs.get((kind, name))
        if obj is not None and kind == "pod":
            obj = {**obj, "status": self.pod_status(obj)}
        return obj

    def delete(self, kind, name):
        self.deleted.append((kind, name))
        self.objs.pop((kind, name), None)

    def list(self, kind, selector):
        want = [s.split("=", 1) for s in selector.split(",")]
        out = []
        for (k, _), obj in self.objs.items():
            labels = obj["metadata"].get("labels") or {}
            if k == kind and all((labels.get(w[0]) == w[1]) if len(w) == 2 else w[0] in labels for w in want):
                out.append(obj)
        return out

    def logs(self, pod, container):
        return f"log of {pod}"

    def only(self, kind, contains=""):
        [obj] = [o for (k, n), o in self.objs.items() if k == kind and contains in n]
        return obj


@pytest.fixture
def root(tmp_path, monkeypatch):
    data = tmp_path / "data"
    work = data / "work"
    (data / "skills" / "v1").mkdir(parents=True)
    (data / "skills" / "current").symlink_to("v1")
    (data / "harness" / "opencode" / "1.0").mkdir(parents=True)
    (data / "harness" / "opencode" / "current").symlink_to("1.0")
    work.mkdir()
    monkeypatch.setenv("PRSEC_K8S_DATA_ROOT", str(data))
    monkeypatch.setenv("PRSEC_WORK_ROOT", str(work))
    monkeypatch.delenv("PRSEC_K8S_RUNTIME_CLASS", raising=False)
    settings.cache_clear()
    yield data
    settings.cache_clear()


def runner(kube, **env) -> K8sRunner:
    r = K8sRunner(kube=kube)
    r.poll_s = 0.001
    r.service_health_s = 0.2
    return r


def spec(data: Path, scan_id=7, network="prsec-scan-7", env_name=None, harness=True, stage=Stage.hypothesise) -> WorkbenchSpec:
    t = StageTask(scan_id=scan_id, stage=stage, task_id=f"{scan_id}-{stage.value}", harness="opencode",
                  model_alias="agent-large", prompt_md="", output_schema={}, limits=Limits(wall_clock_s=60, usd_budget=1))
    w = data / "work" / f"{scan_id}-x"
    for d in ("src", "in", "out", "app"):
        (w / d).mkdir(parents=True, exist_ok=True)
    return WorkbenchSpec(scan_id=scan_id, task=t, image="prsec/workbench-base:latest",
                         harness_volume=str(data / "harness" / "opencode" / "current") if harness else None,
                         src_dir=w / "src", in_dir=w / "in", out_dir=w / "out", skills_dir=data / "skills" / "current",
                         env={"PRSEC_GATEWAY_URL": "http://llm-gateway:4000"}, network=network, env_name=env_name,
                         app_dir=(w / "app") if env_name else None)


# ------------------------------------------------------------------ static stages


def test_static_workbench_pod_is_hardened(root):
    kube = FakeKube()
    pod = runner(kube).workbench_pod(spec(root), ["/work/in/task.json"], ["prsec-stage"])
    ps = pod["spec"]
    [c] = ps["containers"]
    assert ps["automountServiceAccountToken"] is False
    assert ps["enableServiceLinks"] is False
    assert ps["restartPolicy"] == "Never"
    assert ps["shareProcessNamespace"] is True
    assert ps["securityContext"] == {"runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001,
                                     "seccompProfile": {"type": "RuntimeDefault"}}
    assert c["securityContext"] == {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]}}
    assert (c["command"], c["args"]) == (["prsec-stage"], ["/work/in/task.json"])
    assert ps["dnsPolicy"] == "None"
    assert ps["dnsConfig"]["nameservers"] == [DEAD_DNS]
    assert ps["hostAliases"] == [{"ip": GW_IP, "hostnames": ["llm-gateway"]}]
    labels = pod["metadata"]["labels"]
    assert (labels["prsec.net"], labels["prsec.llm"], labels["prsec.scan_id"]) == ("scan-7", "1", "7")
    mounts = {m["mountPath"]: m for m in c["volumeMounts"]}
    assert mounts["/work/src"] == {"name": "data", "mountPath": "/work/src", "subPath": "work/7-x/src", "readOnly": True}
    assert mounts["/skills"]["subPath"] == "skills/v1"  # the 'current' symlink resolved: kubelet refuses symlinks
    assert mounts["/opt/harness/opencode/current"]["subPath"] == "harness/opencode/1.0"
    assert mounts["/work/out"].get("readOnly") is None
    assert mounts["/work/in"].get("readOnly") is None
    env = {e["name"]: e["value"] for e in c["env"]}
    assert env["HOME"] == "/work/out/.home"
    assert env["PRSEC_HARNESS_HOME"] == "/opt/harness/opencode/current"
    assert {"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "1Gi"}} in ps["volumes"]
    assert "runtimeClassName" not in ps


def test_runtime_class_and_no_network(root, monkeypatch):
    monkeypatch.setenv("PRSEC_K8S_RUNTIME_CLASS", "gvisor")
    pod = runner(FakeKube()).workbench_pod(spec(root, network=None), ["x"], None)
    assert pod["spec"]["runtimeClassName"] == "gvisor"
    assert pod["metadata"]["labels"]["prsec.net"] == "none"  # only the namespace's default deny applies
    assert "hostAliases" not in pod["spec"]
    assert "command" not in pod["spec"]["containers"][0]


def test_paths_outside_the_data_volume_are_refused(root, tmp_path):
    s = spec(root)
    s.src_dir = tmp_path / "elsewhere"
    r = runner(FakeKube())
    with pytest.raises(RuntimeError, match="not under the data volume"):
        r.workbench_pod(s, ["x"], None)


def test_scan_network_policy_allows_only_the_gateway(root):
    kube = FakeKube()
    assert runner(kube).create_scan_network(7) == "prsec-scan-7"
    np = kube.only("networkpolicy")
    assert np["spec"]["podSelector"] == {"matchLabels": {"prsec.net": "scan-7"}}
    assert np["spec"]["ingress"] == []
    [rule] = np["spec"]["egress"]
    assert rule["ports"] == [{"protocol": "TCP", "port": 4000}]
    assert rule["to"][0]["podSelector"] == {"matchLabels": {"app.kubernetes.io/name": "llm-gateway"}}
    assert rule["to"][0]["namespaceSelector"] == {"matchLabels": {"kubernetes.io/metadata.name": "prsec"}}
    runner(kube).create_scan_network(7)  # idempotent
    assert kube.created.count(("networkpolicy", "prsec-scan-7")) == 1


def test_scan_network_fails_without_a_gateway(root):
    kube = FakeKube()
    kube.control = {}
    r = runner(kube)
    with pytest.raises(RuntimeError, match="llm-gateway not found"):
        r.create_scan_network(7)


def test_run_workbench_reads_the_result_and_deletes_the_pod(root):
    kube = FakeKube()
    s = spec(root)

    def workbench(kind, body):
        if kind == "pod":
            res = StageResult(task_id=s.task.task_id, stage=s.task.stage, status=StageStatus.ok, output={"a": 1},
                              harness="opencode", model="agent-large")
            (s.out_dir / "result.json").write_text(res.model_dump_json())

    kube.on_create = workbench
    result = runner(kube).run_workbench(s)
    assert result.status == StageStatus.ok
    assert result.output == {"a": 1}
    assert (s.in_dir / "task.json").is_file()
    assert (s.out_dir / "workbench.log").read_text().startswith("log of wb-7-hypothesise-")
    assert not [k for k in kube.objs if k[0] == "pod"]  # deleted after the run


def test_wall_clock_kill_is_a_timeout(root):
    kube = FakeKube(pod_status=lambda body: {"phase": "Running", "containerStatuses": [{"state": {"running": {}}}]})
    r = runner(kube)
    code, logs, killed = r.run_container(spec(root), ["x"], 0.05)
    assert (code, killed) == (None, True)
    assert "killed after" in logs
    assert not [k for k in kube.objs if k[0] == "pod"]


@pytest.mark.parametrize("reason", ["CreateContainerConfigError", "InvalidImageName"])
def test_fatal_waiting_reason_fails_fast(root, reason):
    kube = FakeKube(pod_status=lambda body: {"phase": "Pending", "containerStatuses": [
        {"state": {"waiting": {"reason": reason, "message": "nope"}}}]})
    code, logs, killed = runner(kube).run_container(spec(root), ["x"], 30)
    assert (code, killed) == (None, False)
    assert reason in logs


def test_pod_that_never_starts_fails_after_the_start_budget(root):
    kube = FakeKube(pod_status=lambda body: {"phase": "Pending", "containerStatuses": [
        {"state": {"waiting": {"reason": "ImagePullBackOff", "message": "rate limited"}}}]})
    r = runner(kube)
    r.start_s = 0.05
    code, logs, killed = r.run_container(spec(root), ["x"], 30)
    assert (code, killed) == (None, False)
    assert "did not start" in logs
    assert "ImagePullBackOff" in logs


# ------------------------------------------------------------------ dynamic envs


def env_req(root, llm=True, packages=True, seeded=True):
    seed = root / "work" / "seeds" / "h1" / "db"
    seed.mkdir(parents=True, exist_ok=True)
    (seed / "00-schema.sql").write_text("create table t (id int);")
    env_dir = root / "work" / "envs" / "h1"
    return EnvRequest(services=[ServiceRequest(name="db", kind="postgres", seed_dir=str(seed) if seeded else None),
                                ServiceRequest(name="mail", kind="mailpit")],
                      llm=llm, packages=packages, env_dir=str(env_dir))


def test_create_env_builds_services_first_and_a_complete_hosts_map(root):
    kube = FakeKube()
    info = runner(kube).create_env(7, "h1", env_req(root))
    kinds = [k for k, _ in kube.created]
    assert kinds.index("configmap") > max(i for i, k in enumerate(kinds) if k == "service")
    assert kinds.index("pod") > kinds.index("configmap")
    sink_ip = kube.only("service", "sink")["spec"]["clusterIP"]
    cm = kube.only("configmap")
    hosts = json.loads(cm["data"]["hosts.json"])
    assert hosts == {"sink": sink_ip, "db": kube.only("service", "-db")["spec"]["clusterIP"],
                     "mail": kube.only("service", "-mail")["spec"]["clusterIP"],
                     "llm-gateway": GW_IP, "egress-proxy": EGRESS_IP}
    assert info.sink_ip == sink_ip
    assert info.hosts == hosts
    assert info.services == {"db": "healthy", "mail": "healthy"}
    assert [p["port"] for p in kube.only("service", "-mail")["spec"]["ports"]] == [1025, 8025]  # extra_ports
    assert cm["metadata"]["annotations"]["prsec/sink-ip"] == sink_ip
    assert cm["metadata"]["labels"]["prsec.llm"] == "1"


def test_env_network_policy(root):
    kube = FakeKube()
    runner(kube).create_env(7, "h1", env_req(root, llm=False, packages=True))
    np = kube.only("networkpolicy")
    same = {"podSelector": {"matchLabels": {"prsec.net": "env-7-h1"}}}
    assert np["spec"]["ingress"] == [{"from": [same]}]
    assert np["spec"]["egress"][0] == {"to": [same]}
    apps = [r["to"][0]["podSelector"]["matchLabels"]["app.kubernetes.io/name"] for r in np["spec"]["egress"][1:]]
    assert apps == ["egress-proxy"]  # no gateway for llm=False (replays)
    assert "llm-gateway" not in json.loads(kube.only("configmap")["data"]["hosts.json"])


def test_sink_and_service_pods(root):
    kube = FakeKube()
    runner(kube).create_env(7, "h1", env_req(root))
    sink = kube.only("pod", "sink")
    sink_ip = kube.only("service", "sink")["spec"]["clusterIP"]
    assert sink["spec"]["securityContext"]["sysctls"] == [{"name": "net.ipv4.ip_unprivileged_port_start", "value": "0"}]
    [c] = sink["spec"]["containers"]
    assert c["command"] == ["prsec-sink", "--data-dir", "/sink", "--self-ip", sink_ip]
    assert {"name": "config", "mountPath": "/sink", "readOnly": True} in c["volumeMounts"]
    db = kube.only("pod", "-db")
    [svc] = db["spec"]["containers"]
    assert svc["securityContext"]["capabilities"] == {"drop": ["ALL"], "add": ["CHOWN", "SETUID", "SETGID", "DAC_OVERRIDE", "FOWNER"]}
    assert svc["readinessProbe"]["exec"]["command"][:3] == ["pg_isready", "-h", "127.0.0.1"]
    assert svc["volumeMounts"] == [{"name": "data", "mountPath": "/docker-entrypoint-initdb.d",
                                    "subPath": "work/seeds/h1/db", "readOnly": True}]
    assert db["spec"]["dnsConfig"]["nameservers"] == [sink_ip]
    assert db["metadata"]["labels"]["prsec.net"] == "env-7-h1"


def test_env_workbench_uses_the_sink_as_dns(root):
    kube = FakeKube()
    r = runner(kube)
    r.create_env(7, "h1", env_req(root))
    pod = r.workbench_pod(spec(root, network=None, env_name="h1"), ["x"], None)
    sink_ip = kube.only("service", "sink")["spec"]["clusterIP"]
    assert pod["spec"]["dnsConfig"]["nameservers"] == [sink_ip]
    labels = pod["metadata"]["labels"]
    assert (labels["prsec.net"], labels["prsec.env"], labels["prsec.llm"]) == ("env-7-h1", "h1", "1")
    assert {"name": "data", "mountPath": "/work/app", "subPath": "work/7-x/app"} in pod["spec"]["containers"][0]["volumeMounts"]


def test_workbench_in_a_missing_env_is_refused(root):
    r, s = runner(FakeKube()), spec(root, network=None, env_name="h9")
    with pytest.raises(RuntimeError, match="does not exist"):
        r.workbench_pod(s, ["x"], None)


def test_replay_refuses_an_env_with_the_gateway(root):
    kube = FakeKube()
    r = runner(kube)
    r.create_env(7, "h1", env_req(root, llm=True))
    s = spec(root, network=None, env_name="h1")
    s.mode = "replay"
    res = r.run_replay(s)
    assert not res.env_ok
    assert "LLM gateway" in res.env_error


def test_sink_that_never_gets_ready_fails_the_env_and_cleans_up(root):
    def status(body):
        ready = body["metadata"]["labels"].get("prsec.role") != "sink"
        return {"phase": "Running", "containerStatuses": [{"state": {"running": {}}}],
                "conditions": [{"type": "Ready", "status": "True" if ready else "False"}]}
    kube = FakeKube(pod_status=status)
    r, req = runner(kube), env_req(root)
    with pytest.raises(RuntimeError, match="sink did not start"):
        r.create_env(7, "h1", req)
    assert kube.objs == {}


def test_unhealthy_service_is_reported_not_fatal(root):
    def status(body):
        ok = body["metadata"]["labels"].get("prsec.service") != "db"
        return {"phase": "Running", "containerStatuses": [{"state": {"running": {}}}],
                "conditions": [{"type": "Ready", "status": "True" if ok else "False"}]}
    info = runner(FakeKube(pod_status=status)).create_env(7, "h1", env_req(root))
    assert info.services["mail"] == "healthy"
    assert info.services["db"].startswith("unhealthy")


def test_destroy_env_scan_and_reaper(root, monkeypatch):
    kube = FakeKube()
    r = runner(kube)
    r.create_scan_network(7)
    r.create_env(7, "h1", env_req(root))
    r.create_env(7, "h2", env_req(root))
    r.destroy_env(7, "h1")
    assert not any("env-7-h1" in n for _, n in kube.objs)
    assert any("env-7-h2" in n for _, n in kube.objs)
    monkeypatch.setattr(k8s_mod.time, "time", lambda: 1793786400.0 + 5 * 3600)  # 5 h after creation
    removed = r.reap_envs(4 * 3600)
    assert removed
    assert not any("env-7-h2" in n for _, n in kube.objs)
    assert ("networkpolicy", "prsec-scan-7") in kube.objs  # the scan's own policy is not an env object
    r.destroy_scan(7)
    assert kube.objs == {}


def test_names_and_labels_stay_within_kubernetes_limits():
    long = "x" * 200
    assert len(k8s_mod._dns_name(f"wb-{long}")) <= 63
    assert k8s_mod._dns_name("wb-12-static_verify-H1-ab12cd") == "wb-12-static-verify-h1-ab12cd"
    assert k8s_mod._label_value("12-rules-shadow-jev") == "12-rules-shadow-jev"
    assert len(k8s_mod._label_value(long)) == 63


def test_launcher_backend_switch(monkeypatch):
    from prsec.launcher.main import backend

    monkeypatch.setenv("PRSEC_LAUNCHER_BACKEND", "k8s")
    assert isinstance(backend(), K8sRunner)
    monkeypatch.setenv("PRSEC_LAUNCHER_BACKEND", "nomad")
    with pytest.raises(ValueError, match="unknown PRSEC_LAUNCHER_BACKEND"):
        backend()

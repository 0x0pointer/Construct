"""K8sRunner on kind: network isolation as enforced by the cluster, and the reference replays end to end."""
from __future__ import annotations

import json
import secrets
import shutil
from pathlib import Path

import pytest

from prsec.adapters.protocols import WorkbenchSpec
from prsec.config import load_policy
from prsec.dynamic.results import EnvRequest, ServiceRequest
from prsec.evals.cases import list_cases
from prsec.evals.reference import explain, problems, replay_reference
from prsec.models import Stage, StageTask

from .conftest import DATA, WORKBENCH

pytestmark = pytest.mark.k8s
DYNAMIC_CASES = [c for c in list_cases() if c.dynamic]

# Every probe is a try/except so one blocked path never hides the others; results go to /work/out.
PROBE = r"""
import json, socket, sys, urllib.request
args = json.loads(sys.argv[1])
r = {}
def attempt(name, fn):
    try:
        r[name] = fn()
    except Exception as e:
        r[name] = f"error: {type(e).__name__}"
def tcp(host, port):
    socket.create_connection((host, port), timeout=4).close()
    return "reachable"
attempt("internet", lambda: tcp("1.1.1.1", 443))
attempt("dns_example", lambda: socket.gethostbyname("example.com"))
attempt("cluster_dns", lambda: tcp(args["cluster_dns"], 53))
attempt("gateway_by_ip", lambda: tcp(args["gateway_ip"], 4000))
attempt("egress_by_ip", lambda: tcp(args["egress_ip"], 3128))
attempt("gateway_by_name", lambda: urllib.request.urlopen("http://llm-gateway:4000/health/liveliness", timeout=5).status)
for name in args.get("resolve", []):
    attempt(f"resolve_{name}", lambda name=name: socket.gethostbyname(name))
if args.get("canary"):
    attempt("canary_http", lambda: urllib.request.urlopen(f"http://{args['canary']}.example.test/x", timeout=5).status)
    attempt("canary_hits", lambda: len(json.load(urllib.request.urlopen(
        f"http://sink/__prsec/hits?contains={args['canary']}", timeout=5))["hits"]))
open("/work/out/probe.json", "w").write(json.dumps(r))
"""


def _cluster_dns(core) -> str:
    """kube-dns' ClusterIP; in-cluster the launcher's account may not read kube-system, so fall back to
    this pod's own resolver (the cluster DNS)."""
    try:
        return core.read_namespaced_service("kube-dns", "kube-system").spec.cluster_ip
    except Exception:
        for line in Path("/etc/resolv.conf").read_text().splitlines():
            if line.startswith("nameserver "):
                return line.split()[1]
        raise


def _ips(core) -> dict[str, str]:
    svc = {n: core.read_namespaced_service(n, "prsec").spec.cluster_ip for n in ("llm-gateway", "egress-proxy")}
    return {"gateway_ip": svc["llm-gateway"], "egress_ip": svc["egress-proxy"], "cluster_dns": _cluster_dns(core)}


def _spec(scan_id: int, work: Path, network: str | None = None, env_name: str | None = None) -> WorkbenchSpec:
    for d in ("src", "in", "out", "app"):
        (work / d).mkdir(parents=True, exist_ok=True)
    task = StageTask(scan_id=scan_id, stage=Stage.dynamic, task_id=f"{scan_id}-probe", harness="raw",
                     prompt_md="", output_schema={})
    return WorkbenchSpec(scan_id=scan_id, task=task, image=WORKBENCH, harness_volume=None, src_dir=work / "src",
                         in_dir=work / "in", out_dir=work / "out", skills_dir=DATA / "skills" / "current",
                         network=network, env_name=env_name, app_dir=(work / "app") if env_name else None)


def _probe(runner, spec: WorkbenchSpec, args: dict) -> dict:
    # The workbench image's entrypoint is prsec-stage: override it, as the replay does with prsec-replay.
    code, logs, killed = runner.run_container(spec, ["-c", PROBE, json.dumps(args)], 120, entrypoint=["python3"])
    assert code == 0, logs
    assert not killed, logs
    return json.loads((Path(spec.out_dir) / "probe.json").read_text())


@pytest.fixture
def scan(k8s):
    scan_id = 900_000 + secrets.randbelow(99_999)
    work = DATA / "work" / f"k8s-test-{scan_id}"
    yield scan_id, work
    k8s.destroy_scan(scan_id)
    shutil.rmtree(work, ignore_errors=True)


def test_static_stage_reaches_only_the_gateway(k8s, kube_ready, scan):
    scan_id, work = scan
    ips = _ips(kube_ready)
    net = k8s.create_scan_network(scan_id)
    r = _probe(k8s, _spec(scan_id, work, network=net), ips)
    assert r["gateway_by_name"] == 200, r
    assert r["gateway_by_ip"] == "reachable", r
    for blocked in ("internet", "cluster_dns", "egress_by_ip", "dns_example"):
        assert str(r[blocked]).startswith("error"), (blocked, r)


def test_isolation_holds_under_concurrency(k8s, kube_ready, scan):
    """kindnet's NetworkPolicy queue failed open under load (pods reached the internet through a deny-all
    policy); the cluster's CNI must hold with several scan pods starting and connecting at once."""
    from concurrent.futures import ThreadPoolExecutor

    scan_id, work = scan
    ips = _ips(kube_ready)
    net = k8s.create_scan_network(scan_id)
    specs = [_spec(scan_id, work / f"p{i}", network=net) for i in range(4)]
    with ThreadPoolExecutor(max_workers=len(specs)) as pool:
        results = list(pool.map(lambda sp: _probe(k8s, sp, ips), specs))
    for r in results:
        assert r["gateway_by_name"] == 200, r
        for blocked in ("internet", "cluster_dns", "egress_by_ip"):
            assert str(r[blocked]).startswith("error"), (blocked, r)


def test_no_network_stage_reaches_nothing(k8s, kube_ready, scan):
    scan_id, work = scan
    r = _probe(k8s, _spec(scan_id, work, network=None), _ips(kube_ready))
    for blocked in ("internet", "cluster_dns", "gateway_by_ip", "egress_by_ip", "gateway_by_name"):
        assert str(r[blocked]).startswith("error"), (blocked, r)


def test_dynamic_env_dns_sink_and_isolation(k8s, kube_ready, scan):
    scan_id, work = scan
    ips = _ips(kube_ready)
    token = f"prsec{secrets.token_hex(6)}"
    info = k8s.create_env(scan_id, "t1", EnvRequest(services=[ServiceRequest(name="cache", kind="redis")],
                                                    llm=False, packages=False, env_dir=str(work / "env")))
    assert info.services == {"cache": "healthy"}, info
    r = _probe(k8s, _spec(scan_id, work, env_name="t1"),
               {**ips, "resolve": ["cache", "api.not-in-the-catalog.example"], "canary": token})
    assert r["resolve_cache"] == info.hosts["cache"], r
    assert r["resolve_api.not-in-the-catalog.example"] == info.sink_ip, r
    assert r["canary_http"] == 200, r
    assert r["canary_hits"] >= 1, r
    for blocked in ("internet", "cluster_dns", "gateway_by_ip", "egress_by_ip"):
        assert str(r[blocked]).startswith("error"), (blocked, r)  # llm=False, packages=False


@pytest.mark.parametrize("case", DYNAMIC_CASES, ids=[c.id for c in DYNAMIC_CASES])
def test_reference_poc_reproduces_on_kubernetes(k8s, scan, case):
    scan_id, work = scan
    policy = load_policy()
    ev, _ = replay_reference(case, k8s, scan_id=scan_id, root=work, image=WORKBENCH, policy=policy)
    why = explain(ev)
    print(why)
    assert problems(ev, policy.dynamic.replay_runs) == [], why

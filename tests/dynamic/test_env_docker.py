"""Dynamic env against a real Docker daemon: sink DNS, catalog service, HTTP recording, no internet.

Builds the prsec image (it carries prsec-sink) as prsec/prsec:test, creates an env with a redis
service and probes it from a throwaway workbench that uses the generated resolv.conf.
"""
import json
import secrets
import shutil
import subprocess
from pathlib import Path

import pytest

from prsec.adapters.protocols import WorkbenchSpec
from prsec.adapters.runner.docker import DockerRunner
from prsec.config import settings
from prsec.dynamic.results import EnvRequest, ServiceRequest
from prsec.models import Stage, StageTask

pytestmark = pytest.mark.docker
ROOT = Path(__file__).resolve().parents[2]
IMAGE = "prsec/prsec:test"
ENV = "t1"

PROBE = r"""
import json, socket, sys, urllib.request
token = sys.argv[1]
r = {}
def attempt(name, fn):
    try:
        r[name] = fn()
    except Exception as e:
        r[name] = f"error: {type(e).__name__}: {e}"
attempt("cache", lambda: socket.gethostbyname("cache"))
attempt("unknown", lambda: socket.gethostbyname("api.not-in-the-catalog.example"))
attempt("http_unknown", lambda: urllib.request.urlopen(f"http://{token}.example.test/ping?t={token}", timeout=10).status)
attempt("hits", lambda: json.load(urllib.request.urlopen(f"http://sink/__prsec/hits?contains={token}", timeout=10)))
attempt("internet", lambda: socket.create_connection(("1.1.1.1", 443), timeout=3).close() or "reachable")
open("/work/out/probe.json", "w").write(json.dumps(r))
"""


@pytest.fixture(scope="module")
def docker_client():
    docker = pytest.importorskip("docker")
    if shutil.which("docker") is None:
        pytest.skip("docker CLI not installed")
    try:
        client = docker.from_env()
        client.ping()
    except Exception as e:
        pytest.skip(f"no docker daemon: {e}")
    proc = subprocess.run(["make", "image-prsec", f"PRSEC_IMAGE={IMAGE}"], cwd=ROOT,
                          capture_output=True, text=True, timeout=1200)
    assert proc.returncode == 0, proc.stdout[-2000:] + proc.stderr[-2000:]
    return client


@pytest.fixture
def runner(docker_client, tmp_path, monkeypatch):
    monkeypatch.setenv("PRSEC_WORK_ROOT", str(tmp_path))
    monkeypatch.setenv("PRSEC_SINK_IMAGE", IMAGE)
    monkeypatch.delenv("PRSEC_DOCKER_RUNTIME", raising=False)
    settings.cache_clear()
    r = DockerRunner(docker_client)
    yield r
    settings.cache_clear()


def _probe_spec(scan_id: int, work: Path) -> WorkbenchSpec:
    for d in ("src", "in", "out", "skills", "app"):
        (work / d).mkdir(exist_ok=True)
    task = StageTask(scan_id=scan_id, stage=Stage.dynamic, task_id=f"{scan_id}-probe", harness="raw",
                     prompt_md="", output_schema={})
    return WorkbenchSpec(scan_id=scan_id, task=task, image=IMAGE, harness_volume=None, src_dir=work / "src",
                         in_dir=work / "in", out_dir=work / "out", skills_dir=work / "skills",
                         env_name=ENV, app_dir=work / "app")


def _ip_of(client, container_name: str, network: str) -> str:
    return client.containers.get(container_name).attrs["NetworkSettings"]["Networks"][network]["IPAddress"]


def _leftovers(client, scan_id: int) -> list:
    return client.containers.list(all=True, filters={"label": f"prsec.scan_id={scan_id}"})


def test_env_dns_sink_and_isolation(docker_client, runner, tmp_path):
    scan_id = 900_000 + secrets.randbelow(99_999)
    token = f"prsec{secrets.token_hex(6)}"
    req = EnvRequest(services=[ServiceRequest(name="cache", kind="redis")], llm=False, packages=False,
                     env_dir=str(tmp_path / "env"))
    try:
        info = runner.create_env(scan_id, ENV, req)
        assert docker_client.networks.get(info.network).attrs["Internal"] is True
        assert info.services == {"cache": "healthy"}
        assert (tmp_path / "env" / "resolv.conf").read_text().startswith(f"nameserver {info.sink_ip}")

        code, logs, killed = runner.run_container(_probe_spec(scan_id, tmp_path), ["python", "-c", PROBE, token],
                                                  timeout_s=120)
        assert code == 0, logs
        assert not killed, logs
        r = json.loads((tmp_path / "out" / "probe.json").read_text())

        assert r["cache"] == _ip_of(docker_client, f"prsec-svc-{scan_id}-{ENV}-cache", info.network), r
        assert r["unknown"] == info.sink_ip, r
        assert r["http_unknown"] == 200, r
        hosts = [h.get("host", "") for h in r["hits"]["hits"]]
        assert any(token in h for h in hosts), r
        assert str(r["internet"]).startswith("error"), r
    finally:
        runner.destroy_scan(scan_id)
    from docker.errors import NotFound

    assert _leftovers(docker_client, scan_id) == []
    with pytest.raises(NotFound):
        docker_client.networks.get(f"prsec-scan-{scan_id}-{ENV}")

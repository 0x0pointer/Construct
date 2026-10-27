"""Isolation smoke test against a real Docker daemon: only the gateway is reachable from the workbench."""
import json
import os
import secrets
from pathlib import Path

import pytest

from prsec.adapters.protocols import WorkbenchSpec
from prsec.adapters.runner.docker import DockerRunner
from prsec.models import Stage, StageTask

pytestmark = pytest.mark.docker
IMAGE = "python:3.12-slim"

PROBE = r"""
import json, os, socket, urllib.request
r = {"uid": os.getuid()}
def attempt(name, fn):
    try:
        fn(); r[name] = "reachable"
    except Exception as e:
        r[name] = f"blocked: {type(e).__name__}"
attempt("tcp_1.1.1.1", lambda: socket.create_connection(("1.1.1.1", 443), timeout=3).close())
attempt("tcp_8.8.8.8_dns", lambda: socket.create_connection(("8.8.8.8", 53), timeout=3).close())
attempt("dns_example.com", lambda: socket.getaddrinfo("example.com", 443))
attempt("https_example.com", lambda: urllib.request.urlopen("https://example.com", timeout=5))
attempt("gateway", lambda: urllib.request.urlopen("http://llm-gateway:4000/", timeout=5))
attempt("write_rootfs", lambda: open("/usr/pwned", "w"))
attempt("write_src", lambda: open("/work/src/pwned", "w"))
attempt("write_tmp", lambda: open("/tmp/ok", "w"))
attempt("write_home", lambda: open(os.path.join(os.environ["HOME"], "ok"), "w"))
open("/work/out/probe.json", "w").write(json.dumps(r))
"""


@pytest.fixture(scope="module")
def docker_client():
    docker = pytest.importorskip("docker")
    try:
        client = docker.from_env()
        client.ping()
    except Exception as e:
        pytest.skip(f"no docker daemon: {e}")
    try:
        client.images.get(IMAGE)
    except docker.errors.ImageNotFound:
        try:
            client.images.pull(IMAGE)
        except Exception as e:
            pytest.skip(f"cannot pull {IMAGE}: {e}")
    return client


def test_workbench_has_no_egress_but_reaches_gateway(docker_client, tmp_path, monkeypatch):
    scan_id = 900_000 + secrets.randbelow(99_999)
    gw_name = f"prsec-test-gw-{scan_id}"
    gateway = docker_client.containers.run(
        IMAGE, ["python", "-m", "http.server", "4000"], name=gw_name, detach=True, labels={"prsec.test": "1"}
    )
    monkeypatch.setenv("PRSEC_GATEWAY_CONTAINER", gw_name)
    runner = DockerRunner(docker_client)
    try:
        network = runner.create_scan_network(scan_id)
        assert docker_client.networks.get(network).attrs["Internal"] is True

        for d in ("src", "in", "out", "skills"):
            (tmp_path / d).mkdir()
        task = StageTask(scan_id=scan_id, stage=Stage.triage, task_id=f"{scan_id}-egress", harness="raw",
                         prompt_md="", output_schema={})
        spec = WorkbenchSpec(scan_id=scan_id, task=task, image=IMAGE, harness_volume=None,
                             src_dir=tmp_path / "src", in_dir=tmp_path / "in", out_dir=tmp_path / "out",
                             skills_dir=tmp_path / "skills", network=network)
        code, logs, killed = runner.run_container(spec, ["python", "-c", PROBE], timeout_s=120)
        assert code == 0 and not killed, logs

        r = json.loads(Path(tmp_path / "out" / "probe.json").read_text())
        assert r["uid"] != 0
        for k in ("tcp_1.1.1.1", "tcp_8.8.8.8_dns", "dns_example.com", "https_example.com", "write_rootfs", "write_src"):
            assert r[k].startswith("blocked"), (k, r)
        assert r["gateway"] == "reachable", r
        assert r["write_tmp"] == r["write_home"] == "reachable", r
    finally:
        runner.destroy_scan(scan_id)
        gateway.remove(force=True)
    with pytest.raises(Exception):
        docker_client.networks.get(f"prsec-scan-{scan_id}")

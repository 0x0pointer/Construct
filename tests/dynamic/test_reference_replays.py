"""Reference PoCs of the dynamic eval cases, replayed for real: no agent, no LLM.

For every case that ships reference/envspec.json + reference/poc.yaml, the orchestrator's own replay
path (`dynamic._replayed`: a fresh env per run, `prsec-replay` in the workbench image, then the
base) runs against a real runner. The reference must reproduce on head (every replay fires through
HTTP) and must not fire on base (the PR introduced the bug). That exercises the sink's DNS, catalog
services, the egress proxy for installs, the app runner and the oracles, so a failure here is in the
dynamic machinery, not in a model.

Needs a Docker daemon, network access to the package registries and the images from `make images`
(override with PRSEC_TEST_IMAGE / PRSEC_TEST_WORKBENCH_IMAGE). `make test-dynamic` builds and runs it.
"""
from __future__ import annotations

import os
import secrets
import time
from pathlib import Path

import pytest

from prsec.adapters.runner.docker import DockerRunner
from prsec.config import load_policy, settings
from prsec.evals.cases import Case, list_cases
from prsec.evals.reference import explain, problems, replay_reference

pytestmark = pytest.mark.docker

ROOT = Path(__file__).resolve().parents[2]
SKILLS = ROOT / "prsec-skills"
IMAGE = os.environ.get("PRSEC_TEST_IMAGE", "prsec/prsec:latest")
WORKBENCH = os.environ.get("PRSEC_TEST_WORKBENCH_IMAGE", "prsec/workbench-base:latest")
DYNAMIC_CASES = [c for c in list_cases() if c.dynamic]



@pytest.fixture(scope="module")
def docker_client():
    docker = pytest.importorskip("docker")
    try:
        client = docker.from_env()
        client.ping()
    except Exception as e:
        pytest.skip(f"no docker daemon: {e}")
    for image in (IMAGE, WORKBENCH):
        try:
            client.images.get(image)
        except docker.errors.ImageNotFound:
            pytest.skip(f"image {image} not built: run `make images` (or `make test-dynamic`)")
    return client


@pytest.fixture(scope="module")
def egress_proxy(docker_client):
    """A prsec-egress-proxy on its own routable network, like the compose service (registries only)."""
    tag = secrets.token_hex(4)
    net = docker_client.networks.create(f"prsec-test-egress-{tag}", driver="bridge", internal=False,
                                        labels={"prsec.test": "1"})
    proxy = docker_client.containers.run(
        IMAGE, ["prsec-egress-proxy"], name=f"prsec-test-egress-{tag}", detach=True, network=net.name,
        labels={"prsec.test": "1"}, read_only=True, cap_drop=["ALL"], security_opt=["no-new-privileges:true"],
        tmpfs={"/tmp": "rw,size=16m"},  # NOSONAR(S5443) private per-container tmpfs
    )
    try:
        _wait_listening(proxy, 3128)
        yield proxy.name
    finally:
        proxy.remove(force=True)
        net.remove()


def _wait_listening(container, port: int, timeout_s: float = 30) -> None:
    probe = f"import socket; socket.create_connection(('127.0.0.1', {port}), timeout=2).close()"
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if container.exec_run(["python", "-c", probe]).exit_code == 0:
            return
        time.sleep(0.5)
    raise AssertionError(f"{container.name} not listening on {port}: {container.logs()[-2000:]!r}")


@pytest.fixture
def runner(docker_client, egress_proxy, tmp_path, monkeypatch):
    monkeypatch.setenv("PRSEC_WORK_ROOT", str(tmp_path))
    monkeypatch.setenv("PRSEC_SKILLS_DIR", str(SKILLS))
    monkeypatch.setenv("PRSEC_SINK_IMAGE", IMAGE)
    monkeypatch.setenv("PRSEC_EGRESS_CONTAINER", egress_proxy)
    monkeypatch.delenv("PRSEC_DOCKER_RUNTIME", raising=False)
    settings.cache_clear()
    yield DockerRunner(docker_client)
    settings.cache_clear()



def _leftovers(client, scan_id: int) -> list[str]:
    containers = client.containers.list(all=True, filters={"label": f"prsec.scan_id={scan_id}"})
    networks = client.networks.list(filters={"label": f"prsec.scan_id={scan_id}"})
    return [c.name for c in containers] + [n.name for n in networks]


@pytest.mark.parametrize("case", DYNAMIC_CASES, ids=[c.id for c in DYNAMIC_CASES])
def test_reference_poc_reproduces_on_head_not_on_base(case: Case, runner, docker_client, tmp_path):
    scan_id = 900_000 + secrets.randbelow(99_999)
    policy = load_policy()
    try:
        ev, _ = replay_reference(case, runner, scan_id=scan_id, root=tmp_path / f"scan-{scan_id}", image=WORKBENCH,
                                 policy=policy)
    finally:
        runner.destroy_scan(scan_id)
    why = explain(ev)
    print(why)  # shown with -s, and on failure
    assert problems(ev, policy.dynamic.replay_runs) == [], why
    assert _leftovers(docker_client, scan_id) == []

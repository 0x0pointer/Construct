import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import requests
from docker.errors import APIError, ImageNotFound, NotFound
from fakeharness import make_task

from prsec.adapters.protocols import WorkbenchSpec
from prsec.adapters.runner.docker import DockerRunner
from prsec.models import Stage, StageResult, StageStatus


@pytest.fixture
def client():
    return MagicMock()


@pytest.fixture
def spec(tmp_path) -> WorkbenchSpec:
    make_task(tmp_path)
    return WorkbenchSpec(
        scan_id=42, task=make_task(tmp_path, harness="codex", container_paths=True), image="prsec/workbench-base:test",
        harness_volume="prsec-harness-codex-0.50", src_dir=tmp_path / "src", in_dir=tmp_path / "in",
        out_dir=tmp_path / "out", skills_dir=tmp_path / "skills",
        env={"PRSEC_GATEWAY_URL": "http://llm-gateway:4000", "PRSEC_GATEWAY_KEY": "sk-scan"},
        network="prsec-scan-42",
    )


def _ok_result(spec: WorkbenchSpec) -> str:
    return StageResult(task_id=spec.task.task_id, stage=Stage.triage, status=StageStatus.ok,
                       output={"decision": "skip"}, harness="codex", model="agent-small").model_dump_json()


def test_create_scan_network_is_internal_and_attaches_gateway(client, monkeypatch):
    monkeypatch.setenv("PRSEC_GATEWAY_CONTAINER", "my-gateway")
    client.networks.get.side_effect = NotFound("nope")
    net = client.networks.create.return_value
    net.attrs = {"Internal": True}

    assert DockerRunner(client).create_scan_network(42) == "prsec-scan-42"
    args, kw = client.networks.create.call_args
    assert args == ("prsec-scan-42",) and kw["internal"] is True and kw["driver"] == "bridge"
    assert kw["labels"]["prsec.scan_id"] == "42"
    net.connect.assert_called_once_with("my-gateway", aliases=["llm-gateway"])


def test_existing_non_internal_network_refused(client):
    client.networks.get.return_value.attrs = {"Internal": False}
    with pytest.raises(RuntimeError, match="not internal"):
        DockerRunner(client).create_scan_network(1)


def test_missing_gateway_is_fatal_already_connected_tolerated(client):
    net = client.networks.get.return_value
    net.attrs = {"Internal": True}
    net.connect.side_effect = NotFound("no gateway")
    with pytest.raises(RuntimeError, match="gateway container"):
        DockerRunner(client).create_scan_network(1)
    net.connect.side_effect = APIError("endpoint with name prsec-llm-gateway already exists in network")
    assert DockerRunner(client).create_scan_network(1) == "prsec-scan-1"


def test_run_workbench_security_options(client, spec, monkeypatch):
    monkeypatch.delenv("PRSEC_DOCKER_RUNTIME", raising=False)
    monkeypatch.delenv("PRSEC_DOCKER_USER", raising=False)
    container = client.containers.run.return_value

    def finish(timeout):
        (spec.out_dir / "result.json").write_text(_ok_result(spec))
        return {"StatusCode": 0}

    container.wait.side_effect = finish
    container.logs.return_value = b"prsec-stage: done\n"

    res = DockerRunner(client).run_workbench(spec)
    assert res.status == StageStatus.ok and res.output == {"decision": "skip"}

    kw = client.containers.run.call_args.kwargs
    assert kw["image"] == "prsec/workbench-base:test"
    assert kw["entrypoint"] == ["prsec-stage"] and kw["command"] == ["/work/in/task.json"]
    # Docker runs entrypoint + command: exactly one argument reaches prsec-stage's main()
    assert kw["entrypoint"] + kw["command"] == ["prsec-stage", "/work/in/task.json"]
    assert kw["cap_drop"] == ["ALL"]
    assert kw["security_opt"] == ["no-new-privileges:true"]
    assert kw["read_only"] is True
    assert "/tmp" in kw["tmpfs"]
    assert kw["pids_limit"] > 0 and kw["mem_limit"] and kw["nano_cpus"] > 0
    assert kw["network"] == "prsec-scan-42" and "network_mode" not in kw
    assert not kw["user"].startswith("0:") and kw["user"] != "root"
    assert "privileged" not in kw and "runtime" not in kw
    vols = kw["volumes"]
    assert vols[str(spec.src_dir)] == {"bind": "/work/src", "mode": "ro"}
    assert vols[str(spec.skills_dir)] == {"bind": "/skills", "mode": "ro"}
    assert vols["prsec-harness-codex-0.50"] == {"bind": "/opt/harness/codex/current", "mode": "ro"}
    assert vols[str(spec.in_dir)]["mode"] == "rw" and vols[str(spec.out_dir)]["mode"] == "rw"
    env = kw["environment"]
    assert env["PRSEC_HARNESS_HOME"] == "/opt/harness/codex/current"
    assert env["HOME"].startswith("/work/out/") and env["PRSEC_GATEWAY_KEY"] == "sk-scan"
    assert kw["labels"]["prsec.scan_id"] == "42"

    written = json.loads((spec.in_dir / "task.json").read_text())
    assert written["workdir"] == "/work/src"  # container paths are kept for docker
    assert (spec.out_dir / ".home").is_dir()
    assert (spec.out_dir / "workbench.log").read_text() == "prsec-stage: done\n"
    container.remove.assert_called_once_with(force=True)


def test_gvisor_runtime_and_no_network(client, spec, monkeypatch):
    monkeypatch.setenv("PRSEC_DOCKER_RUNTIME", "runsc")
    kw = DockerRunner(client).container_kwargs(spec, ["true"])
    assert kw["runtime"] == "runsc"
    spec.network = None
    kw = DockerRunner(client).container_kwargs(spec, ["true"])
    assert kw["network_mode"] == "none" and "network" not in kw


def test_run_workbench_timeout_kills_container(client, spec):
    container = client.containers.run.return_value
    container.wait.side_effect = requests.exceptions.ReadTimeout()
    container.logs.return_value = b"still thinking"
    res = DockerRunner(client, grace_s=0).run_workbench(spec)
    assert res.status == StageStatus.timeout
    container.kill.assert_called_once()
    container.remove.assert_called_once_with(force=True)


def test_run_workbench_missing_result_and_image(client, spec):
    container = client.containers.run.return_value
    container.wait.return_value = {"StatusCode": 137}
    container.logs.return_value = b"OOMKilled"
    res = DockerRunner(client).run_workbench(spec)
    assert res.status == StageStatus.harness_error and "137" in res.errors[0] and "OOMKilled" in res.errors[1]

    client.containers.run.side_effect = ImageNotFound("no such image")
    res = DockerRunner(client).run_workbench(spec)
    assert res.status == StageStatus.harness_error and "no such image" in "\n".join(res.errors)


def test_destroy_scan_disconnects_gateway_then_removes(client, monkeypatch):
    monkeypatch.setenv("PRSEC_GATEWAY_CONTAINER", "gw")
    leftover = MagicMock()
    client.containers.list.return_value = [leftover]
    net = client.networks.get.return_value
    order = MagicMock()
    net.disconnect.side_effect = lambda *a, **k: order("disconnect", *a)
    net.remove.side_effect = lambda: order("remove")

    DockerRunner(client).destroy_scan(42)
    assert client.containers.list.call_args.kwargs["filters"] == {"label": "prsec.scan_id=42"}
    leftover.remove.assert_called_once_with(force=True)
    assert [c.args[0] for c in order.call_args_list] == ["disconnect", "remove"]
    assert order.call_args_list[0].args[1] == "gw"


def test_destroy_scan_missing_network_is_noop(client):
    client.containers.list.return_value = []
    client.networks.get.side_effect = NotFound("gone")
    DockerRunner(client).destroy_scan(42)


def test_effective_workbench_argv_with_image_entrypoint(client, spec):
    """Docker semantics: an explicit entrypoint replaces the image's, else command is appended to it."""
    import re

    from prsec.sandbox.entrypoint import main as stage_main

    dockerfile = (Path(__file__).resolve().parents[2] / "images" / "workbench-base" / "Dockerfile").read_text()
    image_entrypoint = json.loads(re.search(r"^ENTRYPOINT (.+)$", dockerfile, re.M).group(1))
    kw = DockerRunner(client).container_kwargs(spec, ["/work/in/task.json"], ["prsec-stage"])
    argv = kw.get("entrypoint", image_entrypoint) + kw["command"]
    assert argv[0] == "prsec-stage" and argv.count("prsec-stage") == 1
    assert stage_main.main(argv[1:] + ["extra"]) == 2  # main() rejects anything but exactly one argument
    assert len(argv[1:]) == 1

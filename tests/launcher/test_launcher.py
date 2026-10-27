"""Launcher service: auth, the fixed-recipe checks, and the worker-side LauncherRunner against it."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest
from fastapi.testclient import TestClient

from prsec.adapters.protocols import WorkbenchSpec
from prsec.adapters.runner.launcher import LauncherError, LauncherRunner
from prsec.config import settings
from prsec.launcher.main import create_app
from prsec.models import Stage, StageResult, StageStatus, StageTask

TOKEN = "launcher-test-token"
IMAGE = "prsec/workbench-base:test"


@pytest.fixture
def roots(tmp_path, monkeypatch):
    work, skills, harness = tmp_path / "work", tmp_path / "skills", tmp_path / "harness"
    (skills / "v1").mkdir(parents=True)
    (skills / "current").symlink_to("v1")
    (harness / "codex" / "1.0").mkdir(parents=True)
    (harness / "codex" / "current").symlink_to("1.0")
    scan = work / "scan-7"
    for d in ("src", "in/t1", "out/t1"):
        (scan / d).mkdir(parents=True)
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        f"defaults: {{}}\nworkbench_image: {IMAGE}\n"
        "repos:\n  'org/java-*':\n    workbench_image: prsec/workbench-java:test\n"
    )
    monkeypatch.setenv("PRSEC_LAUNCHER_TOKEN", TOKEN)
    monkeypatch.setenv("PRSEC_WORK_ROOT", str(work))
    monkeypatch.setenv("PRSEC_SKILLS_DIR", str(skills / "current"))
    monkeypatch.setenv("PRSEC_HARNESS_ROOT", str(harness))
    monkeypatch.setenv("PRSEC_POLICY_PATH", str(policy))
    settings.cache_clear()
    yield {"work": work, "skills": skills, "harness": harness, "scan": scan}
    settings.cache_clear()


@pytest.fixture
def docker() -> MagicMock:
    runner = MagicMock()
    runner.create_scan_network.side_effect = lambda sid: f"prsec-scan-{sid}"
    runner.run_container.return_value = (0, "stage done", False)
    return runner


@pytest.fixture
def client(roots, docker) -> TestClient:
    return TestClient(create_app(runner=docker), headers={"Authorization": f"Bearer {TOKEN}"})


def _task(**kw) -> StageTask:
    base = {"scan_id": 7, "stage": Stage.triage, "task_id": "t1", "harness": "codex",
            "prompt_md": "x", "output_schema": {"type": "object"}}
    return StageTask(**(base | kw))


def _body(roots, **kw) -> dict:
    scan = roots["scan"]
    body = {
        "scan_id": 7, "task": _task().model_dump(mode="json"), "image": IMAGE,
        "harness_volume": str(roots["harness"] / "codex" / "current"),
        "src_dir": str(scan / "src"), "in_dir": str(scan / "in" / "t1"), "out_dir": str(scan / "out" / "t1"),
        "skills_dir": str(roots["skills"] / "current"), "env": {"PRSEC_GATEWAY_KEY": "sk-x"},
        "network": "prsec-scan-7", "timeout_s": 300,
    }
    return body | kw


# ------------------------------------------------------------------ auth


@pytest.mark.parametrize("header", [None, "Bearer wrong", TOKEN])
def test_requests_without_the_token_are_rejected(roots, docker, header):
    c = TestClient(create_app(runner=docker), headers={"Authorization": header} if header else {})
    assert c.post("/scans/7/network").status_code == 401
    assert c.post("/run", json=_body(roots)).status_code == 401
    docker.create_scan_network.assert_not_called()
    docker.run_container.assert_not_called()


def test_unconfigured_token_refuses_everything(roots, docker, monkeypatch):
    monkeypatch.setenv("PRSEC_LAUNCHER_TOKEN", "")
    settings.cache_clear()
    c = TestClient(create_app(runner=docker), headers={"Authorization": "Bearer "})
    assert c.post("/scans/7/network").status_code == 503


def test_healthz_needs_no_token(roots, docker):
    assert TestClient(create_app(runner=docker)).get("/healthz").json() == {"ok": True}


# ------------------------------------------------------------------ happy path


def test_network_and_destroy(client, docker):
    assert client.post("/scans/7/network").json() == {"network": "prsec-scan-7"}
    assert client.delete("/scans/7").json() == {"ok": True}
    docker.destroy_scan.assert_called_once_with(7)


def test_run_uses_fixed_command_and_resolved_paths(client, docker, roots):
    r = client.post("/run", json=_body(roots))
    assert r.status_code == 200
    assert r.json() == {"exit_code": 0, "logs": "stage done", "killed": False}
    spec, command, timeout = docker.run_container.call_args.args
    assert command == ["/work/in/task.json"]
    assert docker.run_container.call_args.kwargs["entrypoint"] == ["prsec-stage"]
    assert timeout == 300
    assert spec.skills_dir == (roots["skills"] / "v1").resolve()
    assert spec.harness_volume == str((roots["harness"] / "codex" / "1.0").resolve())
    assert spec.src_dir == (roots["scan"] / "src").resolve()


def test_repo_override_image_is_allowed(client, docker, roots):
    assert client.post("/run", json=_body(roots, image="prsec/workbench-java:test")).status_code == 200


# ------------------------------------------------------------------ refusals


def _refused(client, docker, body) -> str:
    r = client.post("/run", json=body)
    assert r.status_code == 403, r.text
    docker.run_container.assert_not_called()
    return r.json()["detail"]


def test_refuses_image_not_in_policy(client, docker, roots):
    assert "not a workbench image" in _refused(client, docker, _body(roots, image="alpine:3"))


@pytest.mark.parametrize("field", ["src_dir", "in_dir", "out_dir"])
@pytest.mark.parametrize("path", ["/", "/etc", "/var/run"])
def test_refuses_host_paths_outside_work_root(client, docker, roots, field, path):
    assert "outside" in _refused(client, docker, _body(roots, **{field: path}))


def test_refuses_dotdot_escape(client, docker, roots):
    escape = str(roots["scan"] / ".." / ".." / "..")
    assert "outside" in _refused(client, docker, _body(roots, src_dir=escape))


def test_refuses_symlink_escape(client, docker, roots):
    (roots["scan"] / "evil").symlink_to("/")
    assert "outside" in _refused(client, docker, _body(roots, src_dir=str(roots["scan"] / "evil")))


def test_refuses_work_root_itself(client, docker, roots):
    assert "outside" in _refused(client, docker, _body(roots, out_dir=str(roots["work"])))


def test_refuses_relative_path(client, docker, roots):
    assert "absolute" in _refused(client, docker, _body(roots, src_dir="work/scan-7/src"))


def test_refuses_other_skills_dir(client, docker, roots):
    assert "skills_dir" in _refused(client, docker, _body(roots, skills_dir="/"))


@pytest.mark.parametrize("vol", ["/", "/var/run/docker.sock", "{h}/codex/1.0", "{h}/pi/current"])
def test_refuses_other_harness_volume(client, docker, roots, vol):
    assert "harness_volume" in _refused(client, docker, _body(roots, harness_volume=vol.format(h=roots["harness"])))


@pytest.mark.parametrize("net", ["host", "bridge", "prsec-scan-8", "prsec-control"])
def test_refuses_foreign_network(client, docker, roots, net):
    assert "network" in _refused(client, docker, _body(roots, network=net))


def test_no_network_is_allowed(client, docker, roots):
    assert client.post("/run", json=_body(roots, network=None)).status_code == 200


def test_refuses_task_for_another_scan(client, docker, roots):
    body = _body(roots, task=_task(scan_id=8).model_dump(mode="json"))
    assert "scan_id" in _refused(client, docker, body)


@pytest.mark.parametrize("field", ["workdir", "in_dir", "out_dir", "skills_dir"])
def test_refuses_changed_container_paths(client, docker, roots, field):
    body = _body(roots, task=_task(**{field: "/proc"}).model_dump(mode="json"))
    assert field in _refused(client, docker, body)


@pytest.mark.parametrize("harness", ["../codex", "Codex", "a b", ""])
def test_refuses_bad_harness_name(client, docker, roots, harness):
    body = _body(roots, task=_task(harness=harness).model_dump(mode="json"))
    assert "harness" in _refused(client, docker, body)


def test_refuses_bad_env_and_long_timeouts(client, docker, roots):
    assert "env name" in _refused(client, docker, _body(roots, env={"bad-name": "x"}))
    assert "env too large" in _refused(client, docker, _body(roots, env={"A": "x" * 70_000}))
    assert "timeout_s" in _refused(client, docker, _body(roots, timeout_s=10**6))


# ------------------------------------------------------------------ LauncherRunner (worker side)


def _runner_against(client: TestClient, token: str = TOKEN) -> LauncherRunner:
    def handler(request: httpx.Request) -> httpx.Response:
        r = client.request(request.method, request.url.path, content=request.content,
                           headers={"Authorization": request.headers.get("authorization", ""),
                                    "Content-Type": "application/json"})
        return httpx.Response(r.status_code, content=r.content, headers={"content-type": "application/json"})

    return LauncherRunner(url="http://launcher:8090", token=token, grace_s=5, transport=httpx.MockTransport(handler))


def _spec(roots, **kw) -> WorkbenchSpec:
    scan = roots["scan"]
    base = dict(scan_id=7, task=_task(), image=IMAGE, harness_volume=str(roots["harness"] / "codex" / "current"),
                src_dir=scan / "src", in_dir=scan / "in" / "t1", out_dir=scan / "out" / "t1",
                skills_dir=roots["skills"] / "current", env={"PRSEC_GATEWAY_KEY": "sk-x"}, network="prsec-scan-7")
    return WorkbenchSpec(**(base | kw))


def test_runner_round_trip(client, docker, roots):
    def fake_run(spec, command, timeout, entrypoint):
        ok = StageResult(task_id="t1", stage=Stage.triage, status=StageStatus.ok, harness="codex", model="agent-small")
        (Path(spec.out_dir) / "result.json").write_text(ok.model_dump_json())
        return 0, "ran", False

    docker.run_container.side_effect = fake_run
    runner = _runner_against(client)
    assert runner.create_scan_network(7) == "prsec-scan-7"
    spec = _spec(roots)
    result = runner.run_workbench(spec)
    assert result.status == StageStatus.ok
    assert (roots["scan"] / "in" / "t1" / "task.json").exists()
    assert (roots["scan"] / "out" / "t1" / "workbench.log").read_text() == "ran"
    assert docker.run_container.call_args.args[2] == spec.task.limits.wall_clock_s + 5
    runner.destroy_scan(7)
    docker.destroy_scan.assert_called_once_with(7)


def test_runner_turns_refusal_into_stage_failure(client, docker, roots):
    result = _runner_against(client).run_workbench(_spec(roots, image="alpine:3"))
    assert result.status == StageStatus.harness_error
    assert "403" in "\n".join(result.errors)
    docker.run_container.assert_not_called()


def test_runner_network_errors_raise(client, roots):
    with pytest.raises(LauncherError):
        _runner_against(client, token="wrong").create_scan_network(7)

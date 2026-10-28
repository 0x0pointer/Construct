import json
import stat
from pathlib import Path

import pytest
from fakeharness import make_task

from prsec.adapters.protocols import WorkbenchSpec
from prsec.adapters.runner import get_runner
from prsec.adapters.runner.local import LocalRunner, host_task
from prsec.models import StageStatus

SANDBOX_TESTS = Path(__file__).parent.parent / "sandbox"


def spec_for(tmp_path, mode="valid", **limits) -> WorkbenchSpec:
    make_task(tmp_path)  # materialise src/in/skills fixtures on the host
    task = make_task(tmp_path, container_paths=True, **limits)
    return WorkbenchSpec(
        scan_id=7, task=task, image="unused", harness_volume=str(tmp_path / "harness"),
        src_dir=tmp_path / "src", in_dir=tmp_path / "in", out_dir=tmp_path / "out", skills_dir=tmp_path / "skills",
        env={"FAKE_MODE": mode, "PRSEC_ADAPTER_MODULES": "fakeharness", "PYTHONPATH": str(SANDBOX_TESTS),
             "PRSEC_GATEWAY_URL": "http://gw:4000", "PRSEC_GATEWAY_KEY": "sk-x"},
    )


def test_get_runner():
    assert isinstance(get_runner("local"), LocalRunner)
    with pytest.raises(ValueError):
        get_runner("k8s")


def test_host_task_rewrites_container_paths(tmp_path):
    spec = spec_for(tmp_path)
    t = host_task(spec)
    assert t.workdir == str(tmp_path / "src")
    assert t.in_dir == str(tmp_path / "in")
    assert t.out_dir == str(tmp_path / "out")
    assert t.skills_dir == str(tmp_path / "skills")
    assert t.output_path == str(tmp_path / "out" / "triage.json")
    assert spec.task.workdir == "/work/src"  # original untouched


def test_end_to_end_ok(tmp_path):
    res = LocalRunner().run_workbench(spec_for(tmp_path))
    assert res.status == StageStatus.ok, res.errors
    assert res.output["decision"] == "light"
    assert res.model == "agent-small"
    assert res.harness == "fake"
    written = json.loads((tmp_path / "in" / "task.json").read_text())
    assert written["workdir"] == str(tmp_path / "src")
    assert (tmp_path / "out" / "transcript.jsonl").stat().st_size > 0
    # the harness subprocess received the gateway + harness-home env through the entrypoint
    assert "OUTPUT CONTRACT" in (tmp_path / "out" / "prompts.jsonl").read_text()


def test_end_to_end_repair(tmp_path):
    res = LocalRunner().run_workbench(spec_for(tmp_path, mode="invalid_then_valid"))
    assert res.status == StageStatus.ok
    assert res.attempts == 2


def test_end_to_end_entrypoint_timeout(tmp_path):
    res = LocalRunner().run_workbench(spec_for(tmp_path, mode="sleep", wall_clock_s=2))
    assert res.status == StageStatus.timeout


def _script(tmp_path: Path, body: str) -> str:
    p = tmp_path / "fakepython.sh"
    p.write_text(f"#!/bin/sh\n{body}\n")
    p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return str(p)


def test_missing_result_is_harness_error(tmp_path):
    runner = LocalRunner(python=_script(tmp_path, "echo entrypoint exploded >&2; exit 4"))
    res = runner.run_workbench(spec_for(tmp_path))
    assert res.status == StageStatus.harness_error
    assert "exit code 4" in res.errors[0]
    assert "exploded" in res.errors[1]


def test_runaway_entrypoint_is_killed(tmp_path):
    runner = LocalRunner(python=_script(tmp_path, "sleep 30"), grace_s=0.5)
    res = runner.run_workbench(spec_for(tmp_path, wall_clock_s=1))
    assert res.status == StageStatus.timeout
    assert res.duration_s < 10


def test_local_runner_has_no_dynamic_envs(tmp_path):
    from prsec.dynamic.results import EnvRequest

    runner = LocalRunner()
    req = EnvRequest(env_dir=str(tmp_path))
    with pytest.raises(NotImplementedError, match="runner_unsupported"):
        runner.create_env(7, "h1", req)
    runner.destroy_env(7, "h1")  # no-op
    spec = spec_for(tmp_path)
    with pytest.raises(NotImplementedError, match="runner_unsupported"):
        runner.run_replay(spec)

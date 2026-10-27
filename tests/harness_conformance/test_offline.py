"""Offline conformance tier: every registered adapter, driven end to end through LocalRunner ->
prsec-stage entrypoint -> run_task, against a deterministic stand-in harness (stub CLI for
subprocess adapters, a stub OpenAI-compatible gateway for in-process ones).

A new adapter is only "supported" once it passes this module (plus the live tier for its CLI).
Network egress is not covered here; tests/runner/test_docker_egress.py covers it for DockerRunner.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from prsec.adapters.harness.base import HarnessAdapter
from prsec.models import Event, EventKind, StageStatus

from .conftest import GATEWAY_KEY, TOKEN, Bench, cli_name, wait_gone


def _kinds(events: list[Event]) -> set[EventKind]:
    return {e.kind for e in events}


def _assert_transcript(bench: Bench, result, out_dir: Path) -> None:
    kinds = _kinds(result.transcript)
    assert EventKind.message in kinds and EventKind.usage in kinds, kinds
    assert result.usage.turns >= 1 and result.usage.tokens_in > 0
    lines = (out_dir / "transcript.jsonl").read_text().splitlines()
    assert len(lines) == len(result.transcript)
    assert all(Event.model_validate_json(line).ts is not None for line in lines)
    assert json.loads((out_dir / "result.json").read_text())["status"] == result.status.value


def test_adapter_shape(bench: Bench) -> None:
    a = bench.adapter
    assert isinstance(a, HarnessAdapter)
    assert a.caps.subprocess == (cli_name(a) is not None)
    if not a.caps.subprocess:
        assert callable(getattr(a, "run_inprocess", None))
    events = list(a.parse_events(["not json", "{\"type\": \"unknown-event\"}", "", "[1, 2]"]))
    assert all(isinstance(e, Event) for e in events)
    a.usage(events)
    a.session_id(events)


@pytest.mark.parametrize("gateway", [False, True], ids=["dev", "gateway"])
def test_skill_install_and_valid_output(bench: Bench, gateway: bool) -> None:
    result, spec = bench.run("ok", gateway=gateway)
    assert result.status == StageStatus.ok, result.errors
    assert result.attempts == 1
    assert result.output == {"skill_token": TOKEN, "answer": "DONE", **({"fixture_line": "# conformance fixture repo"} if bench.adapter.caps.subprocess else {})}
    assert result.harness == bench.adapter.name
    _assert_transcript(bench, result, spec.out_dir)

    calls = bench.calls()
    assert len(calls) == 1
    call = calls[0]
    assert call["skill_token"] == TOKEN
    if bench.adapter.caps.subprocess:
        assert result.harness_version == "9.9.9"
        assert call["cwd"] in (str(spec.src_dir), str(spec.out_dir))
        # skills are a copy in the writable harness home, never the read-only source tree
        assert Path(call["skill_path"]).is_relative_to(spec.out_dir)
        # the PR checkout's CLAUDE.md / AGENTS.md / settings / skills (canaries) are never loaded
        assert call["project_files"] == []
        # container paths in the prompt were rewritten to the host dirs by LocalRunner
        assert "/work/" not in call["prompt"] and "`/skills/" not in call["prompt"]
        assert call["output_path"] == str(spec.out_dir / "output.json")
        assert call["gateway_key_visible"] is gateway and call["gateway_url_visible"] is gateway
        if gateway:
            assert Path(call["home"]).is_relative_to(spec.out_dir)
        if bench.adapter.name == "claude-code":
            assert call["parent_session_vars"] == []
    else:
        assert call["auth"] == (f"Bearer {GATEWAY_KEY}" if gateway else None)
        assert call["model"] == ("agent-small" if gateway else "stub-model")


def test_repair_loop_recovers(bench: Bench) -> None:
    result, spec = bench.run("repair")
    assert result.status == StageStatus.ok, result.errors
    assert result.attempts == 2
    assert result.output["skill_token"] == TOKEN
    assert (spec.out_dir / "output.attempt1.invalid.json").is_file()
    assert any(e.kind == EventKind.system and e.text == "output invalid" for e in result.transcript)
    calls = bench.calls()
    assert len(calls) == 2
    if bench.adapter.caps.subprocess and bench.adapter.caps.resume:
        assert calls[1]["resumed"] is True
        assert "skill_token" in calls[1]["prompt"]  # the validation errors are fed back
    else:
        second = calls[1].get("prompt") or calls[1].get("system")
        assert "REPAIR" in second and '"skill_token": 42' in second


def test_wall_clock_kill(bench: Bench) -> None:
    result, spec = bench.run("hang", wall_clock_s=3)
    assert result.status == StageStatus.timeout, result.errors
    assert result.duration_s < 3 + 15
    if bench.adapter.caps.subprocess:
        pid = bench.calls()[0]["pid"]
        assert wait_gone(pid), f"harness process {pid} survived the wall-clock kill"


def test_budget_kill(bench: Bench) -> None:
    result, _ = bench.run("repair", usd_budget=0.000001)
    if result.usage.usd == 0:
        assert result.status == StageStatus.ok
        pytest.skip(f"{bench.adapter.name} reports no USD; the gateway key budget is the enforcement point")
    assert result.status == StageStatus.budget_exceeded, result.errors
    assert result.attempts == 1


def test_budget_kill_via_per_task_gateway_key(bench: Bench) -> None:
    """Every harness, including those reporting $0, is stopped by the gateway spend of its per-task key."""
    bench.gateway.key_spend = 7.5
    task = bench.task("repair", usd_budget=1.0)
    spec = bench.spec(task, gateway=True, extra_env={"PRSEC_GATEWAY_KEY_SCOPE": "task"})
    result = bench.runner.run_workbench(spec)
    assert result.status == StageStatus.budget_exceeded, result.errors
    assert result.attempts == 1 and result.usage.usd >= 7.5
    assert bench.gateway.key_info_auth == [f"Bearer {GATEWAY_KEY}"]


def test_crash_without_output_is_harness_error(bench: Bench) -> None:
    if not bench.adapter.caps.subprocess:
        pytest.skip("in-process adapter")
    result, _ = bench.run("crash")
    assert result.status == StageStatus.harness_error
    assert "exited with code 3" in result.errors[0]
    assert "simulated crash" in "\n".join(result.errors)


def test_missing_cli_is_harness_error(bench: Bench, tmp_path: Path) -> None:
    if not bench.adapter.caps.subprocess:
        pytest.skip("in-process adapter")
    task = bench.task("ok")
    empty = tmp_path / "empty-harness"
    (empty / "bin").mkdir(parents=True)
    spec = bench.spec(task, gateway=False, harness_home=empty, extra_env={"PATH": os.pathsep.join(["/usr/bin", "/bin"])})
    result = bench.runner.run_workbench(spec)
    assert result.status == StageStatus.harness_error
    assert "failed to start harness" in result.errors[0]

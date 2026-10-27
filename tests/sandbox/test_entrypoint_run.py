import json
from pathlib import Path

import pytest
from fakeharness import VALID, make_task

from prsec.adapters.harness.base import GatewayConfig, get_adapter
from prsec.models import EventKind, StageStatus
from prsec.sandbox.entrypoint import contract
from prsec.sandbox.entrypoint.run import run_task

GW = GatewayConfig(base_url="http://llm-gateway:4000", api_key="sk-scan", model="agent-small")


def prompts(task) -> list[dict]:
    path = Path(task.out_dir) / "prompts.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


@pytest.fixture
def mode(monkeypatch):
    def set_mode(m: str) -> None:
        monkeypatch.setenv("FAKE_MODE", m)

    return set_mode


def test_valid_first_try(tmp_path, mode):
    mode("valid")
    task = make_task(tmp_path)
    res = run_task(task, get_adapter("fake"), GW)

    assert res.status == StageStatus.ok, res.errors
    assert res.output["decision"] == "light" and res.output["focus_files"] == []
    assert res.attempts == 1
    assert res.harness == "fake" and res.harness_version == "fake 1.0" and res.model == "agent-small"
    assert res.usage.usd == pytest.approx(0.01) and res.usage.tokens_in == 100
    kinds = {e.kind for e in res.transcript}
    assert {EventKind.message, EventKind.tool_call, EventKind.usage, EventKind.system} <= kinds
    assert all(e.ts is not None for e in res.transcript)

    schema = json.loads((Path(task.in_dir) / "output_schema.json").read_text())
    assert not (Path(task.out_dir) / "output.schema.json").exists()
    assert schema["title"] == "TriageOutput"
    prompt = prompts(task)[0]["prompt"]
    assert prompt.startswith("# Triage")
    for needle in ("OUTPUT CONTRACT", task.output_path, f"{task.in_dir}/output_schema.json", "prsec-cite check",
                   task.workdir, str(Path(task.in_dir) / "diff.patch"), "DONE"):
        assert needle in prompt
    assert "demo skill" in (Path(task.out_dir) / "skills_index.md").read_text()


def test_dev_mode_without_gateway_uses_task_model(tmp_path, mode):
    mode("valid")
    res = run_task(make_task(tmp_path), get_adapter("fake"), None)
    assert res.status == StageStatus.ok and res.model == "agent-small"


def test_stale_output_is_not_accepted(tmp_path, mode):
    mode("no_output")
    task = make_task(tmp_path, repair_attempts=0)
    Path(task.output_path).write_text(json.dumps(VALID))
    res = run_task(task, get_adapter("fake"), GW)
    assert res.status == StageStatus.output_invalid
    assert "was not written" in res.errors[0]


def test_repair_via_resume(tmp_path, mode):
    mode("invalid_then_valid")
    task = make_task(tmp_path)
    res = run_task(task, get_adapter("fake"), GW)

    assert res.status == StageStatus.ok, res.errors
    assert res.attempts == 2
    calls = prompts(task)
    assert calls[1]["resume"] == "sess-1"
    repair = calls[1]["prompt"]
    assert "failed validation" in repair and "decision" in repair and "OUTPUT CONTRACT" not in repair
    assert (Path(task.out_dir) / "triage.attempt1.invalid.json").exists()
    assert res.usage.usd == pytest.approx(0.02)


def test_repair_via_fresh_call_when_no_resume(tmp_path, mode):
    mode("invalid_then_valid")
    task = make_task(tmp_path, harness="fake-noresume")
    res = run_task(task, get_adapter("fake-noresume"), GW)

    assert res.status == StageStatus.ok, res.errors
    assert res.attempts == 2
    second = prompts(task)[1]
    assert second["resume"] is None
    p = second["prompt"]
    assert "OUTPUT CONTRACT" in p and "REPAIR" in p and '"maybe"' in p and "$.decision" in p


def test_resume_refused_falls_back_to_fresh(tmp_path, mode):
    mode("invalid_then_valid")
    task = make_task(tmp_path, harness="fake-resume-refused")
    res = run_task(task, get_adapter("fake-resume-refused"), GW)
    assert res.status == StageStatus.ok
    assert prompts(task)[1]["resume"] is None and "REPAIR" in prompts(task)[1]["prompt"]


def test_not_json_is_repaired(tmp_path, mode):
    mode("not_json_then_valid")
    res = run_task(make_task(tmp_path), get_adapter("fake"), GW)
    assert res.status == StageStatus.ok and res.attempts == 2


def test_never_valid_gives_output_invalid(tmp_path, mode):
    mode("never_valid")
    task = make_task(tmp_path, repair_attempts=2)
    res = run_task(task, get_adapter("fake"), GW)
    assert res.status == StageStatus.output_invalid
    assert res.attempts == 3
    assert res.output is None
    assert any("decision" in e for e in res.errors)


def test_timeout_kills_harness(tmp_path, mode):
    mode("sleep")
    res = run_task(make_task(tmp_path, wall_clock_s=2), get_adapter("fake"), GW)
    assert res.status == StageStatus.timeout
    assert res.duration_s < 15
    assert "wall clock" in res.errors[0]


def test_output_written_before_timeout_is_kept(tmp_path, mode):
    mode("write_then_sleep")
    res = run_task(make_task(tmp_path, wall_clock_s=2), get_adapter("fake"), GW)
    assert res.status == StageStatus.ok


def test_budget_exceeded(tmp_path, mode):
    mode("expensive")
    res = run_task(make_task(tmp_path, usd_budget=1.0), get_adapter("fake"), GW)
    assert res.status == StageStatus.budget_exceeded
    assert res.attempts == 1
    assert res.usage.usd == pytest.approx(10.0)


def test_garbage_stdout_is_tolerated(tmp_path, mode):
    mode("garbage_ok")
    res = run_task(make_task(tmp_path), get_adapter("fake"), GW)
    assert res.status == StageStatus.ok
    assert any(e.data.get("unparsed") for e in res.transcript)


def test_crash_without_output_is_harness_error(tmp_path, mode):
    mode("garbage_crash")
    res = run_task(make_task(tmp_path), get_adapter("fake"), GW)
    assert res.status == StageStatus.harness_error
    assert res.attempts == 1
    assert "code 3" in res.errors[0]
    assert "auth failed" in res.errors[1]


def test_missing_binary_is_harness_error(tmp_path, mode):
    mode("valid")
    res = run_task(make_task(tmp_path, harness="fake-missing-binary"), get_adapter("fake-missing-binary"), GW)
    assert res.status == StageStatus.harness_error
    assert "failed to start" in res.errors[0]


def test_install_skills_failure_is_harness_error(tmp_path, mode, monkeypatch):
    adapter = get_adapter("fake")
    monkeypatch.setattr(adapter, "install_skills", lambda task: (_ for _ in ()).throw(OSError("ro fs")))
    res = run_task(make_task(tmp_path), adapter, GW)
    assert res.status == StageStatus.harness_error and "ro fs" in res.errors[0]


def test_raising_parse_events_does_not_hang(tmp_path, mode, monkeypatch):
    mode("valid")
    adapter = get_adapter("fake")

    def bad_parse(lines):
        next(iter(lines))
        raise ValueError("boom")
        yield  # pragma: no cover

    monkeypatch.setattr(adapter, "parse_events", bad_parse)
    res = run_task(make_task(tmp_path), adapter, GW)
    assert res.status == StageStatus.ok
    assert any(e.kind == EventKind.error and "boom" in e.text for e in res.transcript)


# ------------------------------------------------------------- in-process


def test_inprocess_valid_and_repair(tmp_path, mode):
    mode("invalid_then_valid")
    adapter = get_adapter("fake-inproc")
    res = run_task(make_task(tmp_path, harness="fake-inproc"), adapter, GW)
    assert res.status == StageStatus.ok and res.attempts == 2
    assert "REPAIR" in adapter.calls[1]
    assert res.usage.usd == pytest.approx(0.04)


def test_inprocess_timeout(tmp_path, mode):
    mode("sleep")
    res = run_task(make_task(tmp_path, harness="fake-inproc", wall_clock_s=1), get_adapter("fake-inproc"), GW)
    assert res.status == StageStatus.timeout


def test_inprocess_exception_is_harness_error(tmp_path, mode):
    mode("raise")
    res = run_task(make_task(tmp_path, harness="fake-inproc"), get_adapter("fake-inproc"), GW)
    assert res.status == StageStatus.harness_error
    assert "provider 500" in "\n".join(res.errors)


# ------------------------------------------------------------- validation


def test_pydantic_model_applies_only_to_matching_schema(tmp_path):
    task = make_task(tmp_path)
    Path(task.output_path).write_text(json.dumps(VALID))
    out, errs, _ = contract.validate_output(task)
    assert not errs and out["business_flows_touched"] == []

    custom = task.model_copy(update={"output_schema": {"type": "object", "required": ["x"]}})
    Path(task.output_path).write_text(json.dumps({"x": 1}))
    out, errs, _ = contract.validate_output(custom)
    assert not errs and out == {"x": 1}

    Path(task.output_path).write_text("[1, 2]")
    _, errs, _ = contract.validate_output(task)
    assert errs


def test_budget_uses_gateway_spend_for_per_task_keys(tmp_path, mode, monkeypatch):
    """A harness that reports $0 (or too little) cannot overspend: the per-task key's gateway spend counts."""
    import dataclasses

    from prsec import gateway

    calls = []
    monkeypatch.setattr(gateway, "self_spend", lambda url, key: calls.append((url, key)) or 5.0)
    mode("never_valid")
    task = make_task(tmp_path, usd_budget=1.0, repair_attempts=2)
    res = run_task(task, get_adapter("fake"), dataclasses.replace(GW, per_task_key=True))
    assert res.status == StageStatus.budget_exceeded and res.attempts == 1
    assert res.usage.usd == pytest.approx(5.0)
    assert calls == [("http://llm-gateway:4000", "sk-scan")]


def test_shared_scan_key_spend_is_not_used(tmp_path, mode, monkeypatch):
    from prsec import gateway

    monkeypatch.setattr(gateway, "self_spend", lambda url, key: pytest.fail("scan-wide spend must not be queried"))
    mode("valid")
    res = run_task(make_task(tmp_path), get_adapter("fake"), GW)
    assert res.status == StageStatus.ok and res.usage.usd == pytest.approx(0.01)

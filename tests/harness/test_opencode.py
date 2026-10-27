from __future__ import annotations

import json
from pathlib import Path

import pytest

from prsec.adapters.harness import opencode
from prsec.adapters.harness.base import GatewayConfig, HarnessAdapter, get_adapter
from prsec.adapters.harness.opencode import OpenCodeAdapter
from prsec.models import EventKind, Stage, StageTask

FIX = Path(__file__).parent / "fixtures" / "opencode"
GW = GatewayConfig(base_url="http://llm-gateway:4000/", api_key="sk-scan-42", model="agent-large")
SID = "ses_e8286f379ffeuPWV1FaMXOg3MR"


def lines(name: str) -> list[str]:
    return (FIX / name).read_text().splitlines()


@pytest.fixture
def task(tmp_path: Path) -> StageTask:
    skills = tmp_path / "skills"
    for name in ("taint-analysis", "business-logic"):
        (skills / name / "scripts").mkdir(parents=True)
        (skills / name / "SKILL.md").write_text(f"---\nname: {name}\ndescription: {name} method\n---\n# {name}\n")
        (skills / name / "scripts" / "helper.sh").write_text("echo PRSEC_CANARY\n")
    (skills / "no-skill-md").mkdir()
    return StageTask(
        scan_id=42,
        stage=Stage.hypothesise,
        task_id="42-hypothesise",
        harness="opencode",
        prompt_md="x",
        skills=["taint-analysis", "business-logic", "no-skill-md", "missing"],
        output_schema={"type": "object"},
        output_path=str(tmp_path / "out" / "hypothesise.json"),
        workdir="/work/src",
        out_dir=str(tmp_path / "out"),
        skills_dir=str(skills),
    )


@pytest.fixture(autouse=True)
def fixed_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(opencode, "resolve_cli", lambda cli: f"/opt/harness/bin/{cli}")
    monkeypatch.delenv(opencode.DEV_MODEL_ENV, raising=False)


def test_registered_and_protocol() -> None:
    a = get_adapter("opencode")
    assert isinstance(a, OpenCodeAdapter)
    assert isinstance(a, HarnessAdapter)
    assert a.caps.native_skills and a.caps.resume and a.caps.json_events
    assert not a.caps.max_turns and a.caps.subprocess


BASE = ["/opt/harness/bin/opencode", "run", "--format", "json", "--auto", "--title", "42-hypothesise"]


def test_build_gateway(task: StageTask) -> None:
    inv = OpenCodeAdapter().build(task, GW, "THE PROMPT")
    home = Path(task.out_dir) / ".home"
    assert inv.argv == BASE + ["--model", "prsec/agent-large"]
    assert inv.stdin == "THE PROMPT"
    assert inv.cwd == "/work/src"
    env = inv.env
    assert env["HOME"] == str(home)
    assert env["XDG_CONFIG_HOME"] == str(home / ".config")
    assert env["XDG_DATA_HOME"] == str(home / ".local" / "share")
    assert env["OPENCODE_CONFIG_DIR"] == str(home / ".opencode")
    assert env["OPENCODE_DISABLE_EXTERNAL_SKILLS"] == "1"
    assert env["OPENCODE_DISABLE_PROJECT_CONFIG"] == env["OPENCODE_DISABLE_CLAUDE_CODE"] == "1"
    assert env["OPENCODE_DISABLE_MODELS_FETCH"] == "1"
    assert env[opencode.KEY_ENV] == "sk-scan-42"

    cfg = json.loads(env["OPENCODE_CONFIG_CONTENT"])
    assert "sk-scan-42" not in env["OPENCODE_CONFIG_CONTENT"]  # key only via {env:...}
    assert cfg["model"] == cfg["small_model"] == "prsec/agent-large"
    assert cfg["enabled_providers"] == ["prsec"]
    prov = cfg["provider"]["prsec"]
    assert prov["npm"] == "@ai-sdk/openai-compatible"
    assert prov["options"] == {"baseURL": "http://llm-gateway:4000/v1", "apiKey": "{env:PRSEC_OPENCODE_API_KEY}"}
    assert list(prov["models"]) == ["agent-large"]
    assert cfg["permission"]["*"] == "allow"
    assert cfg["permission"]["webfetch"] == cfg["permission"]["task"] == "deny"
    assert cfg["autoupdate"] is False and cfg["share"] == "disabled"


def test_build_dev_mode_keeps_login(task: StageTask, monkeypatch: pytest.MonkeyPatch) -> None:
    inv = OpenCodeAdapter().build(task, None, "p")
    assert inv.argv == BASE
    assert "HOME" not in inv.env and opencode.KEY_ENV not in inv.env
    assert inv.env["OPENCODE_DISABLE_PROJECT_CONFIG"] == "1"
    cfg = json.loads(inv.env["OPENCODE_CONFIG_CONTENT"])
    assert "provider" not in cfg and "model" not in cfg
    assert cfg["permission"]["*"] == "allow"

    monkeypatch.setenv(opencode.DEV_MODEL_ENV, "anthropic/claude-sonnet-4-5")
    assert OpenCodeAdapter().build(task, None, "p").argv == BASE + ["--model", "anthropic/claude-sonnet-4-5"]


def test_build_resume(task: StageTask) -> None:
    inv = OpenCodeAdapter().build_resume(task, GW, SID, "fix the schema errors")
    assert inv is not None
    assert inv.argv == BASE + ["--model", "prsec/agent-large", "--session", SID]
    assert inv.stdin == "fix the schema errors"


def test_install_skills(task: StageTask) -> None:
    a = OpenCodeAdapter()
    a.install_skills(task)
    dest = Path(task.out_dir) / ".home" / ".opencode" / "skills"
    assert sorted(p.name for p in dest.iterdir()) == ["business-logic", "taint-analysis"]
    assert (dest / "taint-analysis" / "scripts" / "helper.sh").is_file()
    a.install_skills(task)  # idempotent
    assert (dest / "business-logic" / "SKILL.md").is_file()


def test_parse_tool_write() -> None:
    a = OpenCodeAdapter()
    events = list(a.parse_events(lines("run_tool_write.jsonl")))
    kinds = [e.kind for e in events]
    assert kinds == [
        EventKind.system, EventKind.message, EventKind.tool_call, EventKind.tool_result, EventKind.usage,
        EventKind.system, EventKind.message, EventKind.usage,
    ]
    call, result = events[2], events[3]
    assert call.tool == "write" and call.data["id"] == "call_1"
    assert call.data["input"]["filePath"] == "/work/out/output.json"
    assert result.text == "Wrote file successfully." and result.data == result.data | {"tool_use_id": "call_1", "is_error": False}
    assert events[1].text == "Writing output."
    assert events[0].ts is not None and events[0].ts.year == 2026
    assert a.session_id(events) == SID

    u = a.usage(events)
    assert (u.tokens_in, u.tokens_out, u.tokens_cache_read, u.turns, u.usd) == (2200, 68, 200, 2, 0.0)


def test_parse_resume() -> None:
    a = OpenCodeAdapter()
    events = list(a.parse_events(lines("resume.jsonl")))
    assert [e.text for e in events if e.kind == EventKind.message] == ["Done. Output written."]
    assert a.usage(events).turns == 1


def test_parse_error() -> None:
    events = list(OpenCodeAdapter().parse_events(lines("error.jsonl")))
    assert len(events) == 1 and events[0].kind == EventKind.error
    assert events[0].text.startswith("Unexpected server error")
    assert events[0].data["name"] == "UnknownError"


def test_parse_tool_error_and_cost() -> None:
    line = json.dumps({
        "type": "tool_use", "sessionID": "s1",
        "part": {"tool": "bash", "callID": "c9", "state": {"status": "error", "input": {"command": "id"}, "error": "boom"}},
    })
    finish = json.dumps({
        "type": "step_finish", "sessionID": "s1",
        "part": {"reason": "stop", "tokens": {"input": 10, "output": 5, "reasoning": 3, "cache": {"write": 2, "read": 7}}, "cost": 0.0125},
    })
    a = OpenCodeAdapter()
    events = list(a.parse_events([line, finish]))
    assert events[1].kind == EventKind.tool_result and events[1].text == "boom" and events[1].data["is_error"]
    u = a.usage(events)
    assert (u.tokens_in, u.tokens_out, u.tokens_cache_read, u.usd) == (12, 8, 7, 0.0125)


def test_parse_garbage_never_raises() -> None:
    a = OpenCodeAdapter()
    events = list(a.parse_events(lines("garbage.txt")))
    assert events, "garbage must still be recorded"
    assert all(e.kind in (EventKind.system, EventKind.message, EventKind.tool_call, EventKind.tool_result) for e in events)
    assert events[0].data.get("unparsed") is True
    assert a.session_id(events) is None
    assert a.usage(events).turns == 0

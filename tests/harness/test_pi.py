from __future__ import annotations

import json
from pathlib import Path

import pytest

from prsec.adapters.harness import pi
from prsec.adapters.harness.base import GatewayConfig, HarnessAdapter, get_adapter
from prsec.adapters.harness.pi import PiAdapter
from prsec.models import EventKind, Stage, StageTask

FIX = Path(__file__).parent / "fixtures" / "pi"
GW = GatewayConfig(base_url="http://llm-gateway:4000/", api_key="sk-scan-42", model="agent-large")
SID = "01a17d7f-4f6a-7083-8e88-d48f55ccd91f"


def lines(name: str) -> list[str]:
    return (FIX / name).read_text().splitlines()


@pytest.fixture
def task(tmp_path: Path) -> StageTask:
    skills = tmp_path / "skills"
    for name in ("taint-analysis", "business-logic"):
        (skills / name).mkdir(parents=True)
        (skills / name / "SKILL.md").write_text(f"---\nname: {name}\ndescription: {name} method\n---\n# {name}\n")
    return StageTask(
        scan_id=42,
        stage=Stage.hypothesise,
        task_id="42-hypothesise",
        harness="pi",
        prompt_md="x",
        skills=["taint-analysis", "business-logic", "missing"],
        output_schema={"type": "object"},
        output_path=str(tmp_path / "out" / "hypothesise.json"),
        workdir="/work/src",
        out_dir=str(tmp_path / "out"),
        skills_dir=str(skills),
    )


@pytest.fixture(autouse=True)
def fixed_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pi, "resolve_cli", lambda cli: f"/opt/harness/bin/{cli}")
    monkeypatch.delenv("PRSEC_PI_PROVIDER", raising=False)
    monkeypatch.delenv("PRSEC_PI_MODEL", raising=False)


def base_argv(task: StageTask) -> list[str]:
    home = Path(task.out_dir) / ".home"
    return [
        "/opt/harness/bin/pi", "-p", "--mode", "json",
        "--no-extensions", "--no-prompt-templates", "--no-themes", "--no-skills",
        "--tools", "read,bash,edit,write,grep,find,ls",
        "--session-dir", str(home / "pi-sessions"),
    ]


def test_registered_and_protocol() -> None:
    a = get_adapter("pi")
    assert isinstance(a, PiAdapter)
    assert isinstance(a, HarnessAdapter)
    assert a.caps.native_skills and a.caps.resume and a.caps.json_events
    assert not a.caps.mcp and not a.caps.max_turns


def test_build_gateway(task: StageTask) -> None:
    a = PiAdapter()
    a.install_skills(task)
    inv = a.build(task, GW, "THE PROMPT")
    home = Path(task.out_dir) / ".home"
    root = home / ".pi" / "prsec-skills"
    assert inv.argv == base_argv(task) + [
        "--skill", str(root / "taint-analysis"),
        "--skill", str(root / "business-logic"),
        "--provider", "prsec", "--model", "agent-large",
    ]
    assert inv.stdin == "THE PROMPT" and inv.cwd == task.out_dir  # context files are never read from the PR checkout
    assert inv.env == {
        "PI_OFFLINE": "1",
        "PI_TELEMETRY": "0",
        "HOME": str(home),
        "PI_CODING_AGENT_DIR": str(home / ".pi" / "agent"),
        "PRSEC_PI_API_KEY": "sk-scan-42",
    }
    models_path = home / ".pi" / "agent" / "models.json"
    raw = models_path.read_text()
    assert "sk-scan-42" not in raw  # apiKey names the env var, never the secret
    prov = json.loads(raw)["providers"]["prsec"]
    assert prov["baseUrl"] == "http://llm-gateway:4000/v1"
    assert prov["api"] == "openai-completions"
    assert prov["apiKey"] == "PRSEC_PI_API_KEY"
    assert [m["id"] for m in prov["models"]] == ["agent-large"]


def test_build_dev_mode(task: StageTask, monkeypatch: pytest.MonkeyPatch) -> None:
    inv = PiAdapter().build(task, None, "p")
    assert inv.argv == base_argv(task)  # skills not installed yet -> no --skill
    assert inv.env == {"PI_OFFLINE": "1", "PI_TELEMETRY": "0"}
    assert not (Path(task.out_dir) / ".home" / ".pi" / "agent" / "models.json").exists()

    monkeypatch.setenv("PRSEC_PI_MODEL", "claude-sonnet-4-5")
    assert PiAdapter().build(task, None, "p").argv[-2:] == ["--model", "claude-sonnet-4-5"]
    monkeypatch.setenv("PRSEC_PI_PROVIDER", "anthropic")
    assert PiAdapter().build(task, None, "p").argv[-4:] == ["--provider", "anthropic", "--model", "claude-sonnet-4-5"]


def test_dev_provider_without_model_is_rejected(task: StageTask, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PRSEC_PI_MODEL", raising=False)
    monkeypatch.setenv("PRSEC_PI_PROVIDER", "anthropic")
    with pytest.raises(ValueError, match="requires --model"):
        PiAdapter().build(task, None, "p")


def test_build_resume(task: StageTask) -> None:
    inv = PiAdapter().build_resume(task, GW, SID, "repair")
    assert inv is not None
    assert inv.argv[-2:] == ["--session", SID]
    assert "--session-dir" in inv.argv and inv.stdin == "repair"


def test_install_skills(task: StageTask) -> None:
    PiAdapter().install_skills(task)
    root = Path(task.out_dir) / ".home" / ".pi" / "prsec-skills"
    assert sorted(p.name for p in root.iterdir()) == ["business-logic", "taint-analysis"]


def test_parse_tool_write() -> None:
    a = PiAdapter()
    events = list(a.parse_events(lines("run_tool_write.jsonl")))
    assert events[0].kind == EventKind.system and events[0].data["session_id"] == SID
    assert a.session_id(events) == SID
    assert not any(e.data.get("type") == "message_update" for e in events)
    calls = [e for e in events if e.kind == EventKind.tool_call]
    results = [e for e in events if e.kind == EventKind.tool_result]
    assert len(calls) == 1 and calls[0].tool == "write" and calls[0].data["id"] == "call_1"
    assert calls[0].data["input"]["path"] == "/work/out/output.json"
    assert len(results) == 1 and results[0].text.startswith("Successfully wrote")
    assert results[0].data == {"tool_use_id": "call_1", "is_error": False}
    msgs = [e.text for e in events if e.kind == EventKind.message]
    assert msgs == ["Writing output.", "Done. Output written."]
    assert not any(e.kind == EventKind.error for e in events)
    u = a.usage(events)
    assert u.turns == 2
    assert u.tokens_in > 0 and u.tokens_out > 0


def test_parse_tool_error() -> None:
    events = list(PiAdapter().parse_events(lines("run_tool_error.jsonl")))
    results = [e for e in events if e.kind == EventKind.tool_result]
    assert len(results) == 1 and results[0].data["is_error"] is True
    assert "Validation failed" in results[0].text


def test_parse_resume() -> None:
    a = PiAdapter()
    events = list(a.parse_events(lines("resume.jsonl")))
    assert [e.text for e in events if e.kind == EventKind.message] == ["Done. Output written."]
    assert a.usage(events).turns == 1


def test_parse_error_retries() -> None:
    events = list(PiAdapter().parse_events(lines("error.jsonl")))
    errors = [e for e in events if e.kind == EventKind.error]
    assert len(errors) == 4  # initial attempt + 3 auto-retries, each an errored assistant message
    retries = [e for e in events if e.data.get("type") == "auto_retry_start"]
    assert [r.data["attempt"] for r in retries] == [1, 2, 3]
    end = [e for e in events if e.data.get("type") == "auto_retry_end"]
    assert end and end[0].text == "Connection error." and end[0].data["success"] is False


def test_usage_mapping() -> None:
    line = json.dumps({
        "type": "message_end",
        "message": {
            "role": "assistant", "content": [{"type": "text", "text": "ok"}], "timestamp": 1793106858964,
            "usage": {"input": 100, "output": 20, "cacheRead": 50, "cacheWrite": 10, "cost": {"total": 0.042}},
        },
    })
    a = PiAdapter()
    u = a.usage(list(a.parse_events([line])))
    assert (u.tokens_in, u.tokens_out, u.tokens_cache_read, u.usd, u.turns) == (110, 20, 50, 0.042, 1)


def test_parse_garbage_never_raises() -> None:
    a = PiAdapter()
    events = list(a.parse_events(lines("garbage.txt")))
    assert events and events[0].data.get("unparsed") is True
    assert a.session_id(events) is None

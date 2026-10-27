from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx

from prsec.adapters.harness.base import GatewayConfig, HarnessAdapter, get_adapter
from prsec.adapters.harness.raw import ANTHROPIC_URL, RawAdapter, truncate
from prsec.models import EventKind, Stage, StageTask

GW = GatewayConfig(base_url="http://llm-gateway:4000/", api_key="sk-scan-42", model="agent-small")
CHAT = "http://llm-gateway:4000/v1/chat/completions"
SCHEMA = {"type": "object", "properties": {"decision": {"type": "string"}}, "required": ["decision"]}


@pytest.fixture
def task(tmp_path: Path) -> StageTask:
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    (in_dir / "pr.json").write_text('{"title": "Add login"}')
    (in_dir / "diff.patch").write_text("+" + "a" * 500)
    (tmp_path / "secret.txt").write_text("OUTSIDE")
    skills = tmp_path / "skills" / "triage-rules"
    skills.mkdir(parents=True)
    (skills / "SKILL.md").write_text("---\nname: triage-rules\ndescription: d\n---\nSKIP docs-only PRs.\n")
    return StageTask(
        scan_id=7,
        stage=Stage.triage,
        task_id="7-triage",
        harness="raw",
        model_alias="agent-small",
        prompt_md="x",
        skills=["triage-rules", "missing"],
        output_schema=SCHEMA,
        output_path=str(tmp_path / "out" / "triage.json"),
        in_dir=str(in_dir),
        out_dir=str(tmp_path / "out"),
        skills_dir=str(tmp_path / "skills"),
        context_files=["pr.json", "diff.patch", "../secret.txt", "nope.txt"],
    )


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for k in ("PRSEC_RAW_BASE_URL", "PRSEC_RAW_API_KEY", "PRSEC_RAW_MODEL", "PRSEC_RAW_MAX_FILE_CHARS", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(k, raising=False)


def chat_reply(content: str, **usage: int) -> dict:
    u = {"prompt_tokens": 1000, "completion_tokens": 50, "prompt_tokens_details": {"cached_tokens": 200}} | usage
    return {"choices": [{"message": {"role": "assistant", "content": content}}], "usage": u}


def test_registered_and_caps() -> None:
    a = get_adapter("raw")
    assert isinstance(a, RawAdapter) and isinstance(a, HarnessAdapter)
    assert a.caps.subprocess is False and not a.caps.resume and not a.caps.native_skills


def test_build_not_supported(task: StageTask) -> None:
    a = RawAdapter()
    with pytest.raises(NotImplementedError):
        a.build(task, GW, "p")
    assert a.build_resume(task, GW, "s", "p") is None
    a.install_skills(task)  # no-op


def test_truncate() -> None:
    assert truncate("abc", 5) == "abc"
    out = truncate("x" * 20, 5)
    assert out.startswith("xxxxx\n") and "showing 5 of 20 chars" in out


def test_system_prompt_inlines_and_truncates(task: StageTask) -> None:
    sp = RawAdapter(max_file_chars=100).system_prompt(task, "STAGE PROMPT")
    assert sp.startswith("STAGE PROMPT")
    assert "You have NO tools" in sp and task.output_path in sp
    assert '"required": [\n    "decision"\n  ]' in sp
    assert '{"title": "Add login"}' in sp
    assert "showing 100 of 501 chars" in sp and "a" * 101 not in sp
    assert "OUTSIDE" not in sp and "refused: path outside the input directory" in sp
    assert "(missing)" in sp
    assert '<skill name="triage-rules">' in sp and "SKIP docs-only PRs." in sp
    assert 'name="missing"' not in sp


def test_max_file_chars_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PRSEC_RAW_MAX_FILE_CHARS", "1234")
    assert RawAdapter().max_file_chars == 1234


@respx.mock
def test_gateway_json_schema(task: StageTask) -> None:
    route = respx.post(CHAT).mock(return_value=httpx.Response(
        200, json=chat_reply('{"decision": "scan"}'), headers={"x-litellm-response-cost": "0.0031"}))
    a = RawAdapter()
    output, events, usage = a.run_inprocess(task, GW, "STAGE PROMPT")

    assert output == {"decision": "scan"}
    assert json.loads(Path(task.output_path).read_text()) == {"decision": "scan"}
    req = route.calls.last.request
    assert req.headers["authorization"] == "Bearer sk-scan-42"
    body = json.loads(req.content)
    assert body["model"] == "agent-small"
    assert body["response_format"]["type"] == "json_schema"
    assert body["response_format"]["json_schema"]["schema"] == SCHEMA
    assert body["messages"][0]["role"] == "system" and body["messages"][0]["content"].startswith("STAGE PROMPT")
    assert (usage.tokens_in, usage.tokens_out, usage.tokens_cache_read, usage.usd, usage.turns) == (800, 50, 200, 0.0031, 1)
    assert a.usage(events) == usage
    assert [e.kind for e in events] == [EventKind.system, EventKind.message, EventKind.usage]


@respx.mock
def test_gateway_rejects_json_schema_falls_back(task: StageTask) -> None:
    route = respx.post(CHAT).mock(side_effect=[
        httpx.Response(400, json={"error": {"message": "response_format json_schema not supported"}}),
        httpx.Response(200, json=chat_reply('```json\n{"decision": "skip"}\n```')),
    ])
    output, events, _ = RawAdapter().run_inprocess(task, GW, "p")
    assert output == {"decision": "skip"}
    assert route.call_count == 2
    assert json.loads(route.calls[1].request.content)["response_format"] == {"type": "json_object"}
    assert any("json_schema rejected" in (e.text or "") for e in events)


@respx.mock
def test_invalid_json_reply_written_for_repair(task: StageTask) -> None:
    respx.post(CHAT).mock(return_value=httpx.Response(200, json=chat_reply("I think it is fine.")))
    output, events, usage = RawAdapter().run_inprocess(task, GW, "p")
    assert output is None
    assert Path(task.output_path).read_text() == "I think it is fine."
    assert any(e.kind == EventKind.error and "not valid JSON" in (e.text or "") for e in events)
    assert usage.turns == 1


@respx.mock
def test_gateway_error(task: StageTask) -> None:
    respx.post(CHAT).mock(return_value=httpx.Response(500, text="boom"))
    output, events, usage = RawAdapter().run_inprocess(task, GW, "p")
    assert output is None and usage.turns == 0
    assert events[-1].kind == EventKind.error and "HTTPStatusError" in events[-1].text


@respx.mock
def test_dev_mode_openai_compatible(task: StageTask, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PRSEC_RAW_BASE_URL", "http://localhost:4000")
    monkeypatch.setenv("PRSEC_RAW_API_KEY", "dev-key")
    route = respx.post("http://localhost:4000/v1/chat/completions").mock(
        return_value=httpx.Response(200, json=chat_reply('{"decision": "scan"}')))
    output, _, _ = RawAdapter().run_inprocess(task, None, "p")
    assert output == {"decision": "scan"}
    req = route.calls.last.request
    assert req.headers["authorization"] == "Bearer dev-key"
    assert json.loads(req.content)["model"] == "agent-small"  # falls back to task.model_alias


@respx.mock
def test_dev_mode_anthropic(task: StageTask, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    route = respx.post(ANTHROPIC_URL).mock(return_value=httpx.Response(200, json={
        "content": [{"type": "text", "text": '{"decision": "scan"}'}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 300, "output_tokens": 40, "cache_read_input_tokens": 5, "cache_creation_input_tokens": 7},
    }))
    output, _, usage = RawAdapter().run_inprocess(task, None, "p")
    assert output == {"decision": "scan"}
    req = route.calls.last.request
    assert req.headers["x-api-key"] == "sk-ant-test" and "anthropic-version" in req.headers
    body = json.loads(req.content)
    assert body["system"].startswith("p") and body["max_tokens"] > 0
    assert (usage.tokens_in, usage.tokens_out, usage.tokens_cache_read) == (307, 40, 5)


def test_dev_mode_without_credentials(task: StageTask) -> None:
    output, events, _ = RawAdapter().run_inprocess(task, None, "p")
    assert output is None
    assert events[-1].kind == EventKind.error and "PRSEC_RAW_BASE_URL" in events[-1].text


def test_parse_events_never_raises() -> None:
    events = list(RawAdapter().parse_events(["garbage", "", "{}"]))
    assert len(events) == 2 and all(e.kind == EventKind.system for e in events)

"""Decision harnesses (rules stage): jev-decide (JEV-27B System 1) and openai-decide (OpenAI Decisions API)."""
import json

import httpx
import pytest

from prsec.adapters.harness.base import GatewayConfig, get_adapter
from prsec.adapters.harness.decide import (
    CONDITION,
    QUESTION,
    RELAY_PATH,
    JevDecideAdapter,
    OpenAIDecideAdapter,
    build_state,
)
from prsec.config import ShadowArm, load_policy
from prsec.gateway import ALLOWED_ROUTES
from prsec.models import Limits, Stage, StageTask
from prsec.orchestrator import stages

GW = GatewayConfig(base_url="http://llm-gateway:4000", api_key="sk-task", model="gpt-6-luna")


def task(tmp_path, diff="+ import os\n", title="Add webhook test ping", files="app.py\n", model="gpt-6-luna") -> StageTask:
    in_dir, out_dir = tmp_path / "in", tmp_path / "out"
    in_dir.mkdir(parents=True)
    out_dir.mkdir(parents=True)
    (in_dir / "pr.json").write_text(json.dumps({"repo": "acme/shop", "title": title, "body": "Lets users test hooks."}))
    (in_dir / "changed_files.txt").write_text(files)
    (in_dir / "diff.patch").write_text(diff)
    t = StageTask(scan_id=1, stage=Stage.rules, task_id="1-rules-shadow-x", harness="jev-decide",
                  model_alias=model, prompt_md="", output_schema={}, in_dir=str(in_dir), out_dir=str(out_dir),
                  limits=Limits(wall_clock_s=60, usd_budget=0.0))
    t.output_path = str(out_dir / "output.json")
    return t


def respond(body, seen=None, status=200):
    """The provider's reply; through the gateway relay it is the chat completion's message content."""
    def handler(req: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(req)
        if req.url.path == RELAY_PATH and status < 400:
            return httpx.Response(status, json={"choices": [{"message": {"role": "assistant", "content": json.dumps(body)}}]})
        return httpx.Response(status, json=body)
    return handler


def relayed(req: httpx.Request) -> dict:
    """The provider request body inside a relay chat request (asserting the chat request's shape)."""
    chat = json.loads(req.content)
    assert str(req.url) == "http://llm-gateway:4000/v1/chat/completions"
    assert req.headers["authorization"] == "Bearer sk-task"
    [msg] = chat["messages"]
    assert msg["role"] == "user"
    return {"model": chat["model"], "body": json.loads(msg["content"])}


def jev(probs, options=None, seen=None):
    body = {"kind": "noul", "probabilities": probs, "usage": {"prompt_tokens": 1200, "completion_tokens": 1}}
    if options is not None:
        body["options"] = options
    return JevDecideAdapter(transport=httpx.MockTransport(respond(body, seen)))


def openai(answer, seen=None, usage=None):
    body = {"answers": [answer], "usage": usage or {"input_tokens": 900}}
    return OpenAIDecideAdapter(transport=httpx.MockTransport(respond(body, seen)))


def predicate(p):
    return {"type": "predicate", "name": "security_relevant", "probability": p}


# ------------------------------------------------------------------ jev-decide


def test_jev_request_goes_through_the_gateway_relay(tmp_path):
    seen = []
    out, _, usage = jev([0.05, 0.95], seen=seen).run_inprocess(task(tmp_path, model="rules-jev"), GW, "ignored")
    [req] = seen
    sent = relayed(req)
    assert sent["model"] == "rules-jev"  # the task's alias: the key's models allowlist gates it
    body = sent["body"]
    assert (body["kind"], body["question"]) == ("noul", QUESTION)
    assert "Add webhook test ping" in body["state"]
    assert "+ import os" in body["state"]
    assert out == {"decision": "scan", "reason": "JEV System 1: P(security-relevant)=0.950; scans at >= 0.10"}
    assert json.loads((tmp_path / "out" / "output.json").read_text()) == out
    assert (usage.tokens_in, usage.turns) == (1200, 1)


@pytest.mark.parametrize(("probs", "threshold", "decision"), [
    ([0.97, 0.03], None, "skip"),
    ([0.85, 0.15], None, "scan"),   # default 0.10: when in doubt, scan
    ([0.85, 0.15], "0.2", "skip"),
])
def test_threshold(tmp_path, monkeypatch, probs, threshold, decision):
    if threshold:
        monkeypatch.setenv("PRSEC_DECIDE_SCAN_THRESHOLD", threshold)
    out, _, _ = jev(probs).run_inprocess(task(tmp_path), GW, "")
    assert out["decision"] == decision


def test_jev_named_options():
    a = JevDecideAdapter()
    assert a.p_yes({"probabilities": [0.9, 0.1], "options": ["yes", "no"]}) == 0.9
    assert a.p_yes({"probabilities": [0.9, 0.1], "options": ["false", "true"]}) == 0.1
    with pytest.raises(ValueError):
        a.p_yes({"probabilities": [0.2, 0.3, 0.5]})


def test_jev_dev_mode(tmp_path, monkeypatch):
    monkeypatch.delenv("PRSEC_JEV_DECIDE_URL", raising=False)
    out, events, _ = jev([0.5, 0.5]).run_inprocess(task(tmp_path), None, "")
    assert out is None
    assert "PRSEC_JEV_DECIDE_URL" in events[-1].text
    seen = []
    monkeypatch.setenv("PRSEC_JEV_DECIDE_URL", "http://spark:8001/v1/decide")
    out, _, _ = jev([0.5, 0.5], seen=seen).run_inprocess(task(tmp_path / "b"), None, "")
    assert str(seen[0].url) == "http://spark:8001/v1/decide"
    assert out["decision"] == "scan"


# ------------------------------------------------------------------ openai-decide


def test_openai_request_shape_and_predicate(tmp_path):
    seen = []
    out, _, usage = openai(predicate(0.04), seen=seen).run_inprocess(task(tmp_path), GW, "")
    [req] = seen
    sent = relayed(req)
    assert sent["model"] == "gpt-6-luna"
    body = sent["body"]
    assert body["model"] == "gpt-6-luna"  # the task's model alias names the Decisions model
    assert body["questions"] == [{"type": "predicate", "name": "security_relevant", "instructions": CONDITION}]
    assert "Add webhook test ping" in body["input"]
    assert out == {"decision": "skip", "reason": "OpenAI Decisions: P(security-relevant)=0.040; scans at >= 0.10"}
    assert usage.tokens_in == 900


@pytest.mark.parametrize(("answer", "error"), [
    ({"type": "refusal", "name": "security_relevant"}, "refused"),
    ({"type": "predicate", "name": "other", "probability": 0.5}, "no answer"),
    ({"type": "predicate", "name": "security_relevant", "probability": 1.7}, "unexpected predicate"),
    ({"type": "predicate", "name": "security_relevant"}, "unexpected predicate"),
])
def test_openai_refusal_and_bad_answers_are_no_decision(tmp_path, answer, error):
    out, events, _ = openai(answer).run_inprocess(task(tmp_path), GW, "")
    assert out is None
    assert error in events[-1].text


def test_openai_dev_mode_uses_the_public_endpoint_with_a_key(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    out, events, _ = openai(predicate(0.5)).run_inprocess(task(tmp_path), None, "")
    assert out is None
    assert "OPENAI_API_KEY" in events[-1].text
    seen = []
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai")
    monkeypatch.delenv("PRSEC_OPENAI_DECIDE_URL", raising=False)
    out, _, _ = openai(predicate(0.5), seen=seen).run_inprocess(task(tmp_path / "b"), None, "")
    assert str(seen[0].url) == "https://api.openai.com/v1/decisions"
    assert seen[0].headers["authorization"] == "Bearer sk-openai"


def test_http_errors_are_no_decision(tmp_path):
    a = OpenAIDecideAdapter(transport=httpx.MockTransport(respond({"error": "x"}, status=429)))
    out, events, _ = a.run_inprocess(task(tmp_path), GW, "")
    assert out is None
    assert events[-1].kind.value == "error"


# ------------------------------------------------------------------ shared


def test_state_is_truncated_diff_last(tmp_path):
    t = task(tmp_path, diff="x" * 200_000, files="".join(f"f{i}.py\n" for i in range(250)))
    state = build_state(t, 10_000)
    assert len(state) < 11_000
    assert "f0.py" in state
    assert "and 50 more" in state
    assert state.index("Changed files") < state.index("Diff:")


def test_relay_route_is_on_the_minted_key_allowlist():
    assert RELAY_PATH in ALLOWED_ROUTES


@pytest.mark.parametrize("content", ["not json", "[1]", None])
def test_relay_without_a_json_object_is_no_decision(tmp_path, content):
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})

    out, events, _ = OpenAIDecideAdapter(transport=httpx.MockTransport(handler)).run_inprocess(task(tmp_path), GW, "")
    assert out is None
    assert events[-1].kind.value == "error"


@pytest.mark.parametrize("harness", ["jev-decide", "openai-decide"])
def test_only_serve_the_rules_stage(harness):
    assert get_adapter(harness).caps.stages == frozenset({"rules"})
    policy = load_policy()
    arm = ShadowArm(stage="rules", name="d", harness=harness, model="gpt-6-luna")
    t, _ = stages.build_task(policy, Stage.rules, 1, "acme/shop", context_files=["pr.json"], shadow=arm)
    assert (t.harness, t.model_alias) == (harness, "gpt-6-luna")
    bad = policy.model_copy(update={"defaults": {**policy.defaults,
                                                 "triage": policy.defaults["triage"].model_copy(update={"harness": harness})}})
    with pytest.raises(ValueError, match="only serves rules"):
        stages.build_task(bad, Stage.triage, 1, "acme/shop", context_files=["pr.json"])

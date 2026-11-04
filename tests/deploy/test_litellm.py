"""LiteLLM gateway config and the server-side-tool stripping hook."""
from __future__ import annotations

import asyncio
import importlib.util
from pathlib import Path

import pytest
import yaml

LITELLM_DIR = Path(__file__).resolve().parents[2] / "deploy" / "compose" / "litellm"


@pytest.fixture(scope="module")
def cfg() -> dict:
    return yaml.safe_load((LITELLM_DIR / "config.yaml").read_text())


@pytest.fixture(scope="module")
def hooks():
    spec = importlib.util.spec_from_file_location("prsec_hooks", LITELLM_DIR / "prsec_hooks.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


def _models(cfg: dict) -> dict[str, dict]:
    return {m["model_name"]: m["litellm_params"] for m in cfg["model_list"]}


def test_aliases_route_to_direct_providers(cfg: dict) -> None:
    models = _models(cfg)
    assert {"agent-large", "agent-small", "judge"} <= set(models)
    for params in models.values():
        provider = params["model"].split("/", 1)[0]
        assert provider in {"anthropic", "openai", "prsec-decide"}
        if provider != "prsec-decide":  # the relay's provider key is checked in test_decision_models_are_relay_aliases
            assert params["api_key"] == f"os.environ/{provider.upper()}_API_KEY"


def test_judge_is_other_family_than_agent_large(cfg: dict) -> None:
    models = _models(cfg)
    assert models["judge"]["model"].split("/")[0] != models["agent-large"]["model"].split("/")[0]


def test_fallbacks_reference_known_aliases(cfg: dict) -> None:
    names = set(_models(cfg))
    for entry in cfg["router_settings"]["fallbacks"]:
        for src, dsts in entry.items():
            assert src in names
            assert set(dsts) <= names
    assert {"agent-large": ["agent-large-openai"]} in cfg["router_settings"]["fallbacks"]


def test_general_settings(cfg: dict) -> None:
    gs = cfg["general_settings"]
    assert gs["master_key"] == "os.environ/LITELLM_MASTER_KEY"
    assert gs["database_url"] == "os.environ/DATABASE_URL"
    assert gs["store_prompts_in_spend_logs"] is False
    ls = cfg["litellm_settings"]
    assert ls["drop_params"] is True
    assert ls["request_timeout"] > 0
    assert ls["callbacks"] == "prsec_hooks.strip_server_tools"


CONFIGS = ["config.yaml", "config.spark.yaml", "config.openai.yaml"]


@pytest.mark.parametrize("name", CONFIGS)
def test_no_custom_pass_through_routes(name: str) -> None:
    """Minted keys get no pass-through route (prsec.gateway.ALLOWED_ROUTES): on OSS LiteLLM a virtual key can
    call an auth: true pass-through only with Enterprise's allowed_passthrough_routes. Decision models are
    aliases behind the prsec-decide relay instead."""
    gs = yaml.safe_load((LITELLM_DIR / name).read_text())["general_settings"]
    assert not gs.get("pass_through_endpoints")


@pytest.mark.parametrize(("name", "aliases"), [
    ("config.yaml", {"gpt-6-luna"}),
    ("config.spark.yaml", {"gpt-6-luna", "rules-jev"}),
    ("config.openai.yaml", {"gpt-6-luna"}),
])
def test_decision_models_are_relay_aliases(name: str, aliases: set[str]) -> None:
    cfg = yaml.safe_load((LITELLM_DIR / name).read_text())
    assert cfg["litellm_settings"]["custom_provider_map"] == [
        {"provider": "prsec-decide", "custom_handler": "prsec_hooks.decide_relay"}]
    relayed = {n: p for n, p in _models(cfg).items() if p["model"].startswith("prsec-decide/")}
    assert set(relayed) == aliases
    for params in relayed.values():
        assert params["api_base"].startswith(("https://", "http://spark:")), params  # a fixed endpoint
        assert params["timeout"] <= 120
    assert relayed["gpt-6-luna"] == {"model": "prsec-decide/gpt-6-luna", "api_base": "https://api.openai.com/v1/decisions",
                                     "api_key": "os.environ/OPENAI_API_KEY", "timeout": 60}
    if "rules-jev" in relayed:
        assert relayed["rules-jev"]["api_base"] == "http://spark:8001/v1/decide"
        assert relayed["rules-jev"]["api_key"] == "none"  # self-hosted: the relay must not send a provider key


def test_policies_name_relay_aliases_for_decide_arms() -> None:
    """Every decide-harness shadow arm's model is a relay alias in the gateway config the policy runs with."""
    root = LITELLM_DIR.parents[2]
    pairs = [("prsec/policy/policy.yaml", "config.yaml"), ("policy-spark.yaml", "config.spark.yaml"),
             ("policy-openai.yaml", "config.openai.yaml")]
    for policy_file, config in pairs:
        policy = yaml.safe_load((root / policy_file).read_text())
        models = _models(yaml.safe_load((LITELLM_DIR / config).read_text()))
        arms = [a for a in policy.get("shadows") or [] if a["harness"] in ("jev-decide", "openai-decide")]
        assert arms, policy_file
        for arm in arms:
            assert models[arm["model"]]["model"].startswith("prsec-decide/"), (policy_file, arm)


def test_strip_anthropic_server_tools(hooks) -> None:
    data = {
        "tools": [
            {"type": "web_search_20250305", "name": "web_search"},
            {"type": "bash_20250124", "name": "bash"},
            {"name": "Read", "input_schema": {"type": "object"}},
        ],
        "mcp_servers": [{"url": "https://mcp.example.invalid"}],
    }
    removed = hooks.strip_request(data)
    assert removed == ["web_search_20250305", "mcp_servers"]
    assert [t.get("name") for t in data["tools"]] == ["bash", "Read"]
    assert "mcp_servers" not in data


def test_strip_openai_responses_tools_and_choice(hooks) -> None:
    data = {
        "tools": [{"type": "web_search_preview"}, {"type": "code_interpreter", "container": {"type": "auto"}}],
        "tool_choice": {"type": "web_search_preview"},
        "web_search_options": {},
    }
    hooks.strip_request(data)
    assert "tools" not in data
    assert "tool_choice" not in data
    assert "web_search_options" not in data


def test_function_tools_untouched(hooks) -> None:
    data = {"tools": [{"type": "function", "function": {"name": "mcp_like_name"}}], "tool_choice": "auto"}
    assert hooks.strip_request(data) == []
    assert data["tool_choice"] == "auto"
    assert len(data["tools"]) == 1


def test_pre_call_hook_returns_data(hooks) -> None:
    data = {"tools": [{"type": "web_fetch_20250910", "name": "web_fetch"}]}
    out = asyncio.run(hooks.strip_server_tools.async_pre_call_hook(None, None, data, "anthropic_messages"))
    assert out is data
    assert "tools" not in data


@pytest.mark.parametrize("data", [
    {"messages": [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": "https://example.invalid/x.png?d=1"}}]}]},
    {"messages": [{"role": "user", "content": [{"type": "image_url", "image_url": "http://minio:9000/prsec/x"}]}]},
    {"messages": [{"role": "user", "content": [{"type": "image", "source": {"type": "url", "url": "https://example.invalid/a"}}]}]},
    {"messages": [{"role": "user", "content": [{"type": "document", "source": {"type": "url", "url": "http://api:8080/"}}]}]},
    {"input": [{"role": "user", "content": [{"type": "input_image", "image_url": "https://example.invalid/i"}]}]},
    {"input": [{"role": "user", "content": [{"type": "input_file", "file_url": "https://example.invalid/f.pdf"}]}]},
    {"messages": [{"role": "user", "content": [{"type": "file", "file": {"file_url": "ftp://example.invalid/f"}}]}]},
    {"system": [{"type": "image", "source": {"type": "url", "url": "https://example.invalid/s"}}]},
])
def test_remote_content_urls_rejected(hooks, data) -> None:
    assert hooks.remote_urls(data)
    call = hooks.strip_server_tools.async_pre_call_hook(None, None, data, "acompletion")
    # HTTPException inside the proxy image, RemoteContentRejected without fastapi: both carry status 400
    with pytest.raises(Exception, match="remote URLs in message content are not allowed") as exc:
        asyncio.run(call)
    assert getattr(exc.value, "status_code", None) == 400


def test_inline_content_and_text_mentions_allowed(hooks) -> None:
    data = {
        "messages": [
            {"role": "user", "content": [
                {"type": "text", "text": "see https://example.invalid/docs for details"},
                {"type": "image_url", "image_url": {"url": "data:image/png;base64,iVBORw0KGgo="}},
                {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBORw0KGgo="}},
            ]},
            {"role": "tool", "content": '{"url": "https://example.invalid/in-a-string"}'},
        ],
        "metadata": {"url": "https://example.invalid/not-content"},
    }
    assert hooks.remote_urls(data) == []
    out = asyncio.run(hooks.strip_server_tools.async_pre_call_hook(None, None, data, "acompletion"))
    assert out is data


# ------------------------------------------------------------------ prsec-decide relay


def _response():
    from types import SimpleNamespace

    return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=None))], model=None)


def _relay(hooks, reply, seen, status=200):
    import httpx

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(status, json=reply)

    relay = hooks.DecideRelay()
    relay.transport = httpx.MockTransport(handler)
    relay.async_transport = httpx.MockTransport(handler)
    return relay


def _user(body) -> list[dict]:
    import json

    return [{"role": "user", "content": json.dumps(body)}]


def test_decide_relay_posts_the_body_to_the_configured_endpoint(hooks) -> None:
    import json

    seen: list = []
    relay = _relay(hooks, {"answers": [{"name": "q", "probability": 0.2}], "usage": {"input_tokens": 9}}, seen)
    body = {"model": "the-alias", "input": "diff", "questions": [{"type": "predicate"}]}
    out = relay.completion(model="gpt-6-luna", messages=_user(body), api_base="https://api.openai.com/v1/decisions",
                           api_key="sk-provider", model_response=_response(), timeout=30, headers={"x-caller": "1"})
    [req] = seen
    assert str(req.url) == "https://api.openai.com/v1/decisions"
    assert req.headers["authorization"] == "Bearer sk-provider"
    assert "x-caller" not in req.headers  # caller headers never reach the provider
    assert json.loads(req.content) == {**body, "model": "gpt-6-luna"}  # the alias's model, not the caller's
    assert json.loads(out.choices[0].message.content)["answers"][0]["probability"] == 0.2
    assert out.model == "gpt-6-luna"


def test_decide_relay_async_and_no_key_for_self_hosted(hooks) -> None:
    import json

    seen: list = []
    relay = _relay(hooks, {"probabilities": [0.1, 0.9]}, seen)
    body = {"kind": "noul", "state": "s", "question": "q"}
    out = asyncio.run(relay.acompletion(model="jev-27b", messages=_user(body), api_base="http://spark:8001/v1/decide",
                                        api_key="none", model_response=_response(), timeout=None))
    [req] = seen
    assert "authorization" not in req.headers
    assert json.loads(req.content) == body  # no `model` in the body: none is added
    assert json.loads(out.choices[0].message.content) == {"probabilities": [0.1, 0.9]}


@pytest.mark.parametrize(("messages", "status"), [
    ([], 400),
    ([{"role": "user", "content": "{}"}, {"role": "user", "content": "{}"}], 400),
    ([{"role": "system", "content": "{}"}], 400),
    ([{"role": "user", "content": [{"type": "text", "text": "{}"}]}], 400),
    ([{"role": "user", "content": "not json"}], 400),
    ([{"role": "user", "content": "[1, 2]"}], 400),
    ([{"role": "user", "content": "x" * ((1 << 20) + 1)}], 413),
])
def test_decide_relay_refuses_anything_but_one_json_body(hooks, messages, status) -> None:
    seen: list = []
    with pytest.raises(hooks.CustomLLMError) as exc:
        _relay(hooks, {}, seen).completion(model="m", messages=messages, api_base="https://x.invalid/d",
                                           api_key="k", model_response=_response())
    assert exc.value.status_code == status
    assert not seen


@pytest.mark.parametrize("api_base", [None, "", "file:///etc/passwd", "spark:8001/v1/decide"])
def test_decide_relay_needs_an_http_endpoint(hooks, api_base) -> None:
    with pytest.raises(hooks.CustomLLMError) as exc:
        _relay(hooks, {}, []).completion(model="m", messages=_user({}), api_base=api_base, api_key="k",
                                         model_response=_response())
    assert exc.value.status_code == 500


def test_decide_relay_maps_provider_errors(hooks) -> None:
    with pytest.raises(hooks.CustomLLMError) as exc:
        _relay(hooks, {"error": "rate limited"}, [], status=429).completion(
            model="m", messages=_user({}), api_base="https://x.invalid/d", api_key="k", model_response=_response())
    assert exc.value.status_code == 429
    assert "rate limited" in str(exc.value)

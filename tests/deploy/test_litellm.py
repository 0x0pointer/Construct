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
        assert provider in {"anthropic", "openai"}
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

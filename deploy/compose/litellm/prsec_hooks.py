"""LiteLLM proxy pre-call hook: strip provider-executed (server-side) tools, refuse remote content.

Server-side tools (web search/fetch, hosted code execution, remote MCP connectors, ...)
run at the provider, so they bypass the per-scan network isolation: the PR source the
agent holds could leave the VM through them. Harness adapters also disable their web
tools; this hook is the gateway-side backstop for every route (/v1/messages,
/v1/responses, /v1/chat/completions).

Remote content: when a request carries an http(s) URL as an image/file/document part, LiteLLM (or
the provider) downloads it, e.g. to base64-encode an image for an Anthropic route. The gateway sits on
the control network and has internet access, so that would turn it into an egress proxy for the
otherwise isolated workbench (to the internet, or to control-network services). The hook therefore
rejects any request whose message content references a non-`data:` URL, on every route.

The built-in `tool_permission` guardrail only inspects `type: function` tools, so it
cannot do this (checked against LiteLLM v1.105.5).

Loaded via `litellm_settings.callbacks: prsec_hooks.strip_server_tools` (module path
is resolved relative to config.yaml).

Decision relay (`litellm_settings.custom_provider_map: [{provider: prsec-decide, custom_handler:
prsec_hooks.decide_relay}]`): the rules shadow arms' decision models (JEV-27B System 1's POST
/v1/decide, the OpenAI Decisions API's POST /v1/decisions) are not chat models. Each is an ordinary
model alias (`model: prsec-decide/<provider model>`, `api_base: <the endpoint URL>`), so a minted key
reaches one only when the alias is in its `models` allowlist, like any model; a key-authenticated
pass-through route would instead need LiteLLM Enterprise's `allowed_passthrough_routes` on the key.
The decide harness (prsec/adapters/harness/decide.py) sends the provider's JSON request body as the
one user message; the relay posts it to the configured endpoint (never one the caller names), with
the alias's own model, and returns the provider's JSON as the message content.
"""
from __future__ import annotations

import json
import logging
from typing import Any, NoReturn

import httpx

try:  # the module is unit-tested without litellm installed
    from litellm.integrations.custom_logger import CustomLogger
    from litellm.llms.custom_llm import CustomLLM, CustomLLMError
    from litellm.types.utils import Usage
except ImportError:  # pragma: no cover - exercised only outside the proxy image
    CustomLogger = object  # type: ignore[misc,assignment]
    CustomLLM = object  # type: ignore[misc,assignment]
    Usage = None  # type: ignore[assignment,misc]

    class CustomLLMError(Exception):  # type: ignore[no-redef]
        def __init__(self, status_code: int, message: str) -> None:
            super().__init__(message)
            self.status_code = status_code
            self.message = message

log = logging.getLogger("prsec.gateway")

# `type` prefixes of tools executed by the provider, across Anthropic Messages and
# OpenAI Responses / Chat Completions. Client-executed schema tools (Anthropic
# bash_*/text_editor_*/memory_*, OpenAI local_shell/shell/apply_patch/custom/function)
# stay, because the harness executes them inside the sandbox.
SERVER_TOOL_PREFIXES: tuple[str, ...] = (
    "web_search",  # anthropic web_search_2025xxxx, openai web_search / web_search_preview
    "web_fetch",
    "code_execution",
    "code_interpreter",
    "file_search",
    "image_generation",
    "computer",  # computer_20xx / computer_use_preview: never needed by prsec
    "mcp",  # openai hosted remote MCP, anthropic mcp_toolset
    "url_context",
    "google_search",
)

# Top-level request params that enable provider-side tools without a `tools` entry.
SERVER_TOOL_PARAMS: tuple[str, ...] = ("web_search_options", "mcp_servers", "container")


# Keys under which message content parts carry a fetchable reference, across OpenAI chat
# (`image_url: {url}`, `file: {file_url}`), OpenAI Responses (`input_image.image_url`,
# `input_file.file_url`) and Anthropic (`source: {type: url, url}`).
URL_KEYS: frozenset[str] = frozenset({"url", "image_url", "file_url", "document_url", "audio_url", "video_url"})
CONTENT_FIELDS: tuple[str, ...] = ("messages", "input", "system", "contents", "prompt")


class RemoteContentRejected(ValueError):
    status_code = 400


def _is_remote(value: str) -> bool:
    v = value.strip()
    return bool(v) and not v.lower().startswith("data:")


def _collect_urls(node: Any, found: list[str]) -> None:
    if isinstance(node, list):
        for item in node:
            _collect_urls(item, found)
        return
    if not isinstance(node, dict):
        return
    for key, value in node.items():
        if key in URL_KEYS and isinstance(value, str):
            if _is_remote(value):
                found.append(value)
        else:
            _collect_urls(value, found)


def remote_urls(data: dict[str, Any]) -> list[str]:
    """Every non-`data:` URL referenced by message content in the request."""
    found: list[str] = []
    for name in CONTENT_FIELDS:
        if name in data:
            _collect_urls(data[name], found)
    return found


def _reject(message: str) -> NoReturn:
    try:
        from fastapi import HTTPException
    except ImportError:  # pragma: no cover - fastapi ships with the proxy
        raise RemoteContentRejected(message) from None
    raise HTTPException(status_code=400, detail=message)


def is_server_tool(tool: Any) -> bool:
    if not isinstance(tool, dict):
        return False
    ttype = tool.get("type")
    if not isinstance(ttype, str) or ttype in ("function", "custom"):
        return False
    return ttype.startswith(SERVER_TOOL_PREFIXES)


def _strip_tools(data: dict[str, Any]) -> list[str]:
    """Drop server-side entries from `data["tools"]`; returns their types."""
    tools = data.get("tools")
    if not isinstance(tools, list):
        return []
    removed = [str(tool.get("type")) for tool in tools if is_server_tool(tool)]
    if not removed:
        return []
    kept = [tool for tool in tools if not is_server_tool(tool)]
    if kept:
        data["tools"] = kept
    else:  # an empty tools list / dangling tool_choice is rejected by providers
        data.pop("tools")
        data.pop("tool_choice", None)
    return removed


def strip_request(data: dict[str, Any]) -> list[str]:
    """Remove server-side tools/params from `data` in place. Returns what was removed."""
    removed = _strip_tools(data)
    choice = data.get("tool_choice")
    if isinstance(choice, dict) and is_server_tool(choice):
        data.pop("tool_choice")
        removed.append(f"tool_choice:{choice.get('type')}")
    for param in SERVER_TOOL_PARAMS:
        if param in data:
            data.pop(param)
            removed.append(param)
    return removed


class StripServerTools(CustomLogger):  # type: ignore[misc,valid-type]
    async def async_pre_call_hook(self, user_api_key_dict: Any, cache: Any, data: dict, call_type: Any) -> dict:
        removed = strip_request(data)
        if removed:
            log.warning("prsec: stripped server-side tools %s (call_type=%s)", removed, call_type)
        urls = remote_urls(data)
        if urls:
            log.warning("prsec: rejected request with %d remote content URL(s) (call_type=%s)", len(urls), call_type)
            _reject("prsec: remote URLs in message content are not allowed; inline the content as data: URLs")
        return data


strip_server_tools = StripServerTools()


# ------------------------------------------------------------------ decision relay

DECIDE_MAX_BODY_CHARS = 1 << 20  # the harness truncates its state to 60k chars; anything near 1 MiB is not it
DECIDE_TIMEOUT_S = 60.0
NO_KEY = ("", "none")  # api_key "none" (a self-hosted endpoint): send no Authorization header


def decide_request(messages: Any, model: str) -> dict[str, Any]:
    """The provider request body carried by the one user message; a body naming a `model` gets the alias's."""
    if not isinstance(messages, list) or len(messages) != 1:
        raise CustomLLMError(status_code=400, message="prsec-decide takes exactly one message: the JSON request body")
    msg = messages[0]
    content = msg.get("content") if isinstance(msg, dict) and msg.get("role") == "user" else None
    if not isinstance(content, str):
        raise CustomLLMError(status_code=400, message="prsec-decide: the message must be a user message with text content")
    if len(content) > DECIDE_MAX_BODY_CHARS:
        raise CustomLLMError(status_code=413, message="prsec-decide: request body too large")
    try:
        body = json.loads(content)
    except ValueError:
        raise CustomLLMError(status_code=400, message="prsec-decide: the message content is not JSON") from None
    if not isinstance(body, dict):
        raise CustomLLMError(status_code=400, message="prsec-decide: the request body must be a JSON object")
    if "model" in body:
        body["model"] = model
    return body


def _headers(api_key: Any) -> dict[str, str]:
    key = api_key if isinstance(api_key, str) else ""
    return {} if key.strip().lower() in NO_KEY else {"Authorization": f"Bearer {key}"}


def _timeout(timeout: Any) -> httpx.Timeout:
    if isinstance(timeout, httpx.Timeout):
        return timeout
    seconds = float(timeout) if isinstance(timeout, (int, float)) and timeout > 0 else DECIDE_TIMEOUT_S
    return httpx.Timeout(seconds, connect=15.0)


def _endpoint(api_base: Any) -> str:
    if not isinstance(api_base, str) or not api_base.startswith(("http://", "https://")):
        raise CustomLLMError(status_code=500, message="prsec-decide: the model's api_base must be the endpoint URL")
    return api_base


def decide_response(model_response: Any, model: str, resp: httpx.Response) -> Any:
    """Fill LiteLLM's response object: the provider's JSON as the content, its token counts as usage."""
    if resp.status_code >= 400:
        raise CustomLLMError(status_code=resp.status_code, message=f"decision endpoint HTTP {resp.status_code}: {resp.text[:500]}")
    try:
        data = resp.json()
    except ValueError:
        raise CustomLLMError(status_code=502, message="decision endpoint returned no JSON") from None
    model_response.choices[0].message.content = json.dumps(data)
    model_response.model = model
    u = data.get("usage") if isinstance(data, dict) else None
    u = u if isinstance(u, dict) else {}
    tokens_in = int(u.get("prompt_tokens") or u.get("input_tokens") or 0)
    tokens_out = int(u.get("completion_tokens") or u.get("output_tokens") or 0)
    if Usage is not None:
        model_response.usage = Usage(prompt_tokens=tokens_in, completion_tokens=tokens_out, total_tokens=tokens_in + tokens_out)
    return model_response


class DecideRelay(CustomLLM):  # type: ignore[misc,valid-type]
    """LiteLLM custom provider `prsec-decide` (see the module docstring). LiteLLM calls the handlers with
    keyword arguments only (api_key, model_response, timeout, headers, ...); caller headers are dropped."""

    transport: httpx.BaseTransport | None = None  # tests
    async_transport: httpx.AsyncBaseTransport | None = None

    def completion(self, model: str, messages: list, api_base: str, **kwargs: Any) -> Any:
        body = decide_request(messages, model)
        with httpx.Client(timeout=_timeout(kwargs.get("timeout")), transport=self.transport) as client:
            resp = client.post(_endpoint(api_base), json=body, headers=_headers(kwargs.get("api_key")))
        return decide_response(kwargs["model_response"], model, resp)

    async def acompletion(self, model: str, messages: list, api_base: str, **kwargs: Any) -> Any:
        body = decide_request(messages, model)
        async with httpx.AsyncClient(timeout=_timeout(kwargs.get("timeout")), transport=self.async_transport) as client:
            resp = await client.post(_endpoint(api_base), json=body, headers=_headers(kwargs.get("api_key")))
        return decide_response(kwargs["model_response"], model, resp)


decide_relay = DecideRelay()

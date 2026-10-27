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
"""
from __future__ import annotations

import logging
from typing import Any

try:  # the module is unit-tested without litellm installed
    from litellm.integrations.custom_logger import CustomLogger
except ImportError:  # pragma: no cover - exercised only outside the proxy image
    CustomLogger = object  # type: ignore[misc,assignment]

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


def remote_urls(data: dict[str, Any]) -> list[str]:
    """Every non-`data:` URL referenced by message content in the request."""
    found: list[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in URL_KEYS and isinstance(value, str):
                    if value.strip() and not value.strip().lower().startswith("data:"):
                        found.append(value)
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    for name in CONTENT_FIELDS:
        if name in data:
            walk(data[name])
    return found


def _reject(message: str) -> Exception:
    try:
        from fastapi import HTTPException

        return HTTPException(status_code=400, detail=message)
    except ImportError:  # pragma: no cover - fastapi ships with the proxy
        return RemoteContentRejected(message)


def is_server_tool(tool: Any) -> bool:
    if not isinstance(tool, dict):
        return False
    ttype = tool.get("type")
    if not isinstance(ttype, str) or ttype in ("function", "custom"):
        return False
    return ttype.startswith(SERVER_TOOL_PREFIXES)


def strip_request(data: dict[str, Any]) -> list[str]:
    """Remove server-side tools/params from `data` in place. Returns what was removed."""
    removed: list[str] = []
    tools = data.get("tools")
    if isinstance(tools, list):
        kept = []
        for tool in tools:
            if is_server_tool(tool):
                removed.append(str(tool.get("type")))
            else:
                kept.append(tool)
        if removed:
            if kept:
                data["tools"] = kept
            else:  # an empty tools list / dangling tool_choice is rejected by providers
                data.pop("tools")
                data.pop("tool_choice", None)
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
            raise _reject("prsec: remote URLs in message content are not allowed; inline the content as data: URLs")
        return data


strip_server_tools = StripServerTools()

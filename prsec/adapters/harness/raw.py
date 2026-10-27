"""raw adapter: one in-process chat completion, no tools.

The model cannot read files, so the system prompt inlines the stage prompt, every context file
(truncated to `max_file_chars`) and the full SKILL.md of each task skill. The reply must be the JSON
document itself; it is written to `task.output_path` for the entrypoint's validation/repair loop.

Gateway mode: POST `<gw.base_url>/v1/chat/completions` with `response_format=json_schema`
(falls back to `json_object` if the gateway rejects it with 400/422). Dev mode (gw None):
PRSEC_RAW_BASE_URL + PRSEC_RAW_API_KEY (same OpenAI-compatible call), else ANTHROPIC_API_KEY
against the Anthropic Messages API with a JSON-only instruction.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Iterable, Iterator

import httpx

from prsec.adapters.harness.base import Caps, GatewayConfig, Invocation, register
from prsec.models import Event, EventKind, StageTask, Usage

DEFAULT_MAX_FILE_CHARS = 100_000
MAX_TOKENS = 16_000
ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"
ANTHROPIC_DEFAULT_MODEL = "claude-opus-5-5"
_FENCE = re.compile(r"^\s*```(?:json)?\s*\n(.*?)\n\s*```\s*$", re.S)

RAW_NOTE = """

---

## RAW MODE (overrides the tool instructions above)

You have NO tools: you cannot run shell commands, read or write files. Every input file and skill
you need is included in full below. Respond with ONLY the JSON document required by the output
schema (no prose, no markdown fences); it will be written to `{output_path}` for you.
"""


def truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n…[truncated by prsec: showing {limit} of {len(text)} chars]\n"


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _strip_fences(text: str) -> str:
    m = _FENCE.match(text)
    return m.group(1) if m else text.strip()


@register
class RawAdapter:
    name = "raw"
    caps = Caps(native_skills=False, resume=False, json_events=False, max_turns=False, mcp=False, subprocess=False)

    def __init__(self, max_file_chars: int | None = None, transport: httpx.BaseTransport | None = None) -> None:
        env = os.environ.get("PRSEC_RAW_MAX_FILE_CHARS")
        self.max_file_chars = max_file_chars or (int(env) if env and env.isdigit() else DEFAULT_MAX_FILE_CHARS)
        self.transport = transport

    def version(self) -> str | None:
        return "1"

    def install_skills(self, task: StageTask) -> None:
        """Skills are inlined into the system prompt; nothing to install."""

    def build(self, task: StageTask, gw: GatewayConfig | None, prompt: str) -> Invocation:
        raise NotImplementedError("raw runs in-process; use run_inprocess()")

    def build_resume(self, task: StageTask, gw: GatewayConfig | None, session_id: str, prompt: str) -> Invocation | None:
        return None

    def parse_events(self, lines: Iterable[str]) -> Iterator[Event]:
        for line in lines:
            if line.strip():
                yield Event(kind=EventKind.system, text=line[:8000], data={"unparsed": True})

    def session_id(self, events: list[Event]) -> str | None:
        return None

    def usage(self, events: list[Event]) -> Usage:
        total = Usage()
        for e in events:
            if e.kind == EventKind.usage and isinstance(e.data.get("usage"), dict):
                total = total + Usage.model_validate(e.data["usage"])
        return total

    # -------------------------------------------------------------- prompt

    def system_prompt(self, task: StageTask, prompt: str) -> str:
        parts = [prompt.rstrip(), RAW_NOTE.format(output_path=task.output_path).rstrip()]
        parts.append(f"\n## Output JSON Schema\n\n```json\n{json.dumps(task.output_schema, indent=2)}\n```")
        in_dir = Path(task.in_dir)
        for rel in task.context_files:
            path = in_dir / rel
            if not _inside(path, in_dir):
                body = "(refused: path outside the input directory)"
            else:
                try:
                    body = truncate(path.read_text(encoding="utf-8", errors="replace"), self.max_file_chars)
                except OSError:
                    body = "(missing)"
            parts.append(f'\n<input_file path="{path}">\n{body}\n</input_file>')
        for name in task.skills:
            path = Path(task.skills_dir) / name / "SKILL.md"
            try:
                body = truncate(path.read_text(encoding="utf-8", errors="replace"), self.max_file_chars)
            except OSError:
                continue
            parts.append(f'\n<skill name="{name}">\n{body}\n</skill>')
        return "\n".join(parts) + "\n"

    # ---------------------------------------------------------- execution

    def _client(self, task: StageTask) -> httpx.Client:
        timeout = httpx.Timeout(float(task.limits.wall_clock_s), connect=15.0)
        return httpx.Client(timeout=timeout, transport=self.transport)

    def run_inprocess(self, task: StageTask, gw: GatewayConfig | None, prompt: str) -> tuple[dict | None, list[Event], Usage]:
        system = self.system_prompt(task, prompt)
        events: list[Event] = [Event(kind=EventKind.system, text="raw request", data={"system_chars": len(system)})]
        try:
            if gw is not None:
                text, usage = self._openai(task, gw.base_url, gw.api_key, gw.model, system, events)
            elif os.environ.get("PRSEC_RAW_BASE_URL"):
                model = os.environ.get("PRSEC_RAW_MODEL") or task.model_alias
                text, usage = self._openai(task, os.environ["PRSEC_RAW_BASE_URL"], os.environ.get("PRSEC_RAW_API_KEY", ""), model, system, events)
            elif os.environ.get("ANTHROPIC_API_KEY"):
                text, usage = self._anthropic(task, system, events)
            else:
                raise RuntimeError("raw dev mode needs PRSEC_RAW_BASE_URL or ANTHROPIC_API_KEY")
        except (httpx.HTTPError, RuntimeError, ValueError, KeyError, TypeError) as e:
            events.append(Event(kind=EventKind.error, text=f"{type(e).__name__}: {e}"))
            return None, events, Usage()

        events.append(Event(kind=EventKind.message, text=text))
        events.append(Event(kind=EventKind.usage, data={"usage": usage.model_dump()}))
        return self._write_output(task, text, events), events, usage

    def _write_output(self, task: StageTask, text: str, events: list[Event]) -> dict | None:
        out = Path(task.output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        body = _strip_fences(text)
        try:
            doc = json.loads(body)
        except ValueError as e:
            out.write_text(body)  # let the entrypoint report it and echo it in the repair prompt
            events.append(Event(kind=EventKind.error, text=f"model reply is not valid JSON: {e}"))
            return None
        out.write_text(json.dumps(doc, indent=2))
        return doc if isinstance(doc, dict) else None

    def _openai(self, task: StageTask, base_url: str, key: str, model: str, system: str, events: list[Event]) -> tuple[str, Usage]:
        url = base_url.rstrip("/") + "/v1/chat/completions"
        body: dict[str, Any] = {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": "Produce the JSON output document now."},
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": f"{task.stage}_output", "schema": task.output_schema, "strict": False},
            },
        }
        headers = {"Authorization": f"Bearer {key}"} if key else {}
        with self._client(task) as client:
            resp = client.post(url, json=body, headers=headers)
            if resp.status_code in (400, 422):
                events.append(Event(kind=EventKind.system, text="json_schema rejected; retrying with json_object",
                                    data={"status": resp.status_code, "body": resp.text[:2000]}))
                body["response_format"] = {"type": "json_object"}
                resp = client.post(url, json=body, headers=headers)
            resp.raise_for_status()
            data = resp.json()
        content = data["choices"][0]["message"].get("content") or ""
        u = data.get("usage") or {}
        cached = int((u.get("prompt_tokens_details") or {}).get("cached_tokens") or 0)
        cost = resp.headers.get("x-litellm-response-cost")
        try:
            usd = float(cost) if cost else 0.0
        except ValueError:
            usd = 0.0
        usage = Usage(
            tokens_in=max(int(u.get("prompt_tokens") or 0) - cached, 0),
            tokens_out=int(u.get("completion_tokens") or 0),
            tokens_cache_read=cached,
            usd=usd,
            turns=1,
        )
        return content, usage

    def _anthropic(self, task: StageTask, system: str, events: list[Event]) -> tuple[str, Usage]:
        body = {
            "model": os.environ.get("PRSEC_RAW_MODEL") or ANTHROPIC_DEFAULT_MODEL,
            "max_tokens": MAX_TOKENS,
            "system": system,
            "messages": [{"role": "user", "content": "Produce the JSON output document now. Reply with the JSON only."}],
        }
        headers = {"x-api-key": os.environ["ANTHROPIC_API_KEY"], "anthropic-version": ANTHROPIC_VERSION}
        with self._client(task) as client:
            resp = client.post(ANTHROPIC_URL, json=body, headers=headers)
            resp.raise_for_status()
            data = resp.json()
        if data.get("stop_reason") == "refusal":
            events.append(Event(kind=EventKind.error, text="model refused", data={"stop_details": data.get("stop_details")}))
        text = "".join(b.get("text", "") for b in data.get("content") or [] if isinstance(b, dict) and b.get("type") == "text")
        u = data.get("usage") or {}
        usage = Usage(
            tokens_in=int(u.get("input_tokens") or 0) + int(u.get("cache_creation_input_tokens") or 0),
            tokens_out=int(u.get("output_tokens") or 0),
            tokens_cache_read=int(u.get("cache_read_input_tokens") or 0),
            turns=1,
        )
        return text, usage

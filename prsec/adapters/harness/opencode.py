"""OpenCode adapter (`opencode run --format json`).

Verified against opencode 1.19.2 (run against a local OpenAI-compatible stub):
- the prompt is read from stdin when no positional message is given;
- `--format json` emits one JSON object per line: `{type, timestamp, sessionID, part|error}` with
  type in step_start | text | reasoning | tool_use (completed/errored tool parts) | step_finish
  (tokens + cost) | error;
- headless permission prompts are auto-*rejected* unless `--auto`; `permission` config (also via
  OPENCODE_CONFIG_CONTENT) sets `*`/`external_directory` to allow and denies webfetch/websearch/task
  (denied tools are removed from the tool list entirely);
- OPENCODE_CONFIG_CONTENT is merged as local config and supports `{env:VAR}` substitution, so the
  gateway key stays out of the config text; the custom provider uses `@ai-sdk/openai-compatible`
  (bundled, no npm fetch) at `<gateway>/v1`;
- skills: `<config dir>/{skill,skills}/**/SKILL.md` for every config dir, including
  OPENCODE_CONFIG_DIR, so skills are copied to `<out_dir>/.home/.opencode/skills/<name>`;
- `--session <id>` continues a session non-interactively (repair loop);
- the PR checkout is the cwd, so OPENCODE_DISABLE_PROJECT_CONFIG=1 makes opencode skip the project's
  opencode.json, `.opencode/` dirs (agents, plugins, skills) and AGENTS.md/CLAUDE.md/CONTEXT.md
  (checked in the 1.19.2 bundle); OPENCODE_DISABLE_CLAUDE_CODE=1 drops the Claude Code compat layer
  (CLAUDE.md, `.claude/skills`) and OPENCODE_DISABLE_EXTERNAL_SKILLS the ~/.claude, ~/.agents skills.

Gateway mode isolates HOME/XDG dirs under `<out_dir>/.home`; dev mode (gw None) keeps the user's
HOME and login and only adds the config dir (model from PRSEC_OPENCODE_MODEL, else the user's default).
"""
from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable, Iterator

from prsec.adapters.harness.base import Caps, GatewayConfig, Invocation, cli_version, copy_skills, register, resolve_cli
from prsec.adapters.harness.claude_code import MAX_RESULT_CHARS
from prsec.models import Event, EventKind, StageTask, Usage

CLI = "opencode"
PROVIDER = "prsec"
KEY_ENV = "PRSEC_OPENCODE_API_KEY"
DEV_MODEL_ENV = "PRSEC_OPENCODE_MODEL"
PERMISSION = {"*": "allow", "external_directory": "allow", "webfetch": "deny", "websearch": "deny", "task": "deny"}


def _ts(ms: Any) -> datetime | None:
    if isinstance(ms, (int, float)) and ms > 0:
        try:
            return datetime.fromtimestamp(ms / 1000, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    return None


def _int(d: dict[str, Any], key: str) -> int:
    v = d.get(key)
    return int(v) if isinstance(v, (int, float)) else 0


def _step_usage(part: dict[str, Any]) -> Usage:
    tokens = part.get("tokens") if isinstance(part.get("tokens"), dict) else {}
    cache = tokens.get("cache") if isinstance(tokens.get("cache"), dict) else {}
    cost = part.get("cost")
    return Usage(
        tokens_in=_int(tokens, "input") + _int(cache, "write"),  # opencode's input excludes cache reads
        tokens_out=_int(tokens, "output") + _int(tokens, "reasoning"),
        tokens_cache_read=_int(cache, "read"),
        usd=float(cost) if isinstance(cost, (int, float)) else 0.0,
        turns=1,
    )


def _text(value: Any) -> str:
    if value is None:
        return ""
    text = value if isinstance(value, str) else json.dumps(value)
    return text[:MAX_RESULT_CHARS]


@register
class OpenCodeAdapter:
    name = "opencode"
    caps = Caps(native_skills=True, resume=True, json_events=True, max_turns=False, mcp=True)

    def version(self) -> str | None:
        return cli_version(CLI)

    def home(self, task: StageTask) -> Path:
        return Path(task.out_dir) / ".home"

    def config_dir(self, task: StageTask) -> Path:
        return self.home(task) / ".opencode"

    def install_skills(self, task: StageTask) -> None:
        copy_skills(task, self.config_dir(task) / "skills")

    # ----------------------------------------------------------- invocation

    def config(self, gw: GatewayConfig | None) -> dict[str, Any]:
        cfg: dict[str, Any] = {
            "$schema": "https://opencode.ai/config.json",
            "autoupdate": False,
            "share": "disabled",
            "permission": dict(PERMISSION),
        }
        if gw is None:
            return cfg
        model_ref = f"{PROVIDER}/{gw.model}"
        cfg |= {
            "model": model_ref,
            "small_model": model_ref,
            "enabled_providers": [PROVIDER],
            "provider": {
                PROVIDER: {
                    "npm": "@ai-sdk/openai-compatible",
                    "name": "PRSec LLM gateway",
                    "options": {"baseURL": gw.base_url.rstrip("/") + "/v1", "apiKey": f"{{env:{KEY_ENV}}}"},
                    "models": {gw.model: {"name": gw.model}},
                }
            },
        }
        return cfg

    def _argv(self, task: StageTask, gw: GatewayConfig | None) -> list[str]:
        argv = [resolve_cli(CLI), "run", "--format", "json", "--auto", "--title", task.task_id]
        model = f"{PROVIDER}/{gw.model}" if gw else os.environ.get(DEV_MODEL_ENV)
        if model:
            argv += ["--model", model]
        return argv

    def _env(self, task: StageTask, gw: GatewayConfig | None) -> dict[str, str]:
        env = {
            "OPENCODE_CONFIG_CONTENT": json.dumps(self.config(gw)),
            "OPENCODE_CONFIG_DIR": str(self.config_dir(task)),
            "OPENCODE_DISABLE_AUTOUPDATE": "1",
            "OPENCODE_DISABLE_LSP_DOWNLOAD": "1",
            "OPENCODE_DISABLE_EXTERNAL_SKILLS": "1",  # no ~/.claude or ~/.agents skills leaking in
            "OPENCODE_DISABLE_PROJECT_CONFIG": "1",  # nothing in the PR checkout configures the harness
            "OPENCODE_DISABLE_CLAUDE_CODE": "1",
        }
        if gw is None:
            return env
        home = self.home(task)
        env |= {
            "HOME": str(home),
            "XDG_CONFIG_HOME": str(home / ".config"),
            "XDG_DATA_HOME": str(home / ".local" / "share"),
            "XDG_CACHE_HOME": str(home / ".cache"),
            "XDG_STATE_HOME": str(home / ".local" / "state"),
            "OPENCODE_DISABLE_MODELS_FETCH": "1",
            KEY_ENV: gw.api_key,
        }
        return env

    def build(self, task: StageTask, gw: GatewayConfig | None, prompt: str) -> Invocation:
        return Invocation(argv=self._argv(task, gw), env=self._env(task, gw), cwd=task.workdir, stdin=prompt)

    def build_resume(self, task: StageTask, gw: GatewayConfig | None, session_id: str, prompt: str) -> Invocation | None:
        argv = self._argv(task, gw) + ["--session", session_id]
        return Invocation(argv=argv, env=self._env(task, gw), cwd=task.workdir, stdin=prompt)

    # --------------------------------------------------------------- events

    def parse_events(self, lines: Iterable[str]) -> Iterator[Event]:
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                yield Event(kind=EventKind.system, text=line[:MAX_RESULT_CHARS], data={"unparsed": True})
                continue
            if not isinstance(obj, dict):
                yield Event(kind=EventKind.system, text=line[:MAX_RESULT_CHARS], data={"unparsed": True})
                continue
            try:
                yield from self._map(obj)
            except Exception as e:  # noqa: BLE001  (never raise on odd shapes)
                yield Event(kind=EventKind.system, text=line[:MAX_RESULT_CHARS], data={"unparsed": True, "error": str(e)})

    def _map(self, obj: dict[str, Any]) -> Iterator[Event]:
        typ = obj.get("type")
        sid = obj.get("sessionID")
        ts = _ts(obj.get("timestamp"))
        part = obj.get("part") if isinstance(obj.get("part"), dict) else {}
        meta: dict[str, Any] = {"session_id": sid}
        if part.get("messageID"):
            meta["message_id"] = part["messageID"]

        if typ == "step_start":
            yield Event(kind=EventKind.system, data=meta | {"type": "step_start"}, ts=ts)
        elif typ == "text":
            yield Event(kind=EventKind.message, text=part.get("text", ""), data=meta, ts=ts)
        elif typ == "reasoning":
            yield Event(kind=EventKind.message, text=part.get("text", ""), data=meta | {"reasoning": True}, ts=ts)
        elif typ == "tool_use":
            state = part.get("state") if isinstance(part.get("state"), dict) else {}
            call_id = part.get("callID")
            yield Event(kind=EventKind.tool_call, tool=part.get("tool"), data=meta | {"id": call_id, "input": state.get("input")}, ts=ts)
            is_error = state.get("status") == "error"
            yield Event(
                kind=EventKind.tool_result,
                tool=part.get("tool"),
                text=_text(state.get("error") if is_error else state.get("output")),
                data=meta | {"tool_use_id": call_id, "is_error": is_error},
                ts=ts,
            )
        elif typ == "step_finish":
            usage = _step_usage(part)
            yield Event(kind=EventKind.usage, data=meta | {"reason": part.get("reason"), "usage": usage.model_dump()}, ts=ts)
        elif typ == "error":
            err = obj.get("error") if isinstance(obj.get("error"), dict) else {"name": str(obj.get("error"))}
            data = err.get("data") if isinstance(err.get("data"), dict) else {}
            text = str(data.get("message") or err.get("name") or "error")
            yield Event(kind=EventKind.error, text=text, data=meta | {"name": err.get("name"), "error": err}, ts=ts)
        else:
            yield Event(kind=EventKind.system, data=meta | {"type": typ}, ts=ts)

    def session_id(self, events: list[Event]) -> str | None:
        for e in events:
            sid = e.data.get("session_id")
            if isinstance(sid, str) and sid:
                return sid
        return None

    def usage(self, events: list[Event]) -> Usage:
        total = Usage()
        for e in events:
            if e.kind == EventKind.usage and isinstance(e.data.get("usage"), dict):
                total = total + Usage.model_validate(e.data["usage"])
        return total

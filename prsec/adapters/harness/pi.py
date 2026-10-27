"""pi adapter (`pi -p --mode json`, npm @mariozechner/pi-coding-agent).

Verified against pi 0.73.1 (run against a local OpenAI-compatible stub):
- print mode merges piped stdin into the prompt, so the prompt goes on stdin;
- `--mode json` emits a `session` header (`id`) then agent events; we keep message_end,
  tool_execution_end, auto_retry_*, compaction_* and drop the per-token message_update deltas;
- custom providers live in `$PI_CODING_AGENT_DIR/models.json` (`api: openai-completions`,
  `baseUrl: <gateway>/v1`); `apiKey` names an env var, so the virtual key never touches disk;
- `--no-skills` disables discovery (the user's ~/.pi skills) while `--skill <dir>` still loads
  the task's skills natively;
- `--session <id>` + the same `--session-dir` resumes in print mode.
pi has no MCP and no permission prompts by design.
- pi loads AGENTS.md / CLAUDE.md context files from its cwd and every parent directory. The cwd is
  therefore the task's out dir, never the PR checkout, so a PR cannot inject instructions; the
  repository is read through absolute paths (the prompt names `task.workdir`).

Gateway mode points HOME and PI_CODING_AGENT_DIR at `<out_dir>/.home` (build() writes models.json
there). Dev mode keeps the user's agent dir/login (model from PRSEC_PI_MODEL, optionally scoped by
PRSEC_PI_PROVIDER; pi's --provider is only valid together with --model).
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

CLI = "pi"
PROVIDER = "prsec"
KEY_ENV = "PRSEC_PI_API_KEY"
DEV_MODEL_ENV = "PRSEC_PI_MODEL"
DEV_PROVIDER_ENV = "PRSEC_PI_PROVIDER"
TOOLS = "read,bash,edit,write,grep,find,ls"
SKIP = {"message_update", "message_start", "tool_execution_start", "tool_execution_update", "turn_start", "agent_start"}


def _ts(value: Any) -> datetime | None:
    if isinstance(value, (int, float)) and value > 0:
        try:
            return datetime.fromtimestamp(value / 1000, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def _usage_from(u: Any) -> Usage:
    u = u if isinstance(u, dict) else {}

    def n(key: str) -> int:
        v = u.get(key)
        return int(v) if isinstance(v, (int, float)) else 0

    cost = u.get("cost")
    usd = cost.get("total") if isinstance(cost, dict) else cost
    return Usage(
        tokens_in=n("input") + n("cacheWrite"),
        tokens_out=n("output"),
        tokens_cache_read=n("cacheRead"),
        usd=float(usd) if isinstance(usd, (int, float)) else 0.0,
        turns=1,
    )


def _content_text(content: Any) -> str:
    if isinstance(content, str):
        return content[:MAX_RESULT_CHARS]
    if not isinstance(content, list):
        return "" if content is None else json.dumps(content)[:MAX_RESULT_CHARS]
    parts = []
    for c in content:
        if isinstance(c, dict) and c.get("type") == "text":
            parts.append(str(c.get("text", "")))
        elif isinstance(c, dict):
            parts.append(f"[{c.get('type', 'block')}]")
    return "\n".join(parts)[:MAX_RESULT_CHARS]


@register
class PiAdapter:
    name = "pi"
    caps = Caps(native_skills=True, resume=True, json_events=True, max_turns=False, mcp=False)

    def version(self) -> str | None:
        return cli_version(CLI)

    def home(self, task: StageTask) -> Path:
        return Path(task.out_dir) / ".home"

    def agent_dir(self, task: StageTask) -> Path:
        return self.home(task) / ".pi" / "agent"

    def skills_root(self, task: StageTask) -> Path:
        return self.home(task) / ".pi" / "prsec-skills"

    def install_skills(self, task: StageTask) -> None:
        copy_skills(task, self.skills_root(task))

    # ----------------------------------------------------------- invocation

    def models_json(self, gw: GatewayConfig) -> dict[str, Any]:
        return {
            "providers": {
                PROVIDER: {
                    "baseUrl": gw.base_url.rstrip("/") + "/v1",
                    "api": "openai-completions",
                    "apiKey": KEY_ENV,  # resolved from the environment by pi
                    "compat": {"supportsDeveloperRole": False, "supportsReasoningEffort": False},
                    "models": [{"id": gw.model, "name": gw.model, "contextWindow": 200_000, "maxTokens": 32_000}],
                }
            }
        }

    def _argv(self, task: StageTask, gw: GatewayConfig | None) -> list[str]:
        argv = [
            resolve_cli(CLI),
            "-p",
            "--mode", "json",
            "--no-extensions",
            "--no-prompt-templates",
            "--no-themes",
            "--no-skills",
            "--tools", TOOLS,
            "--session-dir", str(self.home(task) / "pi-sessions"),
        ]
        root = self.skills_root(task)
        for name in task.skills:
            if (root / name / "SKILL.md").is_file():
                argv += ["--skill", str(root / name)]
        if gw is not None:
            argv += ["--provider", PROVIDER, "--model", gw.model]
        elif model := os.environ.get(DEV_MODEL_ENV):
            if provider := os.environ.get(DEV_PROVIDER_ENV):
                argv += ["--provider", provider]
            argv += ["--model", model]
        elif os.environ.get(DEV_PROVIDER_ENV):
            raise ValueError(f"{DEV_PROVIDER_ENV} is set without {DEV_MODEL_ENV}; pi's --provider requires --model")
        return argv

    def _env(self, task: StageTask, gw: GatewayConfig | None) -> dict[str, str]:
        env = {"PI_OFFLINE": "1", "PI_TELEMETRY": "0"}
        if gw is None:
            return env
        return env | {"HOME": str(self.home(task)), "PI_CODING_AGENT_DIR": str(self.agent_dir(task)), KEY_ENV: gw.api_key}

    def _prepare(self, task: StageTask, gw: GatewayConfig | None) -> None:
        if gw is None:
            return
        d = self.agent_dir(task)
        d.mkdir(parents=True, exist_ok=True)
        (d / "models.json").write_text(json.dumps(self.models_json(gw), indent=2))

    def build(self, task: StageTask, gw: GatewayConfig | None, prompt: str) -> Invocation:
        self._prepare(task, gw)
        return Invocation(argv=self._argv(task, gw), env=self._env(task, gw), cwd=task.out_dir, stdin=prompt)

    def build_resume(self, task: StageTask, gw: GatewayConfig | None, session_id: str, prompt: str) -> Invocation | None:
        self._prepare(task, gw)
        argv = self._argv(task, gw) + ["--session", session_id]
        return Invocation(argv=argv, env=self._env(task, gw), cwd=task.out_dir, stdin=prompt)

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
        if typ in SKIP:
            return
        if typ == "session":
            yield Event(
                kind=EventKind.system,
                data={"type": "session", "session_id": obj.get("id"), "cwd": obj.get("cwd"), "version": obj.get("version")},
                ts=_ts(obj.get("timestamp")),
            )
        elif typ == "message_end":
            yield from self._message(obj.get("message") if isinstance(obj.get("message"), dict) else {})
        elif typ == "tool_execution_end":
            result = obj.get("result") if isinstance(obj.get("result"), dict) else {"content": obj.get("result")}
            yield Event(
                kind=EventKind.tool_result,
                tool=obj.get("toolName"),
                text=_content_text(result.get("content")),
                data={"tool_use_id": obj.get("toolCallId"), "is_error": bool(obj.get("isError"))},
            )
        elif typ in ("auto_retry_start", "auto_retry_end", "compaction_start", "compaction_end"):
            data = {k: v for k, v in obj.items() if k != "result" and isinstance(v, (str, int, float, bool, type(None)))}
            yield Event(kind=EventKind.system, text=obj.get("errorMessage") or obj.get("finalError"), data=data)
        elif typ in ("turn_end", "agent_end", "queue_update"):
            yield Event(kind=EventKind.system, data={"type": typ})
        else:
            yield Event(kind=EventKind.system, data={"type": typ})

    def _message(self, msg: dict[str, Any]) -> Iterator[Event]:
        if msg.get("role") != "assistant":
            return  # user / toolResult messages are covered by the prompt and tool_execution_end
        ts = _ts(msg.get("timestamp"))
        mid = msg.get("responseId") or f"ts:{msg.get('timestamp')}"
        meta: dict[str, Any] = {"message_id": mid, "model": msg.get("model"), "stop_reason": msg.get("stopReason")}
        for block in msg.get("content") or []:
            if not isinstance(block, dict):
                continue
            bt = block.get("type")
            if bt == "text":
                yield Event(kind=EventKind.message, text=block.get("text", ""), data=meta, ts=ts)
            elif bt == "thinking":
                yield Event(kind=EventKind.message, text=block.get("thinking", ""), data=meta | {"reasoning": True}, ts=ts)
            elif bt == "toolCall":
                yield Event(kind=EventKind.tool_call, tool=block.get("name"), data=meta | {"id": block.get("id"), "input": block.get("arguments")}, ts=ts)
        yield Event(kind=EventKind.usage, data=meta | {"usage": _usage_from(msg.get("usage")).model_dump()}, ts=ts)
        if msg.get("stopReason") in ("error", "aborted") or msg.get("errorMessage"):
            yield Event(kind=EventKind.error, text=str(msg.get("errorMessage") or msg.get("stopReason")), data=meta, ts=ts)

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

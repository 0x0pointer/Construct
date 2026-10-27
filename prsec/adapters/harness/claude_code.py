"""Claude Code adapter (`claude -p --output-format stream-json --verbose`).

Verified against Claude Code 2.1.311:
- prompt is read from stdin when no positional prompt is given (no argv length limits);
- `--permission-mode dontAsk` + `--allowedTools` runs headless without prompting, and
  `--add-dir` makes in/out dirs writable working dirs;
- personal skills at `$HOME/.claude/skills/<name>/SKILL.md` and `<add-dir>/.claude/skills/...`
  are both discovered in -p mode (listed in the system/init event);
- `--resume <session_id>` continues the session in -p mode;
- `--setting-sources ""` loads no user/project/local settings (no repo or personal hooks,
  permissions, plugins or skills), `CLAUDE_CODE_DISABLE_CLAUDE_MDS=1` stops CLAUDE.md discovery,
  and skills shipped as an inline `--plugin-dir` plugin are still discovered (as `prsec:<name>`)
  while the login (keychain / OAuth) keeps working.

The PR checkout is the cwd, so nothing in it may configure the harness: the repo's CLAUDE.md,
`.claude/settings*.json` (hooks, permissions) and `.claude/skills` are never loaded, in either mode.
The workdir is mounted read-only, so skills are copied into a plugin under the writable
`<out_dir>/.home`. In gateway mode HOME/CLAUDE_CONFIG_DIR also point there (fresh config); in dev
mode (gw None) the user's HOME is kept for the login only — their settings, CLAUDE.md, hooks,
plugins and personal skills are not loaded.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Iterator

from prsec.adapters.harness.base import Caps, GatewayConfig, Invocation, cli_version, copy_skills, register, resolve_cli
from prsec.models import Event, EventKind, StageTask, Usage

CLI = "claude"
PLUGIN = "prsec"
TOOLS = "Bash,Read,Write,Edit,Glob,Grep,Skill"
MAX_RESULT_CHARS = 8000
# Set by a parent Claude Code session (dev laptops); a nested `claude -p` must not see them.
PARENT_SESSION_ENV = (
    "CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CLAUDE_CODE_SESSION_ID", "CLAUDE_CODE_CHILD_SESSION",
    "CLAUDE_CODE_SESSION_ATTENDED", "CLAUDE_CODE_MESSAGING_SOCKET", "CLAUDE_CODE_MESSAGING_TOKEN",
    "CLAUDE_CODE_EXECPATH", "CLAUDE_PID", "CLAUDE_EFFORT",
)


def _ts(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _result_text(content: Any) -> str:
    if isinstance(content, str):
        text = content
    elif isinstance(content, list):
        parts = []
        for c in content:
            if isinstance(c, dict) and c.get("type") == "text":
                parts.append(str(c.get("text", "")))
            elif isinstance(c, dict):
                parts.append(f"[{c.get('type', 'block')}]")
        text = "\n".join(parts)
    elif content is None:
        text = ""
    else:
        text = json.dumps(content)
    return text[:MAX_RESULT_CHARS]


def _usage_from(u: Any, *, usd: float = 0.0, turns: int = 0) -> Usage:
    u = u if isinstance(u, dict) else {}

    def n(key: str) -> int:
        v = u.get(key)
        return int(v) if isinstance(v, (int, float)) else 0

    return Usage(
        tokens_in=n("input_tokens") + n("cache_creation_input_tokens"),
        tokens_out=n("output_tokens"),
        tokens_cache_read=n("cache_read_input_tokens"),
        usd=float(usd or 0.0),
        turns=int(turns or 0),
    )


@register
class ClaudeCodeAdapter:
    name = "claude-code"
    caps = Caps(native_skills=True, resume=True, json_events=True, max_turns=True, mcp=True)

    def version(self) -> str | None:
        return cli_version(CLI)

    def home(self, task: StageTask) -> Path:
        return Path(task.out_dir) / ".home"

    def plugin_dir(self, task: StageTask) -> Path:
        return self.home(task) / PLUGIN

    def install_skills(self, task: StageTask) -> None:
        root = self.plugin_dir(task)
        copy_skills(task, root / "skills")
        manifest = root / ".claude-plugin" / "plugin.json"
        manifest.parent.mkdir(parents=True, exist_ok=True)
        manifest.write_text(json.dumps({"name": PLUGIN, "description": "PRSec methodology skills"}))

    # ----------------------------------------------------------- invocation

    def _argv(self, task: StageTask, gw: GatewayConfig | None) -> list[str]:
        argv = [
            resolve_cli(CLI),
            "-p",
            "--output-format", "stream-json",
            "--verbose",
            "--permission-mode", "dontAsk",
            "--tools", TOOLS,
            "--allowedTools", TOOLS,
            "--strict-mcp-config",
            "--setting-sources", "",
            "--plugin-dir", str(self.plugin_dir(task)),
            "--add-dir", task.in_dir, task.out_dir,
        ]
        if gw is not None:
            argv += ["--model", gw.model]
        if task.limits.max_turns:
            argv += ["--max-turns", str(task.limits.max_turns)]
        if task.limits.usd_budget and task.limits.usd_budget > 0:
            argv += ["--max-budget-usd", f"{task.limits.usd_budget:g}"]
        return argv

    def _env(self, task: StageTask, gw: GatewayConfig | None) -> dict[str, str]:
        env = {
            "DISABLE_TELEMETRY": "1",
            "DISABLE_ERROR_REPORTING": "1",
            "DISABLE_AUTOUPDATER": "1",
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            "CLAUDE_CODE_DISABLE_CLAUDE_MDS": "1",
            "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1",
        }
        if gw is None:
            return env
        home = self.home(task)
        env |= {
            "HOME": str(home),
            "CLAUDE_CONFIG_DIR": str(home / ".claude"),
            "ANTHROPIC_BASE_URL": gw.base_url.rstrip("/"),
            "ANTHROPIC_AUTH_TOKEN": gw.api_key,
            "ANTHROPIC_API_KEY": "",
            "ANTHROPIC_MODEL": gw.model,
            "ANTHROPIC_SMALL_FAST_MODEL": gw.model,
            "ANTHROPIC_DEFAULT_HAIKU_MODEL": gw.model,
            "ANTHROPIC_DEFAULT_SONNET_MODEL": gw.model,
            "ANTHROPIC_DEFAULT_OPUS_MODEL": gw.model,
            "CLAUDE_CODE_SUBAGENT_MODEL": gw.model,
        }
        return env

    def build(self, task: StageTask, gw: GatewayConfig | None, prompt: str) -> Invocation:
        return Invocation(argv=self._argv(task, gw), env=self._env(task, gw), cwd=task.workdir, stdin=prompt,
                          unset_env=list(PARENT_SESSION_ENV))

    def build_resume(self, task: StageTask, gw: GatewayConfig | None, session_id: str, prompt: str) -> Invocation | None:
        argv = self._argv(task, gw) + ["--resume", session_id]
        return Invocation(argv=argv, env=self._env(task, gw), cwd=task.workdir, stdin=prompt,
                          unset_env=list(PARENT_SESSION_ENV))

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
        sid = obj.get("session_id")
        ts = _ts(obj.get("timestamp"))
        if typ == "system":
            data: dict[str, Any] = {"subtype": obj.get("subtype"), "session_id": sid}
            if obj.get("subtype") == "init":
                data |= {k: obj.get(k) for k in ("model", "tools", "skills", "claude_code_version", "permissionMode", "cwd")}
            elif obj.get("subtype") == "api_retry":
                data |= {k: obj.get(k) for k in ("attempt", "max_retries", "error_status", "error")}
            yield Event(kind=EventKind.system, data=data, ts=ts)
        elif typ == "assistant":
            msg = obj.get("message") or {}
            meta = {"message_id": msg.get("id"), "session_id": sid}
            if obj.get("parent_tool_use_id"):
                meta["parent_tool_use_id"] = obj["parent_tool_use_id"]
            if isinstance(msg.get("usage"), dict):
                meta["usage"] = _usage_from(msg["usage"]).model_dump()
            for block in msg.get("content") or []:
                if not isinstance(block, dict):
                    continue
                bt = block.get("type")
                if bt == "text":
                    yield Event(kind=EventKind.message, text=block.get("text", ""), data=meta, ts=ts)
                elif bt == "tool_use":
                    yield Event(
                        kind=EventKind.tool_call,
                        tool=block.get("name"),
                        data=meta | {"id": block.get("id"), "input": block.get("input")},
                        ts=ts,
                    )
            if msg.get("type") == "error" or obj.get("error"):
                yield Event(kind=EventKind.error, text=str(obj.get("error") or msg.get("error")), data=meta, ts=ts)
        elif typ == "user":
            msg = obj.get("message") or {}
            content = msg.get("content")
            if not isinstance(content, list):
                return
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    yield Event(
                        kind=EventKind.tool_result,
                        text=_result_text(block.get("content")),
                        data={"tool_use_id": block.get("tool_use_id"), "is_error": bool(block.get("is_error")), "session_id": sid},
                        ts=ts,
                    )
        elif typ == "result":
            usage = _usage_from(obj.get("usage"), usd=obj.get("total_cost_usd") or 0.0, turns=obj.get("num_turns") or 0)
            data = {
                "session_id": sid,
                "subtype": obj.get("subtype"),
                "is_error": bool(obj.get("is_error")),
                "terminal_reason": obj.get("terminal_reason"),
                "duration_ms": obj.get("duration_ms"),
                "usage": usage.model_dump(),
            }
            yield Event(kind=EventKind.usage, text=obj.get("result") if isinstance(obj.get("result"), str) else None, data=data, ts=ts)
            if obj.get("is_error") or (obj.get("subtype") not in (None, "success")):
                reason = obj.get("result") or obj.get("subtype") or "error"
                yield Event(kind=EventKind.error, text=str(reason), data={"session_id": sid, "subtype": obj.get("subtype"), "terminal_reason": obj.get("terminal_reason")}, ts=ts)
        else:
            yield Event(kind=EventKind.system, data={"type": typ, "session_id": sid}, ts=ts)

    def session_id(self, events: list[Event]) -> str | None:
        for e in events:
            sid = e.data.get("session_id")
            if isinstance(sid, str) and sid:
                return sid
        return None

    def usage(self, events: list[Event]) -> Usage:
        total = Usage()
        results = [e for e in events if e.kind == EventKind.usage and isinstance(e.data.get("usage"), dict)]
        if results:
            for e in results:
                total = total + Usage.model_validate(e.data["usage"])
            return total
        # no result event (killed / timed out): fall back to per-message usage, once per message id
        seen: dict[str, Usage] = {}
        for e in events:
            mid, u = e.data.get("message_id"), e.data.get("usage")
            if isinstance(mid, str) and isinstance(u, dict):
                seen[mid] = Usage.model_validate(u)
        for u in seen.values():
            total = total + u
        return total.model_copy(update={"turns": len(seen)})

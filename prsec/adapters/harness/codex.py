"""OpenAI Codex CLI adapter (`codex exec --json`).

Built from the Codex docs and `codex-rs/exec` sources (exec_events.rs / cli.rs); not run
locally. Notes:
- the prompt is read from stdin via the `-` positional (no argv length limits);
- `-c key=value` overrides are TOML values and belong to the top-level `codex` command, so
  they go before `exec`; exec options go before the `resume` subcommand;
- gateway mode registers a custom provider `prsec` (`base_url=<gateway>/v1`,
  `wire_api="responses"`, the only wire API current Codex supports; LiteLLM serves
  `/v1/responses`) whose key is read from `env_key`;
- native skills: Codex discovers `$HOME/.agents/skills/<name>/SKILL.md` (user scope); we also
  mirror them to the legacy `$CODEX_HOME/skills`. HOME and CODEX_HOME point at a writable
  `<out_dir>/.home` in both modes; dev mode only links the user's `auth.json` in, so their login
  works but their config.toml, MCP servers, AGENTS.md and personal skills are not loaded.
- the PR checkout must not configure the harness: `-C` (the project root Codex scans for AGENTS.md,
  `.codex/` and repo-scoped `.agents/skills`) is the task's out dir, never the repo, and
  `project_doc_max_bytes=0` disables project docs on top. The repo is read via absolute paths.
- dev mode runs Codex's own `workspace-write` sandbox, whose writable roots are then the out dir
  (+ tmp) only: the repository stays read-only like it is under the Docker runner's ro mount.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Iterable, Iterator

from prsec.adapters.harness.base import Caps, GatewayConfig, Invocation, cli_version, copy_skills, register, resolve_cli
from prsec.adapters.harness.claude_code import MAX_RESULT_CHARS
from prsec.models import Event, EventKind, StageTask, Usage

CLI = "codex"
PROVIDER = "prsec"
KEY_ENV = "PRSEC_CODEX_API_KEY"
CODEX_DIR = ".codex"


def _toml(value: str | bool | int) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    return json.dumps(value)  # a JSON string is a valid TOML basic string


def _usage_from(u: Any) -> Usage:
    u = u if isinstance(u, dict) else {}

    def n(key: str) -> int:
        v = u.get(key)
        return int(v) if isinstance(v, (int, float)) else 0

    cached = n("cached_input_tokens")
    return Usage(
        tokens_in=max(n("input_tokens") - cached, 0),  # OpenAI input_tokens include cached ones
        tokens_out=n("output_tokens"),
        tokens_cache_read=cached,
        turns=1,
    )


@register
class CodexAdapter:
    name = "codex"
    caps = Caps(native_skills=True, resume=True, json_events=True, max_turns=False, mcp=True)

    def version(self) -> str | None:
        return cli_version(CLI)

    def home(self, task: StageTask) -> Path:
        return Path(task.out_dir) / ".home"

    def codex_home(self, task: StageTask) -> Path:
        return self.home(task) / CODEX_DIR

    @staticmethod
    def user_codex_home() -> Path:
        return Path(os.environ.get("CODEX_HOME") or Path.home() / CODEX_DIR)

    def install_skills(self, task: StageTask) -> None:
        home = self.home(task)
        copy_skills(task, home / ".agents" / "skills")
        copy_skills(task, home / CODEX_DIR / "skills")

    # ----------------------------------------------------------- invocation

    def _overrides(self, gw: GatewayConfig | None) -> list[str]:
        cfg: dict[str, str | bool | int] = {
            "approval_policy": "never",
            "check_for_update_on_startup": False,
            "analytics.enabled": False,
            "feedback.enabled": False,
            "project_doc_max_bytes": 0,
        }
        if gw is not None:
            cfg |= {
                "model": gw.model,
                "model_provider": PROVIDER,
                f"model_providers.{PROVIDER}.name": "PRSec LLM gateway",
                f"model_providers.{PROVIDER}.base_url": gw.base_url.rstrip("/") + "/v1",
                f"model_providers.{PROVIDER}.env_key": KEY_ENV,
                f"model_providers.{PROVIDER}.wire_api": "responses",
            }
        out: list[str] = []
        for k, v in cfg.items():
            out += ["-c", f"{k}={_toml(v)}"]
        return out

    def _exec_opts(self, task: StageTask, gw: GatewayConfig | None) -> list[str]:
        # gateway mode runs in the isolated workbench container, where Codex's own
        # landlock/seatbelt sandbox is redundant (and often unavailable); dev mode stays
        # inside workspace-write, rooted at the out dir so the repository is not writable.
        sandbox = "danger-full-access" if gw is not None else "workspace-write"
        opts = [
            "--json",
            "--color", "never",
            "--skip-git-repo-check",
            "--sandbox", sandbox,
            "-C", task.out_dir,
            "--output-last-message", str(Path(task.out_dir) / ".codex-last-message.txt"),
        ]
        if gw is not None:
            opts += ["--model", gw.model]
        return opts

    def _env(self, task: StageTask, gw: GatewayConfig | None) -> dict[str, str]:
        env = {"HOME": str(self.home(task)), "CODEX_HOME": str(self.codex_home(task))}
        if gw is not None:
            env[KEY_ENV] = gw.api_key
        return env

    def _prepare(self, task: StageTask, gw: GatewayConfig | None) -> None:
        home = self.codex_home(task)
        home.mkdir(parents=True, exist_ok=True)
        if gw is not None:
            return
        # dev mode: the user's login only (a link, so a token refresh is written back to it)
        auth, link = self.user_codex_home() / "auth.json", home / "auth.json"
        if auth.is_file() and not link.exists():
            link.symlink_to(auth)

    def build(self, task: StageTask, gw: GatewayConfig | None, prompt: str) -> Invocation:
        self._prepare(task, gw)
        argv = [resolve_cli(CLI), *self._overrides(gw), "exec", *self._exec_opts(task, gw), "-"]
        return Invocation(argv=argv, env=self._env(task, gw), cwd=task.out_dir, stdin=prompt)

    def build_resume(self, task: StageTask, gw: GatewayConfig | None, session_id: str, prompt: str) -> Invocation | None:
        self._prepare(task, gw)
        argv = [resolve_cli(CLI), *self._overrides(gw), "exec", *self._exec_opts(task, gw), "resume", session_id, "-"]
        return Invocation(argv=argv, env=self._env(task, gw), cwd=task.out_dir, stdin=prompt)

    # --------------------------------------------------------------- events

    def parse_events(self, lines: Iterable[str]) -> Iterator[Event]:
        started: set[str] = set()
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                obj = None
            if not isinstance(obj, dict):
                yield Event(kind=EventKind.system, text=line[:MAX_RESULT_CHARS], data={"unparsed": True})
                continue
            try:
                yield from self._map(obj, started)
            except Exception as e:  # noqa: BLE001  (never raise on odd shapes)
                yield Event(kind=EventKind.system, text=line[:MAX_RESULT_CHARS], data={"unparsed": True, "error": str(e)})

    def _map(self, obj: dict[str, Any], started: set[str]) -> Iterator[Event]:
        typ = obj.get("type")
        if typ == "thread.started":
            yield Event(kind=EventKind.system, data={"subtype": typ, "session_id": obj.get("thread_id")})
        elif typ == "turn.started":
            yield Event(kind=EventKind.system, data={"subtype": typ})
        elif typ == "turn.completed":
            raw = obj.get("usage") or {}
            yield Event(kind=EventKind.usage, data={"usage": _usage_from(raw).model_dump(), "raw": raw})
        elif typ == "turn.failed":
            err = obj.get("error") or {}
            yield Event(kind=EventKind.error, text=str(err.get("message") if isinstance(err, dict) else err), data={"subtype": typ})
        elif typ == "error":
            yield Event(kind=EventKind.error, text=str(obj.get("message", "")), data={"subtype": typ})
        elif typ in ("item.started", "item.completed"):
            item = obj.get("item")
            if isinstance(item, dict):
                yield from self._item(item, completed=typ == "item.completed", started=started)
        elif typ == "item.updated":
            return
        else:
            yield Event(kind=EventKind.system, data={"type": typ})

    def _item(self, item: dict[str, Any], *, completed: bool, started: set[str]) -> Iterator[Event]:
        it, iid = item.get("type"), str(item.get("id", ""))
        tool, call_data = self._tool_of(item)
        if tool is not None:
            if not completed or iid not in started:
                started.add(iid)
                yield Event(kind=EventKind.tool_call, tool=tool, data={"id": iid, "input": call_data})
            if completed:
                yield Event(kind=EventKind.tool_result, tool=tool, text=self._result_text(item), data=self._result_data(item))
            return
        if not completed:
            return
        if it == "agent_message":
            yield Event(kind=EventKind.message, text=item.get("text", ""), data={"id": iid})
        elif it == "error":
            yield Event(kind=EventKind.error, text=str(item.get("message", "")), data={"id": iid})
        elif it == "todo_list":
            yield Event(kind=EventKind.system, data={"subtype": it, "id": iid, "items": item.get("items")})
        # reasoning items are intentionally dropped from the normalised transcript

    @staticmethod
    def _tool_of(item: dict[str, Any]) -> tuple[str | None, Any]:
        it = item.get("type")
        if it == "command_execution":
            return "shell", {"command": item.get("command")}
        if it == "file_change":
            return "apply_patch", {"changes": item.get("changes")}
        if it == "mcp_tool_call":
            return f"mcp:{item.get('server')}/{item.get('tool')}", item.get("arguments")
        if it == "web_search":
            return "web_search", {"query": item.get("query")}
        if it == "collab_tool_call":
            return "collab", {k: v for k, v in item.items() if k not in ("id", "type")}
        return None, None

    @staticmethod
    def _result_text(item: dict[str, Any]) -> str:
        it = item.get("type")
        if it == "command_execution":
            text = str(item.get("aggregated_output") or "")
        elif it == "mcp_tool_call":
            res, err = item.get("result"), item.get("error")
            if err:
                text = json.dumps(err)
            else:
                text = json.dumps(res.get("content", []) if isinstance(res, dict) else res)
        elif it == "file_change":
            text = "\n".join(f"{c.get('kind')} {c.get('path')}" for c in item.get("changes") or [] if isinstance(c, dict))
        else:
            text = json.dumps({k: v for k, v in item.items() if k not in ("id", "type")})
        return text[:MAX_RESULT_CHARS]

    @staticmethod
    def _result_data(item: dict[str, Any]) -> dict[str, Any]:
        status = item.get("status")
        exit_code = item.get("exit_code")
        is_error = status in ("failed", "declined") or bool(item.get("error")) or (isinstance(exit_code, int) and exit_code != 0)
        data: dict[str, Any] = {"tool_use_id": str(item.get("id", "")), "status": status, "is_error": is_error}
        if exit_code is not None:
            data["exit_code"] = exit_code
        return data

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

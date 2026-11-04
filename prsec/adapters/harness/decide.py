"""Decision harnesses: one calibrated yes/no from a decision model, in process, no tools.

Rules stage only (skip/scan). The question is whether the PR could have any security relevance; the
calibrated P(yes) becomes `RulesOutput`: `scan` unless P(yes) is below PRSEC_DECIDE_SCAN_THRESHOLD
(default 0.10), because a wrong skip (a missed vulnerability) costs far more than a wrong scan. The
evidence is the PR metadata, changed files and diff from the task's context files, truncated to
PRSEC_DECIDE_MAX_STATE_CHARS (default 60000). Skills and the stage prompt are not used.

Through the gateway a decision model is an ordinary model alias: the adapter sends the provider's
request body as the one user message of a chat completion to the task's alias, and the gateway's
`prsec-decide` relay (deploy/compose/litellm/prsec_hooks.py) posts it to the endpoint fixed in the
gateway config and returns the provider's JSON as the message content. So a minted key reaches a
decision model only when the alias is in its `models` allowlist, and the provider key stays in the
gateway. (A key-authenticated LiteLLM pass-through route would need the Enterprise-only
`allowed_passthrough_routes` on every virtual key.)

- `jev-decide`: AutoTrust JEV-27B System 1 (`serve_decide.py` POST /v1/decide, kind `noul`), self-hosted.
  Dev mode (no gateway) PRSEC_JEV_DECIDE_URL.
- `openai-decide`: the OpenAI Decisions API (POST /v1/decisions, a `predicate` question); the task's
  model alias names the Decisions model (e.g. gpt-6-luna; the relay sends the alias's own model). Dev
  mode PRSEC_OPENAI_DECIDE_URL (default the public endpoint) with OPENAI_API_KEY.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Iterable, Iterator

import httpx

from prsec.adapters.harness.base import Caps, GatewayConfig, Invocation, register
from prsec.adapters.harness.raw import truncate
from prsec.models import Event, EventKind, StageTask, Usage

DEFAULT_THRESHOLD = 0.10
DEFAULT_MAX_STATE_CHARS = 60_000
# Phrased as a statement for predicate APIs; JEV's noul kind takes it as a question.
CONDITION = (
    "This pull request could have security relevance: it changes code, configuration, dependencies or "
    "infrastructure that handles user input, authentication, authorization, sessions, data access, secrets, "
    "file or network access, so a security review should look at it."
)
QUESTION = (
    "Could this pull request have any security relevance: does it change code, configuration, dependencies or "
    "infrastructure that handles user input, authentication, authorization, sessions, data access, secrets, "
    "file or network access, so that a security review should look at it?"
)
MAX_BODY_CHARS = 4_000
MAX_FILES_LISTED = 200
OPENAI_DECISIONS_URL = "https://api.openai.com/v1/decisions"
RELAY_PATH = "/v1/chat/completions"  # the gateway's prsec-decide relay sits behind the ordinary chat route
PREDICATE_NAME = "security_relevant"


def _read(task: StageTask, name: str) -> str:
    p = Path(task.in_dir) / name
    try:
        return p.read_text(errors="replace") if p.is_file() else ""
    except OSError:
        return ""


def build_state(task: StageTask, max_chars: int) -> str:
    """The PR as one text block: title/description, changed files, then the diff (truncated last)."""
    try:
        pr = json.loads(_read(task, "pr.json") or "{}")
    except ValueError:
        pr = {}
    files = [f for f in _read(task, "changed_files.txt").splitlines() if f.strip()]
    head = [
        f"Repository: {pr.get('repo', '?')}",
        f"Pull request: {pr.get('title', '')}".rstrip(),
        "Description:",
        truncate(str(pr.get("body") or "(none)"), MAX_BODY_CHARS).rstrip(),
        f"Changed files ({len(files)}):",
        *files[:MAX_FILES_LISTED],
        *([f"... and {len(files) - MAX_FILES_LISTED} more"] if len(files) > MAX_FILES_LISTED else []),
        "Diff:",
    ]
    text = "\n".join(head) + "\n"
    return text + truncate(_read(task, "diff.patch") or "(empty)", max(max_chars - len(text), 1_000))


class _Decide:
    """Shared run loop; a provider supplies its dev endpoint, the request body and P(yes) parsing."""

    name = ""
    label = ""  # shown in the decision's reason
    caps = Caps(native_skills=False, resume=False, json_events=False, max_turns=False, mcp=False, subprocess=False,
                stages=frozenset({"rules"}))

    def __init__(self, transport: httpx.BaseTransport | None = None) -> None:
        self.transport = transport
        raw = os.environ.get("PRSEC_DECIDE_SCAN_THRESHOLD")
        self.threshold = float(raw) if raw else DEFAULT_THRESHOLD
        env = os.environ.get("PRSEC_DECIDE_MAX_STATE_CHARS", "")
        self.max_state_chars = int(env) if env.isdigit() else DEFAULT_MAX_STATE_CHARS

    # ---- provider hooks
    def dev_endpoint(self) -> tuple[str, dict[str, str]]:  # pragma: no cover - overridden
        raise NotImplementedError

    def body(self, task: StageTask, state: str) -> dict[str, Any]:  # pragma: no cover - overridden
        raise NotImplementedError

    def p_yes(self, resp: dict[str, Any]) -> float:  # pragma: no cover - overridden
        raise NotImplementedError

    def usage_of(self, resp: dict[str, Any]) -> Usage:
        u = resp.get("usage") or {}
        tokens_in = int(u.get("prompt_tokens") or u.get("input_tokens") or 0)
        return Usage(tokens_in=tokens_in, tokens_out=int(u.get("completion_tokens") or u.get("output_tokens") or 0), turns=1)

    # ---- HarnessAdapter protocol
    def version(self) -> str | None:
        return "1"

    def install_skills(self, task: StageTask) -> None:
        """A decision model answers a fixed question; skills are not used."""

    def build(self, task: StageTask, gw: GatewayConfig | None, prompt: str) -> Invocation:
        raise NotImplementedError(f"{self.name} runs in-process; use run_inprocess()")

    def build_resume(self, task: StageTask, gw: GatewayConfig | None, session_id: str, prompt: str) -> Invocation | None:  # NOSONAR(S1172) Protocol signature
        return None

    def parse_events(self, lines: Iterable[str]) -> Iterator[Event]:
        for line in lines:
            if line.strip():
                yield Event(kind=EventKind.system, text=line[:8000], data={"unparsed": True})

    def session_id(self, events: list[Event]) -> str | None:  # NOSONAR(S1172) Protocol signature
        return None

    def usage(self, events: list[Event]) -> Usage:
        total = Usage()
        for e in events:
            if e.kind == EventKind.usage and isinstance(e.data.get("usage"), dict):
                total = total + Usage.model_validate(e.data["usage"])
        return total

    def _call(self, client: httpx.Client, task: StageTask, body: dict[str, Any], gw: GatewayConfig | None) -> dict[str, Any]:
        """The provider's response to `body`: straight from the provider in dev mode, else via the gateway relay."""
        if gw is None:
            url, headers = self.dev_endpoint()
            resp = client.post(url, json=body, headers=headers)
            resp.raise_for_status()
            return resp.json()
        headers = {"Authorization": f"Bearer {gw.api_key}"} if gw.api_key else {}
        chat = {"model": task.model_alias, "messages": [{"role": "user", "content": json.dumps(body)}]}
        resp = client.post(gw.base_url.rstrip("/") + RELAY_PATH, json=chat, headers=headers)
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]
        data = json.loads(content) if isinstance(content, str) else None
        if not isinstance(data, dict):
            raise ValueError(f"the gateway relay returned no JSON object: {str(content)[:300]}")
        return data

    def run_inprocess(self, task: StageTask, gw: GatewayConfig | None, prompt: str) -> tuple[dict | None, list[Event], Usage]:  # NOSONAR(S1172) prompt: a fixed question is asked
        state = build_state(task, self.max_state_chars)
        events: list[Event] = [Event(kind=EventKind.system, text=f"{self.name} request",
                                     data={"state_chars": len(state), "threshold": self.threshold})]
        try:
            timeout = httpx.Timeout(float(task.limits.wall_clock_s), connect=15.0)
            with httpx.Client(timeout=timeout, transport=self.transport) as client:
                data = self._call(client, task, self.body(task, state), gw)
            p = self.p_yes(data)
        except (httpx.HTTPError, RuntimeError, ValueError, KeyError, TypeError) as e:
            events.append(Event(kind=EventKind.error, text=f"{type(e).__name__}: {e}"[:2000]))
            return None, events, Usage()
        usage = self.usage_of(data)
        decision = "skip" if p < self.threshold else "scan"
        doc = {"decision": decision,
               "reason": f"{self.label}: P(security-relevant)={p:.3f}; scans at >= {self.threshold:.2f}"}
        events.append(Event(kind=EventKind.message, text=json.dumps(doc), data={"p_yes": p, "model": data.get("model")}))
        events.append(Event(kind=EventKind.usage, data={"usage": usage.model_dump()}))
        out = Path(task.output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(doc, indent=2))
        return doc, events, usage


@register
class JevDecideAdapter(_Decide):
    name = "jev-decide"
    label = "JEV System 1"

    def dev_endpoint(self) -> tuple[str, dict[str, str]]:
        url = os.environ.get("PRSEC_JEV_DECIDE_URL")
        if not url:
            raise RuntimeError("jev-decide dev mode needs PRSEC_JEV_DECIDE_URL")
        return url, {}

    def body(self, task: StageTask, state: str) -> dict[str, Any]:
        return {"kind": "noul", "state": state, "question": QUESTION}

    def p_yes(self, resp: dict[str, Any]) -> float:
        """serve_decide returns probabilities [P(false), P(true)]; when it names the options, the yes/true one."""
        probs = resp.get("probabilities")
        if not isinstance(probs, list) or len(probs) != 2 or not all(isinstance(p, (int, float)) for p in probs):
            raise ValueError(f"unexpected decide response: {json.dumps(resp)[:300]}")
        options = [str(o).strip().lower() for o in resp.get("options") or []]
        idx = next((i for i, o in enumerate(options) if o in ("yes", "true")), 1) if len(options) == 2 else 1
        return float(probs[idx])


@register
class OpenAIDecideAdapter(_Decide):
    name = "openai-decide"
    label = "OpenAI Decisions"

    def dev_endpoint(self) -> tuple[str, dict[str, str]]:
        key = os.environ.get("OPENAI_API_KEY")
        if not key:
            raise RuntimeError("openai-decide dev mode needs OPENAI_API_KEY")
        return os.environ.get("PRSEC_OPENAI_DECIDE_URL") or OPENAI_DECISIONS_URL, {"Authorization": f"Bearer {key}"}

    def body(self, task: StageTask, state: str) -> dict[str, Any]:
        return {"model": task.model_alias, "input": state,
                "questions": [{"type": "predicate", "name": PREDICATE_NAME, "instructions": CONDITION}]}

    def p_yes(self, resp: dict[str, Any]) -> float:
        """The predicate's `probability`; a per-question refusal is no decision (the arm records it)."""
        answers = resp.get("answers")
        if not isinstance(answers, list):
            raise ValueError(f"unexpected decisions response: {json.dumps(resp)[:300]}")
        answer = next((a for a in answers if isinstance(a, dict) and a.get("name") == PREDICATE_NAME), None)
        if answer is None:
            raise ValueError("decisions response has no answer for the question")
        if answer.get("type") == "refusal":
            raise ValueError(f"the Decisions API refused the question: {json.dumps(answer)[:300]}")
        p = answer.get("probability")
        if not isinstance(p, (int, float)) or not 0.0 <= p <= 1.0:
            raise ValueError(f"unexpected predicate answer: {json.dumps(answer)[:300]}")
        return float(p)

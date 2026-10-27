"""Harness adapter contract.

An adapter translates a harness-neutral StageTask into one CLI invocation of a
specific agent harness and maps its native event stream back to `Event`s.
It must NOT require any harness-only feature from prompts or skills; the
universal contract is: read files, run shell, write `task.output_path`.

The sandbox entrypoint (prsec.sandbox.entrypoint) owns the run loop:
install_skills -> command -> spawn -> parse_events -> validate output -> repair
(resume_command if caps.resume else a fresh command with repair prompt).

`gw` is None in dev mode: the adapter must then leave gateway/provider env alone and use
the harness's own local login. Adapters with `caps.subprocess=False` (raw) implement
`run_inprocess(task, gw, prompt)` instead of build(); it writes task.output_path itself and
returns either an iterable of Events or a `(output, events, usage)` tuple.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator, Protocol, runtime_checkable

from prsec.models import Event, StageTask, Usage

# possessive quantifiers + a digit-run lookbehind keep the search linear (same leftmost match)
_VERSION_RE = re.compile(r"(?<!\d)\d++\.\d++\.\d++[\w.+-]*+")


@dataclass(frozen=True)
class Caps:
    native_skills: bool  # harness discovers SKILL.md dirs itself
    resume: bool  # can continue a previous session (used by the repair loop)
    json_events: bool  # emits machine-readable event stream on stdout
    max_turns: bool  # honours a turn limit flag
    mcp: bool  # supports MCP (never required by prsec)
    subprocess: bool = True  # False for in-process adapters (raw)


@dataclass(frozen=True)
class GatewayConfig:
    """LLM gateway (LiteLLM) the harness must talk to. Real provider keys never enter the sandbox."""

    base_url: str  # e.g. http://llm-gateway:4000
    api_key: str  # per-scan virtual key
    model: str  # alias resolved by the gateway: agent-large | agent-small | judge
    per_task_key: bool = False  # key is minted for this task only, so its gateway spend is this task's cost


@dataclass
class Invocation:
    argv: list[str]
    env: dict[str, str]  # overlay merged on top of the entrypoint's os.environ, not the full env
    cwd: str
    stdin: str | None = None
    unset_env: list[str] = field(default_factory=list)  # inherited vars to remove before spawning


@runtime_checkable
class HarnessAdapter(Protocol):
    name: str
    caps: Caps

    def version(self) -> str | None:
        """Harness CLI version string, or None if not installed."""

    def install_skills(self, task: StageTask) -> None:
        """Make task.skills available: native location if caps.native_skills, else write an index
        (AGENTS.md / prompt preamble) pointing at `{skills_dir}/<name>/SKILL.md`."""

    def build(self, task: StageTask, gw: GatewayConfig | None, prompt: str) -> Invocation:
        """Build the CLI invocation for a fresh session with the given prompt."""

    def build_resume(self, task: StageTask, gw: GatewayConfig | None, session_id: str, prompt: str) -> Invocation | None:
        """Continue an existing session (repair loop). None if unsupported."""

    def parse_events(self, lines: Iterable[str]) -> Iterator[Event]:
        """Map native stdout lines to normalised Events. Must never raise on unknown lines."""

    def session_id(self, events: list[Event]) -> str | None:
        """Extract the session id from parsed events (for resume), if any."""

    def usage(self, events: list[Event]) -> Usage:
        """Aggregate usage reported by the harness (best effort; the gateway is authoritative)."""


# ----------------------------------------------------------------- helpers


def resolve_cli(cli: str) -> str:
    """`$PRSEC_HARNESS_HOME/bin/<cli>` (harness volume) first, then PATH, else the bare name."""
    home = os.environ.get("PRSEC_HARNESS_HOME")
    if home:
        cand = Path(home) / "bin" / cli
        if cand.is_file() and os.access(cand, os.X_OK):
            return str(cand)
    return shutil.which(cli) or cli


def cli_version(cli: str) -> str | None:
    try:
        cp = subprocess.run([resolve_cli(cli), "--version"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    if cp.returncode != 0:
        return None
    out = cp.stdout.strip() or cp.stderr.strip()
    m = _VERSION_RE.search(out)
    return m.group(0) if m else (out or None)


def copy_skills(task: StageTask, dest: Path) -> None:
    """Copy task.skills (dirs with a SKILL.md under task.skills_dir) into dest/<name>."""
    dest.mkdir(parents=True, exist_ok=True)
    for name in task.skills:
        src = Path(task.skills_dir) / name
        if not (src / "SKILL.md").is_file():
            continue
        target = dest / name
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(src, target, symlinks=False)


def skills_index_md(task: StageTask) -> str:
    """Fallback skill discovery for harnesses without native SKILL.md support."""
    lines = [
        "# Available skills",
        "",
        "The following methodology skills are available. When one is relevant, read its",
        "SKILL.md in full with a shell command (e.g. `cat <path>`) BEFORE acting, and follow it.",
        "",
    ]
    for name in task.skills:
        skill_md = Path(task.skills_dir) / name / "SKILL.md"
        desc = _frontmatter_description(skill_md)
        lines.append(f"- **{name}** — {desc} — `{skill_md}`")
    return "\n".join(lines) + "\n"


def _frontmatter_description(path: Path) -> str:
    try:
        text = path.read_text()
    except OSError:
        return "(missing)"
    if not text.startswith("---"):
        return ""
    for line in text.split("---", 2)[1].splitlines():
        if line.strip().startswith("description:"):
            return line.split(":", 1)[1].strip().strip("\"'")
    return ""


_REGISTRY: dict[str, type] = {}


def register(cls: type) -> type:
    _REGISTRY[cls.name] = cls
    return cls


def get_adapter(name: str) -> HarnessAdapter:
    import prsec.adapters.harness  # noqa: F401  (populates registry)

    try:
        return _REGISTRY[name]()
    except KeyError:
        raise ValueError(f"unknown harness {name!r}; known: {sorted(_REGISTRY)}") from None


def adapter_names() -> list[str]:
    import prsec.adapters.harness  # noqa: F401

    return sorted(_REGISTRY)

"""Fake harness adapters for tests. Importing this module registers them.

Also imported by the stage entrypoint subprocess via PRSEC_ADAPTER_MODULES=fakeharness.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Iterable, Iterator

from prsec.adapters.harness.base import Caps, GatewayConfig, Invocation, register
from prsec.models import Event, EventKind, Limits, Stage, StageTask, Usage
from prsec.stages.outputs import schema_for

CLI = Path(__file__).with_name("fake_harness_cli.py")
VALID = {"decision": "light", "rationale": "touches the login handler", "risk_tags": ["authz"]}
INVALID = {"decision": "maybe", "rationale": 42}
_KINDS = {k.value for k in EventKind}


class _FakeBase:
    name = "fake-base"
    caps = Caps(native_skills=False, resume=True, json_events=True, max_turns=False, mcp=False)

    def version(self) -> str | None:
        return "fake 1.0"

    def install_skills(self, task: StageTask) -> None:
        from prsec.adapters.harness.base import skills_index_md

        (Path(task.out_dir) / "skills_index.md").write_text(skills_index_md(task))

    def build(self, task: StageTask, gw: GatewayConfig | None, prompt: str) -> Invocation:
        return Invocation(
            argv=[sys.executable, str(CLI), task.output_path, task.out_dir],
            env={"FAKE_GW_URL": gw.base_url if gw else "", "FAKE_GW_MODEL": gw.model if gw else ""},
            cwd=task.workdir,
            stdin=prompt,
        )

    def build_resume(self, task: StageTask, gw: GatewayConfig | None, session_id: str, prompt: str) -> Invocation | None:
        inv = self.build(task, gw, prompt)
        inv.argv += ["--resume", session_id, prompt]
        inv.stdin = None
        return inv

    def parse_events(self, lines: Iterable[str]) -> Iterator[Event]:
        for line in lines:
            try:
                obj = json.loads(line)
            except ValueError:
                obj = None
            if not isinstance(obj, dict) or not isinstance(obj.get("type"), str):
                if line.strip():
                    yield Event(kind=EventKind.system, text=line[:500], data={"unparsed": True})
                continue
            kind = obj["type"] if obj["type"] in _KINDS else "system"
            yield Event(kind=kind, text=obj.get("text"), tool=obj.get("tool"), data=obj)

    def session_id(self, events: list[Event]) -> str | None:
        ids = [e.data["id"] for e in events if e.data.get("type") == "session"]
        return ids[0] if ids else None

    def usage(self, events: list[Event]) -> Usage:
        u = Usage()
        for e in events:
            if e.kind == EventKind.usage:
                u = u + Usage(tokens_in=e.data.get("in", 0), tokens_out=e.data.get("out", 0), usd=e.data.get("usd", 0.0), turns=1)
        return u


@register
class FakeAdapter(_FakeBase):
    name = "fake"


@register
class FakeNoResumeAdapter(_FakeBase):
    name = "fake-noresume"
    caps = Caps(native_skills=False, resume=False, json_events=True, max_turns=False, mcp=False)


@register
class FakeResumeRefusedAdapter(_FakeBase):
    """Claims resume but build_resume returns None -> entrypoint must fall back to a fresh call."""

    name = "fake-resume-refused"

    def build_resume(self, task, gw, session_id, prompt):  # type: ignore[override]
        return None


@register
class FakeMissingBinaryAdapter(_FakeBase):
    name = "fake-missing-binary"

    def build(self, task, gw, prompt):  # type: ignore[override]
        return Invocation(argv=["/nonexistent/harness-cli"], env={}, cwd=task.workdir, stdin=prompt)


@register
class FakeInProcessAdapter(_FakeBase):
    name = "fake-inproc"
    caps = Caps(native_skills=False, resume=False, json_events=True, max_turns=False, mcp=False, subprocess=False)

    def __init__(self) -> None:
        self.calls: list[str] = []

    def run_inprocess(self, task: StageTask, gw: GatewayConfig | None, prompt: str) -> list[Event]:
        self.calls.append(prompt)
        mode = os.environ.get("FAKE_MODE", "valid")
        out = Path(task.output_path)
        if mode == "sleep":
            time.sleep(30)
        if mode == "raise":
            raise RuntimeError("provider 500")
        doc = INVALID if mode == "never_valid" or (mode == "invalid_then_valid" and len(self.calls) == 1) else VALID
        out.write_text(json.dumps(doc))
        return [
            Event(kind=EventKind.message, text="ok"),
            Event(kind=EventKind.usage, data={"usd": 0.02, "in": 50, "out": 10}),
        ]


def make_task(root: Path, harness: str = "fake", *, container_paths: bool = False, **limits) -> StageTask:
    """A triage StageTask with a tiny repo + one skill under `root`."""
    src, inp, out, skills = root / "src", root / "in", root / "out", root / "skills"
    for d in (src, inp, out, skills / "demo"):
        d.mkdir(parents=True, exist_ok=True)
    (src / "app.py").write_text("def login(user, pw):\n    return db.query(f\"SELECT * FROM u WHERE n='{user}'\")\n")
    (skills / "demo" / "SKILL.md").write_text("---\nname: demo\ndescription: demo skill\n---\nDo the thing.\n")
    (inp / "diff.patch").write_text("+def login(user, pw): ...\n")
    if container_paths:
        paths = dict(workdir="/work/src", in_dir="/work/in", out_dir="/work/out", skills_dir="/skills",
                     output_path="/work/out/triage.json")
    else:
        paths = dict(workdir=str(src), in_dir=str(inp), out_dir=str(out), skills_dir=str(skills),
                     output_path=str(out / "triage.json"))
    return StageTask(
        scan_id=7, stage=Stage.triage, task_id="7-triage", harness=harness, model_alias="agent-small",
        prompt_md="# Triage\nDecide whether this PR is security relevant.", skills=["demo"],
        output_schema=schema_for(Stage.triage), context_files=["diff.patch"],
        limits=Limits(**{"wall_clock_s": 20, "usd_budget": 1.0, "repair_attempts": 2, **limits}),
        **paths,
    )

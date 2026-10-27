"""Cross-module glue added at integration: prompt path remapping, env unsetting, raw tuple return,
bug_class canonicalisation."""
from __future__ import annotations

from pathlib import Path

import pytest

from prsec.adapters.harness.base import Invocation
from prsec.adapters.harness.claude_code import PARENT_SESSION_ENV, ClaudeCodeAdapter
from prsec.adapters.protocols import WorkbenchSpec
from prsec.adapters.runner.local import _rewrite_prompt, host_task
from prsec.models import Stage, StageTask
from prsec.orchestrator.pipeline import _canonical_bug_classes
from prsec.sandbox.entrypoint import run as run_mod
from prsec.stages.outputs import Citation, Hypothesis

ROOTS = {"/work/src": Path("/h/src"), "/work/in": Path("/h/in"), "/work/out": Path("/h/out"), "/skills": Path("/h/sk")}


@pytest.mark.parametrize("text,expected", [
    ("read `/work/in/diff.patch`", "read `/h/in/diff.patch`"),
    ("repo at /work/src.", "repo at /h/src."),
    ("under `/skills/<name>/`", "under `/h/sk/<name>/`"),
    ("write /work/out/output.json", "write /h/out/output.json"),
    ("not /work/srcx or /work/src.bak", "not /work/srcx or /work/src.bak"),
    ("prsec-skills/x and a/skills/y", "prsec-skills/x and a/skills/y"),
])
def test_rewrite_prompt(text: str, expected: str) -> None:
    assert _rewrite_prompt(text, ROOTS) == expected


def test_host_task_rewrites_prompt_and_fields(tmp_path: Path) -> None:
    task = StageTask(scan_id=1, stage=Stage.triage, task_id="1-triage", harness="raw", output_schema={},
                     prompt_md="Inputs in `/work/in`, repo `/work/src`, write `/work/out/output.json`.")
    spec = WorkbenchSpec(scan_id=1, task=task, image="x", harness_volume=None, src_dir=tmp_path / "s",
                         in_dir=tmp_path / "i", out_dir=tmp_path / "o", skills_dir=tmp_path / "k")
    t = host_task(spec)
    assert "/work/" not in t.prompt_md
    assert str(tmp_path / "o" / "output.json") in t.prompt_md
    assert t.output_path == str(tmp_path / "o" / "output.json")


def test_invocation_env_unsets_parent_session(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("CLAUDECODE", "1")
    monkeypatch.setenv("KEEP_ME", "1")
    task = StageTask(scan_id=1, stage=Stage.triage, task_id="t", harness="claude-code", output_schema={},
                     prompt_md="p", out_dir=str(tmp_path), workdir=str(tmp_path))
    inv = ClaudeCodeAdapter().build(task, None, "p")
    assert "CLAUDECODE" in inv.unset_env
    assert set(PARENT_SESSION_ENV) == set(inv.unset_env)
    env = run_mod._invocation_env(task, inv)
    assert "CLAUDECODE" not in env
    assert env["KEEP_ME"] == "1"
    env = run_mod._invocation_env(task, Invocation(argv=["x"], env={"CLAUDECODE": "set-by-adapter"}, cwd=".",
                                                   unset_env=["CLAUDECODE"]))
    assert env["CLAUDECODE"] == "set-by-adapter"  # the overlay wins over the unset list


def test_inprocess_tuple_return_is_unpacked(tmp_path: Path) -> None:
    from prsec.models import Event, EventKind, Usage

    class Fake:
        name = "fake"

        def run_inprocess(self, task, gw, prompt):
            return None, [Event(kind=EventKind.message, text="hi")], Usage()

    task = StageTask(scan_id=1, stage=Stage.triage, task_id="t", harness="raw", output_schema={}, prompt_md="p",
                     out_dir=str(tmp_path))
    att = run_mod._run_inprocess(Fake(), task, None, "p", deadline=__import__("time").monotonic() + 5)
    assert att.exit_code == 0
    assert [e.text for e in att.events] == ["hi"]


def test_canonical_bug_classes() -> None:
    sink = Citation(file="a.py", line=1, quote="x = 1")
    hyps = [Hypothesis(id=f"H{i}", vuln_class="technical", bug_class=bc, title="t", description="d", entry_point="e",
                       sink=sink, impact="i", severity_guess="high", introduced_by_diff=True)
            for i, bc in enumerate(["sql-injection", "SQLi", "negative_quantity", "brand-new-class"])]
    aliases = {"sqli": "sqli", "sql-injection": "sqli", "value-tampering": "value-tampering",
               "negative-quantity": "value-tampering"}
    assert [h.bug_class for h in _canonical_bug_classes(hyps, aliases)] == [
        "sqli", "sqli", "value-tampering", "brand-new-class"]

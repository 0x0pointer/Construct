"""Live conformance tier: a real harness CLI + a real model run one real stage.

Opt-in: PRSEC_LIVE_HARNESS=1 (and `-m live_harness`). Runs the hypothesise stage on the
`sqli-new-endpoint` eval case in dev mode (gw None: the CLI's own local login), via LocalRunner,
for every adapter whose CLI is installed. Optional: PRSEC_LIVE_HARNESSES=claude-code,opencode.
"""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from prsec.adapters.harness.base import adapter_names, get_adapter, resolve_cli
from prsec.adapters.protocols import WorkbenchSpec
from prsec.adapters.runner.local import LocalRunner
from prsec.citations import verify_all
from prsec.config import Policy, StagePolicy
from prsec.models import Stage, StageStatus
from prsec.orchestrator import stages
from prsec.skills_lint import bug_class_aliases
from prsec.stages.outputs import HypothesesOutput

from .conftest import cli_name

ROOT = Path(__file__).resolve().parents[2]
SKILLS = ROOT / "prsec-skills"
CASE = SKILLS / "evals" / "cases" / "sqli-new-endpoint"

pytestmark = [
    pytest.mark.live_harness,
    pytest.mark.skipif(os.environ.get("PRSEC_LIVE_HARNESS") != "1", reason="set PRSEC_LIVE_HARNESS=1 to run real harness CLIs"),
]


def _selected() -> list[str]:
    only = {n.strip() for n in os.environ.get("PRSEC_LIVE_HARNESSES", "").split(",") if n.strip()}
    return [n for n in adapter_names() if not only or n in only]


def _available(name: str) -> str | None:
    """Reason to skip, or None if the harness can run here."""
    adapter = get_adapter(name)
    cli = cli_name(adapter)
    if cli is None:
        if os.environ.get("PRSEC_RAW_BASE_URL") or os.environ.get("ANTHROPIC_API_KEY"):
            return None
        return "raw needs PRSEC_RAW_BASE_URL or ANTHROPIC_API_KEY"
    resolved = resolve_cli(cli)
    if os.path.sep not in resolved and shutil.which(resolved) is None:
        return f"{cli} CLI not installed"
    return None


@pytest.mark.parametrize("harness", _selected())
def test_live_hypothesise_finds_sqli(harness: str, tmp_path: Path) -> None:
    reason = _available(harness)
    if reason:
        pytest.skip(reason)

    sp = StagePolicy(harness=harness, model="agent-large", skills=["taint-analysis", "business-logic"],
                     wall_clock_s=int(os.environ.get("PRSEC_LIVE_WALL_S", "600")), usd_budget=2.0, max_turns=40)
    policy = Policy(defaults={s.value: sp for s in (Stage.triage, Stage.hypothesise, Stage.static_verify, Stage.skeptic)},
                    max_hypotheses=3)
    pr = json.loads((CASE / "pr.json").read_text())
    files = {
        "pr.json": json.dumps(pr, indent=2),
        "diff.patch": (CASE / "diff.patch").read_text(),
        "changed_files.txt": "\n".join(pr["changed_files"]) + "\n",
    }
    task, _ = stages.build_task(
        policy, Stage.hypothesise, 9001, pr["repo"], context_files=list(files),
        prompt_ctx={"pr_number": pr["number"], "max_hypotheses": 3, "triage_decision": "full", "focus_files": ["app.py"]},
    )
    src = tmp_path / "src"
    shutil.copytree(CASE / "repo", src)
    in_dir, out_dir = tmp_path / "in", tmp_path / "out"
    in_dir.mkdir()
    for name, content in files.items():
        (in_dir / name).write_text(content)
    (in_dir / stages.SCHEMA_FILE).write_text(json.dumps(task.output_schema, indent=2))

    spec = WorkbenchSpec(scan_id=9001, task=task, image="local", harness_volume=os.environ.get("PRSEC_HARNESS_HOME"),
                         src_dir=src, in_dir=in_dir, out_dir=out_dir, skills_dir=SKILLS, env={})
    result = LocalRunner(grace_s=60).run_workbench(spec)

    print(f"\n[{harness}] status={result.status} attempts={result.attempts} usage={result.usage} "
          f"version={result.harness_version} duration={result.duration_s}s")
    assert result.status == StageStatus.ok, result.errors
    assert result.transcript and result.usage.turns >= 1
    out = HypothesesOutput.model_validate(result.output)
    aliases = bug_class_aliases(SKILLS)
    sqli = [h for h in out.hypotheses if aliases.get(h.bug_class, h.bug_class) == "sqli"]
    assert sqli, [h.bug_class for h in out.hypotheses]
    h = sqli[0]
    assert h.sink.file == "app.py" and 33 <= h.sink.line <= 38, h.sink
    assert verify_all([h.sink, *([h.source] if h.source else []), *h.path], src) == []

"""Replay a dynamic case's reference PoC through the orchestrator's own replay path, with any runner.

No agent and no LLM: `dynamic._replayed` gets the case's reference envspec + PoC as if the dynamic stage
had produced them, so it runs the real replays (a fresh env per run, prsec-replay in the workbench image,
head replay_runs times, then base). A dynamic case's reference must come out `reproduced` on head and
not fire on base. This proves the dynamic machinery of a runner (Docker, Kubernetes) end to end.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from prsec.adapters.protocols import Runner
from prsec.config import Policy, load_policy
from prsec.dynamic.results import DynamicEvidence, ReplayResult
from prsec.evals.cases import REPO_OWNER, Case, CaseSCM, head_source
from prsec.orchestrator import dynamic as dynamic_mod
from prsec.orchestrator import pipeline
from prsec.stages.outputs import Citation, DynamicOutput, Hypothesis


@dataclass
class OfflineCtx(pipeline.Ctx):
    """pipeline.Ctx without the database: timeline events are collected, the scan is never superseded."""

    events: list[tuple[str, str, dict[str, Any]]] = field(default_factory=list)

    def emit(self, kind: str, message: str, **kw: Any) -> None:
        self.events.append((kind, message, kw))

    def check(self) -> None:
        return None


def hypothesis(case: Case) -> Hypothesis:
    """The case's first expected finding as the hypothesis the reference PoC proves."""
    exp = case.expected["expected_findings"][0]
    line = (exp.get("sink_lines") or [1])[0]
    quote = (case.repo / exp["sink_file"]).read_text().splitlines()[line - 1]
    return Hypothesis(
        id=case.reference_poc().hypothesis_id, vuln_class=exp["vuln_class"], bug_class=exp["bug_class"],
        title=case.pr["title"], description=case.expected["description"],
        entry_point=exp.get("entry_point", "http"), sink=Citation(file=exp["sink_file"], line=line, quote=quote),
        impact="reference replay", severity_guess=exp.get("min_severity", "high"), introduced_by_diff=True,
    )


def replay_reference(case: Case, runner: Runner, *, scan_id: int, root: Path, image: str,
                     policy: Policy | None = None) -> tuple[DynamicEvidence, OfflineCtx]:
    """Run the case's reference PoC through `dynamic._replayed` with `runner`. The caller destroys the scan."""
    spec, poc = case.reference_envspec(), case.reference_poc()
    number = 1
    pr = case.pr_info(f"{REPO_OWNER}/{case.id}", number)
    ctx = OfflineCtx(
        scan_id=scan_id, repo=pr.repo, pr=pr, policy=policy or load_policy(), root=root,
        src=head_source(case, root / "src"), runner=runner, network=None, gw_key="", image=image,
        skills_version="reference", scm=CaseSCM(),
    )
    st = dynamic_mod._State(ctx=ctx, spec=spec)
    out = DynamicOutput(hypothesis_id=poc.hypothesis_id, outcome="reproduced", reasoning="reference PoC",
                        poc=poc, envspec=spec)
    return dynamic_mod._replayed(st, 1, hypothesis(case), out), ctx


def explain(ev: DynamicEvidence) -> str:
    """Everything needed to see why a replay did (not) fire."""
    def one(r: ReplayResult) -> dict[str, Any]:
        return {
            "run_id": r.run_id, "env_ok": r.env_ok, "env_error": r.env_error, "fired": r.fired,
            "aborted": r.aborted, "incomplete": r.incomplete,
            "oracles": [(o.type, o.passed, o.detail[:200]) for o in r.oracle_results],
            "steps": [(s.name, s.status, s.error, s.response_excerpt[:200]) for s in r.steps],
            "app_log_tail": r.app_log_tail[-1500:],
        }
    return json.dumps({"outcome": ev.outcome, "reason": ev.reason, "replays": [one(r) for r in ev.replays]}, indent=2)


def problems(ev: DynamicEvidence, replay_runs: int) -> list[str]:
    """Why the evidence is not a clean reference result ([] = reproduced on head, not on base)."""
    out = []
    if ev.outcome != "reproduced":
        out.append(f"outcome {ev.outcome} ({ev.reason})")
    if ev.entry != "http":
        out.append(f"entry {ev.entry}")
    if ev.head_runs != replay_runs or not ev.replay_confirmed:
        out.append(f"head fired {ev.head_fired}/{ev.head_runs} of {replay_runs}")
    if not ev.base_ran:
        out.append("base replay did not run")
    elif ev.base_fired is not False:
        out.append("fired on base")
    return out

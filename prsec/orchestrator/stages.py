"""Builds harness-neutral StageTasks from policy, experiments and prompt templates."""
from __future__ import annotations

import fnmatch
import hashlib
from dataclasses import dataclass
from typing import Any

from prsec import prompts
from prsec.config import Policy, StagePolicy
from prsec.models import Limits, Stage, StageTask
from prsec.sandbox.entrypoint.contract import SCHEMA_FILE
from prsec.stages.outputs import schema_for


@dataclass(frozen=True)
class StageChoice:
    policy: StagePolicy
    experiment: str | None  # e.g. "hypothesise:codex" when an experiment arm replaced the default


def bucket(scan_id: int, key: str) -> float:
    """Deterministic value in [0, 1) for (scan_id, key); replaces randomness for sampling."""
    digest = hashlib.sha256(f"{scan_id}:{key}".encode()).digest()
    return int.from_bytes(digest[:8], "big") / 2**64


def task_id(scan_id: int, stage: Stage | str, hyp_id: str | None = None) -> str:
    base = f"{scan_id}-{Stage(stage).value}"
    return f"{base}-{hyp_id}" if hyp_id else base


def _repo_pins(policy: Policy, stage: str, repo: str | None) -> bool:
    return bool(repo) and any(
        fnmatch.fnmatch(repo, pattern) and stage in ov.stages for pattern, ov in policy.repos.items()
    )


def choose(policy: Policy, stage: Stage | str, repo: str | None, scan_id: int) -> StageChoice:
    """Stage policy after repo overrides; an experiment may swap the harness unless the repo pins the stage."""
    name = Stage(stage).value
    sp = policy.stage(name, repo)
    if _repo_pins(policy, name, repo):
        return StageChoice(sp, None)
    for exp in policy.experiments:
        if exp.stage != name or not exp.harnesses:
            continue
        if bucket(scan_id, f"experiment:{name}") < exp.sample:
            arm = exp.harnesses[int(bucket(scan_id, f"arm:{name}") * len(exp.harnesses))]
            return StageChoice(sp.model_copy(update={"harness": arm}), f"{name}:{arm}")
        break
    return StageChoice(sp, None)


def has_tools(harness: str) -> bool:
    """False for in-process adapters (raw) whose context files are inlined into the prompt."""
    try:
        from prsec.adapters.harness.base import get_adapter

        return bool(get_adapter(harness).caps.subprocess)
    except Exception:
        return harness != "raw"


def build_task(
    policy: Policy,
    stage: Stage | str,
    scan_id: int,
    repo: str,
    *,
    context_files: list[str],
    prompt_ctx: dict[str, Any] | None = None,
    hyp_id: str | None = None,
) -> tuple[StageTask, StageChoice]:
    stage = Stage(stage)
    choice = choose(policy, stage, repo, scan_id)
    sp = choice.policy
    files = [f for f in context_files if f != SCHEMA_FILE] + [SCHEMA_FILE]
    task = StageTask(
        scan_id=scan_id,
        stage=stage,
        task_id=task_id(scan_id, stage, hyp_id),
        harness=sp.harness,
        model_alias=sp.model,
        prompt_md="",
        skills=list(sp.skills),
        output_schema=schema_for(stage),
        context_files=files,
        limits=Limits(wall_clock_s=sp.wall_clock_s, usd_budget=sp.usd_budget, max_turns=sp.max_turns),
    )
    task.output_path = f"{task.out_dir}/output.json"
    ctx: dict[str, Any] = {
        "repo": repo,
        "pr_number": "",
        "has_tools": has_tools(sp.harness),
        "context_files": files,
        "skills": task.skills,
        "skills_dir": task.skills_dir,
        "in_dir": task.in_dir,
        "out_dir": task.out_dir,
        "workdir": task.workdir,
        "output_path": task.output_path,
        "max_hypotheses": policy.max_hypotheses,
        "hypothesis_id": hyp_id or "",
        "bug_class": "",
        "triage_decision": "full",
        "focus_files": [],
        "has_repo_profile": "repo_profile.json" in files,
        "app_dir": "",  # dynamic stage: writable app copy (its tools may install and run the app)
    }
    ctx.update(prompt_ctx or {})
    task.prompt_md = prompts.render(stage.value, **ctx)
    return task, choice


def _dynamic_runs(policy: Policy, n_hypotheses: int) -> int:
    """Hypotheses that may get a dynamic attempt (0 when phase 2 is off)."""
    return min(n_hypotheses, policy.dynamic.max_hypotheses) if policy.dynamic.enabled else 0


def scan_budget(policy: Policy, repo: str, n_hypotheses: int) -> tuple[float, int, list[str]]:
    """Upper bound (usd, wall-clock seconds, model aliases) for one scan's gateway key.

    Phase 2 adds the env stage (once) and one dynamic stage per candidate; the wall clock also
    covers the agent-free replays, since the key must outlive every dynamic stage that waits on them.
    """
    n_dyn = _dynamic_runs(policy, n_hypotheses)
    usd = 0.0
    wall = 0
    models: set[str] = set()
    plan = (("triage", 1), ("hypothesise", 1), ("static_verify", n_hypotheses), ("skeptic", n_hypotheses),
            ("env", 1 if n_dyn else 0), ("dynamic", n_dyn))
    for stage, mult in plan:
        if stage not in policy.defaults or not mult:
            continue
        sp = policy.stage(stage, repo)
        usd += sp.usd_budget * mult
        wall += sp.wall_clock_s * mult
        models.add(sp.model)
    if n_dyn and "dynamic" in policy.defaults:
        replays = policy.dynamic.replay_runs + (1 if policy.dynamic.base_replay else 0)
        wall += policy.dynamic.replay_timeout_s * replays * n_dyn
    return usd, wall, sorted(models)

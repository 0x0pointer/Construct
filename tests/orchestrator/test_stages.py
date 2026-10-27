import pytest

from prsec.config import Experiment, Policy, RepoOverride, StagePolicy, load_policy
from prsec.models import Stage
from prsec.orchestrator import stages
from prsec.stages.outputs import schema_for


def _policy(**kw) -> Policy:
    p = load_policy()
    return p.model_copy(update=kw)


def test_task_shape_from_policy():
    p = _policy(experiments=[])
    task, choice = stages.build_task(p, Stage.triage, 42, "acme/shop", context_files=["pr.json", "diff.patch"],
                                     prompt_ctx={"pr_number": 3})
    sp = p.defaults["triage"]
    assert task.task_id == "42-triage"
    assert task.harness == sp.harness
    assert task.model_alias == sp.model
    assert task.skills == sp.skills
    assert task.limits.wall_clock_s == sp.wall_clock_s
    assert task.limits.usd_budget == sp.usd_budget
    assert task.output_schema == schema_for(Stage.triage)
    assert task.context_files == ["pr.json", "diff.patch", "output_schema.json"]
    assert task.output_path == "/work/out/output.json"
    assert "acme/shop#3" in task.prompt_md
    assert choice.experiment is None


def test_task_id_with_hypothesis():
    p = _policy(experiments=[])
    task, _ = stages.build_task(p, "static_verify", 7, "a/b", context_files=["hypothesis.json"], hyp_id="H3",
                                prompt_ctx={"bug_class": "sqli"})
    assert task.task_id == "7-static_verify-H3"
    assert "H3" in task.prompt_md
    assert "sqli" in task.prompt_md


def test_raw_harness_prompt_has_no_paths():
    p = _policy(experiments=[])
    task, _ = stages.build_task(p, "skeptic", 1, "a/b", context_files=["code_slices.md"])
    assert task.harness == "raw"
    assert "cannot run commands" in task.prompt_md
    assert "/work/out" not in task.prompt_md


def test_bucket_deterministic_and_spread():
    first = stages.bucket(5, "x")
    assert stages.bucket(5, "x") == first
    assert first != stages.bucket(5, "y")
    vals = [stages.bucket(i, "experiment:hypothesise") for i in range(2000)]
    assert all(0 <= v < 1 for v in vals)
    assert 0.07 < sum(v < 0.1 for v in vals) / len(vals) < 0.13


def test_experiment_sampling_is_deterministic():
    arms = ["claude-code", "codex", "opencode", "pi"]
    p = _policy(experiments=[Experiment(stage="hypothesise", harnesses=arms, sample=0.5)])
    picks = {sid: stages.choose(p, "hypothesise", "a/b", sid) for sid in range(200)}
    again = {sid: stages.choose(p, "hypothesise", "a/b", sid) for sid in range(200)}
    assert picks == again
    sampled = [c for c in picks.values() if c.experiment]
    assert 60 < len(sampled) < 140
    assert {c.policy.harness for c in sampled} == set(arms)
    assert all(c.experiment == f"hypothesise:{c.policy.harness}" for c in sampled)
    assert all(c.policy.harness == p.defaults["hypothesise"].harness for c in picks.values() if not c.experiment)
    # other stages untouched
    assert all(stages.choose(p, "triage", "a/b", sid).experiment is None for sid in range(50))


def test_repo_override_wins_and_disables_experiment():
    over = RepoOverride(stages={"hypothesise": StagePolicy(harness="claude-code", model="agent-large", usd_budget=9.0)})
    p = _policy(
        repos={"acme/pay-*": over},
        experiments=[Experiment(stage="hypothesise", harnesses=["codex"], sample=1.0)],
    )
    task, choice = stages.build_task(p, "hypothesise", 9, "acme/pay-api", context_files=[])
    assert task.harness == "claude-code"
    assert task.limits.usd_budget == 9.0
    assert choice.experiment is None
    assert task.skills == p.defaults["hypothesise"].skills  # unset fields inherit defaults
    task2, choice2 = stages.build_task(p, "hypothesise", 9, "acme/other", context_files=[])
    assert task2.harness == "codex"
    assert choice2.experiment == "hypothesise:codex"


def _static_usd(d, n):
    return d["triage"].usd_budget + d["hypothesise"].usd_budget + n * d["static_verify"].usd_budget + n * d["skeptic"].usd_budget


def test_scan_budget():
    p = _policy()
    usd, wall, models = stages.scan_budget(p, "a/b", 2)
    d = p.defaults
    assert usd == pytest.approx(_static_usd(d, 2) + d["env"].usd_budget + 2 * d["dynamic"].usd_budget)
    assert wall > 0
    assert set(models) == {sp.model for sp in d.values()}


def test_scan_budget_caps_dynamic_and_covers_replays():
    p = _policy()
    p = p.model_copy(update={"dynamic": p.dynamic.model_copy(update={"max_hypotheses": 1})})
    d = p.defaults
    usd, wall, _ = stages.scan_budget(p, "a/b", 4)
    assert usd == pytest.approx(_static_usd(d, 4) + d["env"].usd_budget + d["dynamic"].usd_budget)
    replays = (p.dynamic.replay_runs + 1) * p.dynamic.replay_timeout_s
    static_wall = d["triage"].wall_clock_s + d["hypothesise"].wall_clock_s + 4 * (d["static_verify"].wall_clock_s + d["skeptic"].wall_clock_s)
    assert wall == static_wall + d["env"].wall_clock_s + d["dynamic"].wall_clock_s + replays


def test_scan_budget_without_dynamic():
    p = _policy()
    p = p.model_copy(update={"dynamic": p.dynamic.model_copy(update={"enabled": False})})
    usd, _, _ = stages.scan_budget(p, "a/b", 2)
    assert usd == pytest.approx(_static_usd(p.defaults, 2))

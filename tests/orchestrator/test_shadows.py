"""Shadow arms (policy `shadows`): a second agent next to the rules stage, recorded but never deciding."""
import pytest
from pydantic import ValidationError

from prsec.config import Policy, ShadowArm, load_policy
from prsec.models import ScanStatus, StageStatus
from prsec.orchestrator import pipeline, stages

from .test_pipeline import ROW, full_script, only
from .test_pipeline import env  # noqa: F401  (fixture)

JEV = ShadowArm(stage="rules", name="jev", harness="raw", model="rules-jev")


def rules_by_arm(main: str, shadow):
    """rules output per task: the primary agent says `main`; the shadow arm returns `shadow` (or a StageStatus)."""
    def fn(t):
        if stages.is_shadow_task(t.task_id):
            return shadow if isinstance(shadow, StageStatus) else {"decision": shadow, "reason": f"jev says {shadow}"}
        return {"decision": main, "reason": f"primary says {main}"}
    return fn


def script(main: str, shadow):
    s = full_script(hyps=[])
    s["rules"] = rules_by_arm(main, shadow)
    return s


@pytest.fixture
def events(monkeypatch):
    seen = []
    monkeypatch.setattr(pipeline.timeline, "emit", lambda scan_id, kind, message, **kw: seen.append((kind, message, kw)))
    return seen


def test_shadow_runs_next_to_rules_and_never_decides(env, events):  # noqa: F811
    s = env(script=script("scan", "skip"), policy_update={"shadows": [JEV]})
    pipeline.run_scan(ROW)
    f = only(s["q"])
    assert f["status"] == ScanStatus.done  # the shadow's skip changed nothing
    rules = f["triage"]["rules"]
    assert rules["decision"] == "scan"
    [arm] = rules["shadows"]
    assert arm == {"name": "jev", "harness": "raw", "model": "rules-jev", "task_id": "101-rules-shadow-jev",
                   "status": "ok", "decision": "skip", "reason": "jev says skip", "agrees": False}
    shadow_spec = next(sp for sp in s["runner"].specs if sp.task.task_id == "101-rules-shadow-jev")
    assert (shadow_spec.task.harness, shadow_spec.task.model_alias) == ("raw", "rules-jev")
    assert shadow_spec.task.stage.value == "rules"
    assert "101-rules-shadow-jev" in s["q"].stage_runs
    [ev] = [e for e in events if e[0] == "rules" and (e[2].get("data") or {}).get("shadow")]
    assert ev[2]["level"] == "warning"
    assert "DISAGREES with scan" in ev[1]
    assert ev[2]["data"]["agrees"] is False


def test_shadow_agreeing_skip_is_recorded_on_the_skipped_scan(env):  # noqa: F811
    s = env(script=script("skip", "skip"), policy_update={"shadows": [JEV]})
    pipeline.run_scan(ROW)
    f = only(s["q"])
    assert f["status"] == ScanStatus.skipped
    assert f["triage"]["source"] == "rules"
    [arm] = f["triage"]["rules"]["shadows"]
    assert (arm["decision"], arm["agrees"]) == ("skip", True)


def test_failed_shadow_is_recorded_not_fatal(env):  # noqa: F811
    s = env(script=script("scan", StageStatus.harness_error), policy_update={"shadows": [JEV]})
    pipeline.run_scan(ROW)
    f = only(s["q"])
    assert f["status"] == ScanStatus.done
    [arm] = f["triage"]["rules"]["shadows"]
    assert (arm["status"], arm["decision"], arm["agrees"]) == ("harness_error", None, None)


def test_shadow_that_raises_is_recorded_not_fatal(env, monkeypatch):  # noqa: F811
    s = env(script=script("scan", "scan"), policy_update={"shadows": [JEV]})
    real = stages.build_task

    def build(*a, shadow=None, **kw):
        if shadow is not None:
            raise RuntimeError("gateway alias missing")
        return real(*a, **kw)

    monkeypatch.setattr(pipeline.stages, "build_task", build)
    pipeline.run_scan(ROW)
    [arm] = only(s["q"])["triage"]["rules"]["shadows"]
    assert arm["status"] == "error"
    assert "gateway alias missing" in arm["reason"]


def test_unsampled_shadow_does_not_run(env):  # noqa: F811
    arm = JEV.model_copy(update={"sample": 0.0})
    s = env(script=script("scan", "skip"), policy_update={"shadows": [arm]})
    pipeline.run_scan(ROW)
    assert "shadows" not in only(s["q"])["triage"]["rules"]
    assert not any(stages.is_shadow_task(t) for t in s["q"].stage_runs)


def test_shadow_policy_validation():
    with pytest.raises(ValidationError, match="supported for rules only"):
        ShadowArm(stage="triage", name="x", harness="raw", model="m")
    with pytest.raises(ValidationError):
        ShadowArm(stage="rules", name="Bad Name", harness="raw", model="m")
    twice = {**load_policy().model_dump(), "shadows": [JEV.model_dump(), JEV.model_dump()]}
    with pytest.raises(ValidationError, match="unique"):
        Policy.model_validate(twice)


def test_shadow_policy_inherits_stage_limits():
    policy = load_policy()
    sp = JEV.policy_for(policy.stage("rules"))
    assert (sp.harness, sp.model, sp.skills) == ("raw", "rules-jev", policy.stage("rules").skills)
    own = JEV.model_copy(update={"skills": [], "wall_clock_s": 30}).policy_for(policy.stage("rules"))
    assert (own.skills, own.wall_clock_s) == ([], 30)


def test_scan_budget_allows_the_shadow_model():
    policy = load_policy().model_copy(update={"shadows": []})
    usd, wall, models = stages.scan_budget(policy, "acme/shop", 2)
    usd2, wall2, models2 = stages.scan_budget(policy.model_copy(update={"shadows": [JEV]}), "acme/shop", 2)
    assert "rules-jev" in models2
    assert "rules-jev" not in models
    assert usd2 == pytest.approx(usd + policy.stage("rules").usd_budget)
    assert wall2 == wall  # runs alongside rules, same wall clock


def test_shadow_task_ids():
    assert stages.shadow_task_id(5, "rules", "jev") == "5-rules-shadow-jev"
    assert stages.is_shadow_task("5-rules-shadow-jev")
    assert not stages.is_shadow_task("5-rules")
    assert not stages.is_shadow_task("5-static_verify-H1")


def test_default_policy_shadow_is_wired_through_the_gateway():
    """The shipped policy's arm uses a decision harness whose route the production gateway serves."""
    from pathlib import Path

    import yaml

    from prsec.adapters.harness.base import get_adapter

    [arm] = load_policy().shadows
    assert (arm.stage, arm.harness, arm.model) == ("rules", "openai-decide", "gpt-6-luna")
    route = get_adapter(arm.harness).route
    cfg = yaml.safe_load((Path(__file__).resolve().parents[2] / "deploy/compose/litellm/config.yaml").read_text())
    assert route in {r["path"] for r in cfg["general_settings"]["pass_through_endpoints"]}

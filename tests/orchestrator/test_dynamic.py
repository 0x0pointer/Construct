"""Phase 2 in the pipeline: env stage, dynamic stage per hypothesis, agent-free replays, labels."""
import json
from pathlib import Path

import pytest

from prsec.config import settings
from prsec.dynamic.results import DynamicEvidence, EnvInfo, ReplayRequest, ReplayResult
from prsec.models import Label, ScanStatus, Stage, StageStatus
from prsec.orchestrator import dynamic as dynamic_mod
from prsec.orchestrator import pipeline

from .test_pipeline import CODE_DIFF, ROW, FakeQueue, FakeRunner, FakeSCM, full_script, only, static
from .test_pipeline import env  # noqa: F401  (fixture)

ENVSPEC = {
    "stack": "python", "install": ["pip install -r requirements.txt"], "start": "python app.py", "port": 8000,
    "services": [{"name": "db", "kind": "postgres", "seed": ["app/orders.py", "../outside.sql"]}],
}
FIXED_SPEC = {**ENVSPEC, "env": {"SECRET_KEY": "x"}, "services": []}  # services may not change
HTTP_POC = {
    "kind": "http", "hypothesis_id": "H1", "description": "boolean-based sqli",
    "steps": [{"name": "inject", "path": "/orders?id=1 OR 1=1"}],
    "oracles": [{"type": "response_contains", "step": "inject", "value": "${CANARY.token}"}],
}
SCRIPT_POC = {"kind": "script", "hypothesis_id": "H1", "description": "direct call", "script": "python -c 'print(1)'",
              "oracles": [{"type": "command", "run": "echo ${CANARY.token}", "expect": "${CANARY.token}"}]}


def dyn_out(outcome="reproduced", poc=HTTP_POC, envspec=FIXED_SPEC):
    return {"hypothesis_id": "H1", "outcome": outcome, "reasoning": "tried", "poc": poc, "envspec": envspec}


class EnvRunner(FakeRunner):
    """FakeRunner with dynamic environments; `replay(req, spec)` scripts each replay's result."""

    def __init__(self, script, replay=None, create_error=None, unsupported=False, **kw):
        super().__init__(script, **kw)
        self.replay = replay or (lambda req, spec: True)
        self.create_error = create_error
        self.unsupported = unsupported
        if unsupported:
            self.supports_envs = False
        self.envs: list[tuple[str, object]] = []
        self.destroyed_envs: list[str] = []
        self.health = lambda env_name: {}  # env name -> EnvInfo.services
        self.replays: list[tuple[ReplayRequest, object]] = []

    def create_env(self, scan_id, env_name, req):
        if self.unsupported:
            raise NotImplementedError("no envs")
        if self.create_error and self.create_error(env_name):
            raise RuntimeError("docker refused")
        self.envs.append((env_name, req))
        return EnvInfo(network=f"prsec-scan-{scan_id}-{env_name}", sink_ip="10.0.0.2", services=self.health(env_name))

    def destroy_env(self, scan_id, env_name):
        self.destroyed_envs.append(env_name)

    def run_replay(self, spec):
        req = ReplayRequest.model_validate_json((spec.in_dir / "replay.json").read_text())
        self.replays.append((req, spec))
        fired = self.replay(req, spec)
        if isinstance(fired, ReplayResult):
            return fired
        if fired is None:
            return ReplayResult(run_id=req.run_id, env_ok=False, env_error="app never healthy", entry=req.poc.kind)
        return ReplayResult(run_id=req.run_id, env_ok=True, fired=fired, entry=req.poc.kind)


class BaseSCM(FakeSCM):
    def __init__(self, diff):
        super().__init__(diff)
        self.fetched: list[str] = []

    def fetch_source(self, repo, sha, dest: Path, installation_id=None):
        self.fetched.append(sha)
        return super().fetch_source(repo, sha, dest, installation_id)


def dyn_script(out=None, env_out=None, static_fn=None):
    script = full_script(static_fn=static_fn)
    script["env"] = lambda t: env_out if env_out is not None else {"envspec": ENVSPEC, "notes": "flask"}
    script["dynamic"] = lambda t: out if out is not None else dyn_out()
    return script


@pytest.fixture
def dyn(env, monkeypatch):  # noqa: F811
    """env() with an EnvRunner and a SCM that records base fetches."""

    def setup(script=None, replay=None, create_error=None, unsupported=False, q=None, policy_update=None):
        q = q or FakeQueue()
        runner = EnvRunner(script or dyn_script(), replay=replay, create_error=create_error,
                           unsupported=unsupported, events=q.events)
        scm = BaseSCM(CODE_DIFF)
        s = env(q=q, scm=scm, policy_update=policy_update)
        monkeypatch.setattr(pipeline.runner_pkg, "get_runner", lambda name: runner, raising=False)
        s.update(runner=runner, scm=scm)
        return s

    return setup


def finding(s):
    [fd] = s["sink"].calls[0][2]
    return fd


def evidence(fd) -> DynamicEvidence:
    return DynamicEvidence.model_validate(fd.dynamic)


# ------------------------------------------------------------------ labels


def test_reproduced_path(dyn):
    s = dyn(replay=lambda req, spec: not req.run_id.endswith("-base"))
    pipeline.run_scan(ROW)
    assert only(s["q"])["status"] == ScanStatus.done
    fd = finding(s)
    assert fd.label == Label.reproduced
    assert fd.label_reason == "replay_confirmed"
    assert fd.introduced is True
    ev = evidence(fd)
    assert ev.outcome == "reproduced"
    assert (ev.head_runs, ev.head_fired, ev.base_ran, ev.base_fired) == (2, 2, True, False)
    assert [r.run_id for r in ev.replays] == ["101-replay-H1-r1", "101-replay-H1-r2", "101-replay-H1-base"]
    assert ev.evidence_uri.startswith("file://")
    assert "101-dynamic-H1/dynamic_evidence.json" in ev.evidence_uri
    stored = json.loads(Path(ev.evidence_uri[7:]).read_text())
    assert stored["poc"]["steps"][0]["name"] == "inject"
    assert s["q"].stage_runs[-2:] == ["101-env", "101-dynamic-H1"]
    assert s["sink"].calls[0][3]["dynamic"]["outcomes"] == {"H1": "reproduced"}


def test_dynamic_stage_provenance_on_the_finding(dyn):
    s = dyn()
    pipeline.run_scan(ROW)
    fd = finding(s)
    assert fd.provenance["dynamic"]["task_id"] == "101-dynamic-H1"
    assert evidence(fd).provenance["task_id"] == "101-dynamic-H1"


def test_supports_envs_flag_on_runners():
    from prsec.adapters.runner.docker import DockerRunner
    from prsec.adapters.runner.launcher import LauncherRunner
    from prsec.adapters.runner.local import LocalRunner

    assert dynamic_mod._supports_envs(DockerRunner)
    assert dynamic_mod._supports_envs(LauncherRunner)
    assert not dynamic_mod._supports_envs(LocalRunner)


def test_script_poc_is_capped_at_likely(dyn):
    s = dyn(script=dyn_script(out=dyn_out(poc=SCRIPT_POC)))
    pipeline.run_scan(ROW)
    fd = finding(s)
    assert fd.label == Label.likely
    assert fd.label_reason == "replay_confirmed_direct_call"
    assert evidence(fd).entry == "script"


def test_not_reproduced_keeps_static_label(dyn):
    s = dyn(script=dyn_script(out=dyn_out(outcome="not_reproduced", poc=None)))
    pipeline.run_scan(ROW)
    fd = finding(s)
    assert fd.label == Label.likely
    assert fd.label_reason == "confirmed_static_reachable_skeptic_upheld"
    assert evidence(fd).outcome == "not_reproduced"
    assert s["runner"].replays == []
    assert fd.introduced is None


def test_not_reproduced_is_recorded_on_inconclusive(dyn):
    plausible = lambda t: static(verdict="plausible", reachable="unknown")  # noqa: E731
    s = dyn(script=dyn_script(out=dyn_out(outcome="blocked", poc=None), static_fn=plausible))
    pipeline.run_scan(ROW)
    fd = finding(s)
    assert fd.label == Label.inconclusive
    assert fd.label_reason == "plausible_static_only; dynamic=not_reproduced"
    assert evidence(fd).reason.startswith("blocked:")


def test_flaky_replay_is_not_reproduced_and_stops_early(dyn):
    s = dyn(replay=lambda req, spec: False)
    pipeline.run_scan(ROW)
    fd = finding(s)
    assert fd.label == Label.likely
    ev = evidence(fd)
    assert ev.outcome == "not_reproduced"
    assert (ev.head_runs, ev.head_fired) == (1, 0)
    assert len(s["runner"].replays) == 1
    assert s["scm"].fetched == ["h" * 40]  # never fetched base


def test_base_replay_fired_means_not_introduced(dyn):
    s = dyn(replay=lambda req, spec: True)
    pipeline.run_scan(ROW)
    fd = finding(s)
    assert fd.label == Label.reproduced
    assert fd.introduced is False
    assert evidence(fd).base_fired is True


# ---------------------------------------------------------------- failures


def test_env_stage_failure(dyn):
    s = dyn(script=dyn_script(env_out=StageStatus.output_invalid))
    pipeline.run_scan(ROW)
    assert only(s["q"])["status"] == ScanStatus.done
    fd = finding(s)
    assert fd.label == Label.likely
    ev = evidence(fd)
    assert ev.outcome == "env_failed"
    assert ev.reason == "env stage output_invalid"
    assert "101-dynamic-H1" not in s["q"].stage_runs


def test_create_env_failure(dyn):
    s = dyn(create_error=lambda name: True)
    pipeline.run_scan(ROW)
    ev = evidence(finding(s))
    assert ev.outcome == "env_failed"
    assert "docker refused" in ev.reason


def test_replay_env_failure(dyn):
    s = dyn(replay=lambda req, spec: None)
    pipeline.run_scan(ROW)
    ev = evidence(finding(s))
    assert ev.outcome == "env_failed"
    assert "app never healthy" in ev.reason
    assert not dynamic_mod._profile_path("acme/shop").exists()


def test_dynamic_stage_failure_is_error(dyn):
    s = dyn(script=dyn_script(out=StageStatus.timeout))
    pipeline.run_scan(ROW)
    fd = finding(s)
    assert fd.label == Label.likely
    assert evidence(fd).outcome == "error"
    assert evidence(fd).reason == "dynamic stage timeout"


def test_runner_unsupported_skips_without_env_stage(dyn):
    s = dyn(unsupported=True)
    pipeline.run_scan(ROW)
    fd = finding(s)
    assert fd.label_reason == "confirmed_static_reachable_skeptic_upheld"
    ev = evidence(fd)
    assert ev.outcome == "skipped"
    assert ev.reason == "runner_unsupported"
    assert "101-env" not in s["q"].stage_runs


def test_runner_without_env_methods_is_unsupported(env):  # noqa: F811
    s = env(script=full_script())
    pipeline.run_scan(ROW)
    assert evidence(finding(s)).reason == "runner_unsupported"


def test_local_runner_is_unsupported_before_the_env_stage(dyn):
    s = dyn()
    s["runner"].name = "local"
    pipeline.run_scan(ROW)
    assert evidence(finding(s)).reason == "runner_unsupported"
    assert "101-env" not in s["q"].stage_runs


def test_create_env_not_implemented_is_runner_unsupported(dyn):
    s = dyn()

    def nope(*a):
        raise NotImplementedError

    s["runner"].create_env = nope
    pipeline.run_scan(ROW)
    ev = evidence(finding(s))
    assert ev.outcome == "skipped"
    assert ev.reason == "runner_unsupported"


def test_disabled_dynamic_leaves_no_trace(dyn):
    s = dyn(policy_update={"dynamic": pipeline.load_policy().dynamic.model_copy(update={"enabled": False})})
    pipeline.run_scan(ROW)
    fd = finding(s)
    assert fd.dynamic is None
    assert "dynamic" not in s["sink"].calls[0][3]


def test_below_min_severity_is_not_a_candidate(dyn):
    low = lambda t: {**static(), "severity": "low"}  # noqa: E731
    s = dyn(script=dyn_script(static_fn=low))
    pipeline.run_scan(ROW)
    assert finding(s).dynamic is None
    assert s["runner"].envs == []


# ------------------------------------------------------------- environments


def test_environments_and_inputs(dyn):
    s = dyn()
    pipeline.run_scan(ROW)
    runner = s["runner"]
    names = [n for n, _ in runner.envs]
    assert names == ["h1", "h1r1", "h1r2", "h1b"]
    assert runner.destroyed_envs.count("h1") == 1
    assert set(names) <= set(runner.destroyed_envs)
    reqs = dict(runner.envs)
    assert reqs["h1"].llm is True
    assert reqs["h1r1"].llm is False
    dyn_spec = next(sp for sp in runner.specs if sp.task.stage == Stage.dynamic)
    assert dyn_spec.env_name == "h1"
    assert dyn_spec.network is None
    assert dyn_spec.app_dir.name == "h1"
    env_spec = next(sp for sp in runner.specs if sp.task.stage == Stage.env)
    assert env_spec.network == "prsec-scan-101"
    assert env_spec.env_name is None
    files = runner.inputs["101-dynamic-H1"]
    assert {"hypothesis.json", "static_verify.json", "envspec.json", "code_slices.md", "pr.json", "diff.patch"} <= set(files)
    assert "quote" not in files["hypothesis.json"]


def test_replays_use_corrected_spec_with_env_stage_services(dyn):
    s = dyn()
    pipeline.run_scan(ROW)
    req, spec = s["runner"].replays[0]
    assert req.envspec.env == {"SECRET_KEY": "x"}
    assert [sv.name for sv in req.envspec.services] == ["db"]
    assert spec.mode == "replay"
    assert spec.network is None
    assert spec.env == {}  # no gateway key in replays
    assert req.timeout_s == pipeline.load_policy().dynamic.replay_timeout_s


def test_base_replay_runs_on_base_source(dyn):
    s = dyn()
    pipeline.run_scan(ROW)
    assert s["scm"].fetched == ["h" * 40, "b" * 40]
    base = s["runner"].replays[-1][1]
    head = s["runner"].replays[0][1]
    assert base.src_dir.name == "base_src"
    assert head.src_dir.name == "src"
    assert base.app_dir != head.app_dir


def test_seed_files_stay_inside_the_repo(dyn):
    s = dyn()
    pipeline.run_scan(ROW)
    [svc] = dict(s["runner"].envs)["h1"].services
    assert svc.kind == "postgres"
    assert svc.seed_dir is not None
    assert "/seeds/h1/db" in svc.seed_dir


def test_seed_dir_copies_only_repository_files(tmp_path):
    st = dynamic_mod._State(ctx=_ctx(tmp_path), spec=dynamic_mod.EnvSpec.model_validate(ENVSPEC))
    (tmp_path / "outside.sql").write_text("select 1;")
    (tmp_path / "src" / "app").mkdir(parents=True)
    (tmp_path / "src" / "app" / "schema.sql").write_text("create table t (id int);")
    out = dynamic_mod._seed_dir(st, tmp_path / "src", "h1", "db", ["app/schema.sql", "../outside.sql", "nope.sql"], "postgres")
    assert sorted(p.name for p in Path(out).iterdir()) == ["00-schema.sql"]


def test_seed_dir_ignores_kinds_without_seed_path(tmp_path):
    st = dynamic_mod._State(ctx=_ctx(tmp_path), spec=dynamic_mod.EnvSpec.model_validate(ENVSPEC))
    assert dynamic_mod._seed_dir(st, tmp_path, "h1", "cache", ["a.sql"], "redis") is None


def _ctx(root):
    return pipeline.Ctx(scan_id=1, repo="acme/shop", pr=FakeSCM("").get_pr("acme/shop", 7), policy=pipeline.load_policy(),
                        root=root, src=root / "src", runner=None, network=None, gw_key="", image="img",
                        skills_version="dev")


def test_healthy_replay_caches_envspec_for_next_scan(dyn):
    s = dyn()
    pipeline.run_scan(ROW)
    cached = dynamic_mod._profile_path("acme/shop")
    assert cached == settings().work_root / "profiles" / "acme__shop.envspec.json"
    assert json.loads(cached.read_text())["env"] == {"SECRET_KEY": "x"}
    s2 = dyn()
    pipeline.run_scan({**ROW, "id": 102})
    prev = json.loads(s2["runner"].inputs["102-env"]["previous_envspec.json"])
    assert prev["env"] == {"SECRET_KEY": "x"}
    env_task = next(sp.task for sp in s2["runner"].specs if sp.task.stage == Stage.env)
    assert "previous_envspec.json" in env_task.context_files


def test_superseded_during_dynamic_stops_the_scan(dyn, monkeypatch):
    q = FakeQueue()
    s = dyn(q=q)
    real = dynamic_mod._replay

    def supersede_then_replay(*a, **kw):
        q.superseded_after = 0
        return real(*a, **kw)

    monkeypatch.setattr(dynamic_mod, "_replay", supersede_then_replay)
    pipeline.run_scan(ROW)
    assert only(q)["status"] == ScanStatus.superseded
    assert not s["sink"].calls


# ------------------------------------------------------------- review fixes


def test_seed_dir_skips_scripts(tmp_path):
    st = dynamic_mod._State(ctx=_ctx(tmp_path), spec=dynamic_mod.EnvSpec.model_validate(ENVSPEC))
    (tmp_path / "src").mkdir()
    for name in ("init.sh", "seed.js", "schema.sql", "data.sql.gz"):
        (tmp_path / "src" / name).write_text("x")
    out = dynamic_mod._seed_dir(st, tmp_path / "src", "h1", "db", ["init.sh", "seed.js", "schema.sql", "data.sql.gz"],
                                "postgres")
    assert sorted(p.name for p in Path(out).iterdir()) == ["02-schema.sql", "03-data.sql.gz"]


def test_unhealthy_service_in_a_replay_env_is_env_failed(dyn):
    s = dyn()
    s["runner"].health = lambda name: {"db": "unhealthy: container exited"} if "r" in name else {"db": "healthy"}
    pipeline.run_scan(ROW)
    ev = evidence(finding(s))
    assert ev.outcome == "env_failed"
    assert "unhealthy" in ev.reason
    assert s["runner"].replays == []
    assert "h1r1" in s["runner"].destroyed_envs


def test_create_env_failure_destroys_the_env(dyn):
    s = dyn(create_error=lambda name: name == "h1r1")
    pipeline.run_scan(ROW)
    assert s["runner"].destroyed_envs.count("h1r1") == 2  # first try and the retry


def test_transient_env_failure_on_a_head_replay_is_retried(dyn):
    s = dyn(replay=lambda req, spec: None if req.run_id.endswith("-r2") else not req.run_id.endswith("-base"))
    pipeline.run_scan(ROW)
    ev = evidence(finding(s))
    assert ev.outcome == "reproduced"
    assert [r.run_id for r in ev.replays] == ["101-replay-H1-r1", "101-replay-H1-r2-retry", "101-replay-H1-base"]


def test_env_failure_on_a_later_head_replay_is_env_failed_not_not_reproduced(dyn):
    s = dyn(replay=lambda req, spec: None if "-r2" in req.run_id else True)
    pipeline.run_scan(ROW)
    ev = evidence(finding(s))
    assert ev.outcome == "env_failed"
    assert (ev.head_runs, ev.head_fired) == (1, 1)


def test_incomplete_base_run_leaves_introduced_unknown(dyn):
    def replay(req, spec):
        if req.run_id.endswith("-base"):
            return ReplayResult(run_id=req.run_id, env_ok=True, fired=False, aborted="request failed: ConnectError",
                                incomplete=True)
        return True

    s = dyn(replay=replay)
    pipeline.run_scan(ROW)
    fd = finding(s)
    assert fd.introduced is None
    assert evidence(fd).base_fired is None


def test_clean_abort_on_base_counts_as_not_fired(dyn):
    def replay(req, spec):
        if req.run_id.endswith("-base"):
            return ReplayResult(run_id=req.run_id, env_ok=True, fired=False, aborted="expected status [200], got 404")
        return True

    s = dyn(replay=replay)
    pipeline.run_scan(ROW)
    assert finding(s).introduced is True


def test_replay_wall_clock_covers_install_and_health(dyn):
    s = dyn()
    pipeline.run_scan(ROW)
    req, spec = s["runner"].replays[0]
    expected = req.envspec.install_timeout_s + req.envspec.health.timeout_s + req.timeout_s
    assert spec.task.limits.wall_clock_s == expected


def test_replay_dirs_are_freed_after_each_replay(dyn):
    leftovers: list[bool] = []

    def replay(req, spec):
        leftovers.append((spec.app_dir.parent / "h1r1").exists() and not spec.app_dir.name == "h1r1")
        return not req.run_id.endswith("-base")

    dyn(replay=replay)
    pipeline.run_scan(ROW)
    assert leftovers == [False, False, False]


def test_env_names_carry_a_lease_tag(tmp_path):
    ctx = _ctx(tmp_path)
    ctx.lease_token = "tok-123456789abcdef"
    st = dynamic_mod._State(ctx=ctx, spec=dynamic_mod.EnvSpec.model_validate(ENVSPEC))
    other = dynamic_mod._State(ctx=_ctx(tmp_path), spec=st.spec)
    other.ctx.lease_token = "tok-other"
    name = dynamic_mod._env_name(st, "h12r2")
    assert name.startswith("h12r2")
    assert name != dynamic_mod._env_name(other, "h12r2")
    from prsec.dynamic.results import ENV_NAME
    assert ENV_NAME.fullmatch(name)

"""Scan instrumentation: timeline events in order, live agent stream, bound log context, keep-for-debugging."""
import json
import threading
import time

from prsec.config import settings
from prsec.models import ScanStatus
from prsec.obs.logging import get_context
from prsec.orchestrator import pipeline

from .test_dynamic import EnvRunner, dyn, dyn_script  # noqa: F401  (fixture)
from .test_pipeline import ROW, FakeQueue, FakeRunner, env, full_script, hyp, only  # noqa: F401  (fixture)

STATIC_SCAN = [
    "scan_started", "rules",
    "stage_started", "stage_finished", "triage",
    "stage_started", "stage_finished", "hypotheses",
    "stage_started", "stage_finished", "static_verdict",
    "stage_started", "stage_finished", "skeptic",
    "dynamic_outcome", "dynamic_outcome",  # candidates, then H1 skipped (the fake runner has no envs)
    "label", "env_destroyed", "scan_finished",
]


def no_agent(kinds):
    return [k for k in kinds if k != "agent"]


class KeepQueue(FakeQueue):
    """FakeQueue that also records keep(); the fixture only patches FakeQueue's functions."""

    def __init__(self, monkeypatch, ok=True):
        super().__init__()
        self.kept: list[tuple] = []
        self.ok = ok
        monkeypatch.setattr(pipeline.queue, "keep", self.keep)

    def keep(self, scan_id, minutes, kept_dir, lease_token=None):
        self.kept.append((scan_id, minutes, kept_dir, lease_token))
        return self.ok


def test_full_scan_timeline_in_order(env, timeline):
    env(script=full_script())
    pipeline.run_scan(ROW)
    assert no_agent(timeline.kinds()) == STATIC_SCAN
    assert {r["scan_id"] for r in timeline.rows} == {101}


def test_scan_started_and_finished_messages(env, timeline):
    env(script=full_script())
    pipeline.run_scan({**ROW, "reason": "synchronize"})
    started = timeline.of("scan_started")[0]
    assert started["message"] == "scan of acme/shop#7 at hhhhhhhhhhhh (synchronize, attempt 1)"
    assert started["data"]["head_sha"] == "h" * 40
    finished = timeline.of("scan_finished")[0]
    assert finished["message"].startswith("scan done in ")
    assert finished["message"].endswith(", 1 finding(s)")
    assert finished["data"]["status"] == "done"


def test_stage_events_carry_harness_model_status_and_cost(env, timeline):
    env(script=full_script())
    pipeline.run_scan(ROW)
    started = timeline.of("stage_started")[0]
    assert started["task_id"] == "101-triage"
    assert started["stage"] == "triage"
    assert started["data"]["harness"]
    assert started["data"]["model"]
    finished = timeline.of("stage_finished")[0]
    assert finished["message"].startswith("triage ok in ")
    assert "$0.5000" in finished["message"]
    assert finished["data"]["usd"] == 0.5
    assert finished["level"] == "info"


def test_failed_stage_is_a_warning(env, timeline):
    script = full_script()
    script["hypothesise"] = lambda t: pipeline.StageStatus.timeout
    env(script=script)
    pipeline.run_scan(ROW)
    hyp_done = [r for r in timeline.of("stage_finished") if r["stage"] == "hypothesise"][0]
    assert hyp_done["level"] == "warning"
    assert hyp_done["data"]["status"] == "timeout"
    assert "incomplete" in timeline.of("error")[0]["message"]
    assert timeline.of("scan_finished")[0]["level"] == "error"


def test_dropped_hypotheses_say_why(env, timeline):
    bad = hyp("H2", sink={"file": "app/orders.py", "line": 5, "quote": "cursor.execute(raw_sql)"})
    low = hyp("H3", severity="info")
    env(script=full_script(hyps=[hyp(), bad, low]))
    pipeline.run_scan(ROW)
    dropped = {r["hypothesis_id"]: r["message"] for r in timeline.of("hypothesis_dropped")}
    assert dropped["H2"].startswith("H2 dropped: its citations do not match the code at head")
    assert dropped["H3"] == "H3 dropped: severity guess below the static-verify floor"
    assert timeline.of("hypotheses")[0]["data"]["to_verify"] == ["H1"]


def test_refuted_static_verdict_and_label(env, timeline):
    from .test_pipeline import static

    env(script=full_script(static_fn=lambda t: static(verdict="refuted")))
    pipeline.run_scan(ROW)
    assert timeline.of("static_verdict")[0]["message"].startswith("H1: refuted")
    assert timeline.of("hypothesis_dropped")[0]["message"] == "H1 dropped: static verification refuted it"
    assert timeline.of("label") == []


def test_rules_skip_is_explained(env, timeline):
    from .test_pipeline import CSS_DIFF

    env(diff=CSS_DIFF)
    pipeline.run_scan(ROW)
    assert timeline.kinds() == ["scan_started", "rules", "scan_finished"]
    assert timeline.of("rules")[0]["message"].startswith("rules: skip (noise_only:")
    assert timeline.of("scan_finished")[0]["message"].startswith("scan skipped in ")


def test_scan_crash_emits_error(env, timeline, monkeypatch):
    s = env(script=full_script())
    monkeypatch.setattr(pipeline.triage_rules, "classify", lambda *a: (_ for _ in ()).throw(RuntimeError("boom")))
    pipeline.run_scan(ROW)
    assert only(s["q"])["status"] == ScanStatus.failed
    assert timeline.of("error")[0]["message"] == "scan failed: RuntimeError: boom"
    assert timeline.kinds()[-1] == "scan_finished"


def test_superseded_reason_reaches_the_timeline_not_the_queue(env, timeline):
    q = FakeQueue(superseded_after=2)
    env(script=full_script(), q=q)
    pipeline.run_scan(ROW)
    assert only(q)["status"] == ScanStatus.superseded
    assert timeline.of("scan_finished")[0]["message"].endswith(": a newer head of the PR was queued")


def test_lease_lost_is_reported_as_abandoned(env, timeline):
    q = FakeQueue(lease_lost_after=1)
    env(script=full_script(), q=q)
    pipeline.run_scan({**ROW, "lease_token": "tok-123456789abcdef"})
    finished = timeline.of("scan_finished")[0]
    assert finished["message"].startswith("abandoned after")
    assert finished["level"] == "warning"


def test_dynamic_timeline(dyn, timeline):
    dyn(replay=lambda req, spec: not req.run_id.endswith("-base"))
    pipeline.run_scan(ROW)
    kinds = no_agent(timeline.kinds())
    dyn_part = kinds[kinds.index("skeptic") + 1:kinds.index("label")]
    assert dyn_part == [
        "dynamic_outcome",
        "stage_started", "stage_finished",  # env
        "env_created", "stage_started", "stage_finished", "env_destroyed",  # dynamic stage in h1
        "env_created", "env_destroyed", "replay",  # r1
        "env_created", "env_destroyed", "replay",  # r2
        "env_created", "env_destroyed", "replay",  # base
        "dynamic_outcome",
    ]
    replays = [r["message"] for r in timeline.of("replay")]
    assert replays[0] == "replay 101-replay-H1-r1 on head: fired; oracles passed 0/0"
    assert replays[2] == "replay 101-replay-H1-base on base: did not fire; oracles passed 0/0"
    outcome = timeline.of("dynamic_outcome")[-1]
    assert outcome["message"] == "H1: reproduced (replay_confirmed); head fired 2/2; base did not fire"
    assert outcome["hypothesis_id"] == "H1"
    assert timeline.of("label")[0]["message"] == "H1 labelled reproduced: replay_confirmed"


def test_replay_lists_passed_oracles(dyn, timeline):
    from prsec.dynamic.results import OracleResult, ReplayResult

    def replay(req, spec):
        return ReplayResult(run_id=req.run_id, env_ok=True, fired=True, entry="http", oracle_results=[
            OracleResult(index=0, type="response_contains", passed=True),
            OracleResult(index=1, type="sink_hit", passed=False)])

    dyn(replay=replay)
    pipeline.run_scan(ROW)
    msg = timeline.of("replay")[0]["message"]
    assert msg.endswith("fired; oracles passed 1/2 (response_contains#0)")
    assert timeline.of("replay")[0]["data"]["oracles"][1]["passed"] is False


def test_unhealthy_env_is_reported_with_service_health(dyn, timeline):
    s = dyn()
    s["runner"].health = lambda env_name: {"db": "unhealthy: no pg_isready"}
    pipeline.run_scan(ROW)
    created = timeline.of("env_created")[0]
    assert created["message"] == "env h1 unusable: db unhealthy: no pg_isready"
    assert created["level"] == "warning"
    assert created["data"]["ok"] is False


# ------------------------------------------------------------ live agent stream


class StreamingRunner(FakeRunner):
    """Writes the stage's events.jsonl like prsec-stage does."""

    def __init__(self, script, lines, **kw):
        super().__init__(script, **kw)
        self.lines = lines

    def run_workbench(self, spec):
        with (spec.out_dir / "events.jsonl").open("w") as f:
            for line in self.lines(spec.task):
                f.write(line + "\n")
        return super().run_workbench(spec)


def test_agent_events_are_relayed_with_the_stage(env, timeline, monkeypatch):
    lines = lambda t: [json.dumps({"kind": "message", "text": f"looking at {t.stage.value}"}),  # noqa: E731
                       json.dumps({"kind": "tool_call", "tool": "Read", "data": {"path": "app/orders.py"}}),
                       "not json", "[1, 2]"]
    s = env(script=full_script())
    runner = StreamingRunner(full_script(), lines, events=s["q"].events)
    monkeypatch.setattr(pipeline.runner_pkg, "get_runner", lambda name: runner, raising=False)
    pipeline.run_scan(ROW)
    triage_agent = [r for r in timeline.of("agent") if r["task_id"] == "101-triage"]
    assert [r["message"] for r in triage_agent] == [
        "message: looking at triage", 'tool_call Read: {"path": "app/orders.py"}']
    assert triage_agent[0]["stage"] == "triage"
    kinds = timeline.kinds()
    assert kinds.index("agent") < kinds.index("stage_finished")


def test_agent_text_is_truncated(env, timeline, monkeypatch):
    lines = lambda t: [json.dumps({"kind": "message", "text": "x" * 5000})]  # noqa: E731
    s = env(script=full_script(hyps=[]))
    runner = StreamingRunner(full_script(hyps=[]), lines, events=s["q"].events)
    monkeypatch.setattr(pipeline.runner_pkg, "get_runner", lambda name: runner, raising=False)
    pipeline.run_scan(ROW)
    agent = timeline.of("agent")[0]
    assert len(agent["data"]["text"]) == pipeline.AGENT_TEXT_MAX
    assert len(agent["message"]) <= 2000


def test_agent_stream_is_live_and_batched(tmp_path, timeline):
    out = tmp_path / "out"
    out.mkdir()
    with pipeline._AgentStream(5, out, flush_s=0.05):
        with (out / "events.jsonl").open("w") as f:
            f.write(json.dumps({"kind": "message", "text": "one"}) + "\n")
            f.flush()
            deadline = time.monotonic() + 5
            while not timeline.of("agent") and time.monotonic() < deadline:
                time.sleep(0.01)
            seen_while_running = [r["message"] for r in timeline.of("agent")]
            f.write(json.dumps({"kind": "error", "text": "two"}) + "\n")
            f.write('{"kind": "message", "text": "par')  # incomplete line: not yet an event
    assert seen_while_running == ["message: one"]
    assert [r["message"] for r in timeline.of("agent")] == ["message: one", "error: two"]
    assert timeline.of("agent")[1]["level"] == "warning"


def test_agent_stream_summarises_a_burst(tmp_path, timeline, monkeypatch):
    monkeypatch.setattr(pipeline, "AGENT_BATCH_MAX", 3)
    out = tmp_path / "out"
    out.mkdir()
    (out / "events.jsonl").write_text("".join(json.dumps({"kind": "message", "text": str(i)}) + "\n"
                                              for i in range(5)))
    with pipeline._AgentStream(5, out, flush_s=60):
        pass
    msgs = [r["message"] for r in timeline.of("agent")]
    assert len(msgs) == 4
    assert msgs[-1].startswith("2 more agent events")


def test_agent_stream_ignores_a_symlinked_events_file(tmp_path, timeline):
    secret = tmp_path / "secret.jsonl"
    secret.write_text(json.dumps({"kind": "message", "text": "host file"}) + "\n")
    out = tmp_path / "out"
    out.mkdir()
    (out / "events.jsonl").symlink_to(secret)
    with pipeline._AgentStream(5, out, flush_s=60):
        pass
    assert timeline.of("agent") == []


# ------------------------------------------------------------ bound log context


class ContextRunner(FakeRunner):
    def __init__(self, script, **kw):
        super().__init__(script, **kw)
        self.contexts: dict[str, dict] = {}
        self.lock = threading.Lock()

    def run_workbench(self, spec):
        with self.lock:
            self.contexts[spec.task.task_id] = get_context()
        return super().run_workbench(spec)


def test_stages_run_in_a_bound_log_context(env, monkeypatch):
    s = env(script=full_script())
    runner = ContextRunner(full_script(), events=s["q"].events)
    monkeypatch.setattr(pipeline.runner_pkg, "get_runner", lambda name: runner, raising=False)
    pipeline.run_scan({**ROW, "debug": {"log_level": "debug", "keep_minutes": 0}})
    triage = runner.contexts["101-triage"]
    assert triage == {"scan_id": 101, "debug": True, "task_id": "101-triage", "stage": "triage"}
    sv = runner.contexts["101-static_verify-H1"]  # ran in a pool thread
    assert sv["hypothesis_id"] == "H1"
    assert sv["scan_id"] == 101
    assert get_context() == {}


def test_debug_is_not_bound_without_debug_options(env, monkeypatch):
    s = env(script=full_script(hyps=[]))
    runner = ContextRunner(full_script(hyps=[]), events=s["q"].events)
    monkeypatch.setattr(pipeline.runner_pkg, "get_runner", lambda name: runner, raising=False)
    pipeline.run_scan(ROW)
    assert "debug" not in runner.contexts["101-triage"]


def test_dynamic_env_name_is_bound(dyn, monkeypatch):
    s = dyn()
    contexts = {}
    orig = s["runner"].run_workbench

    def run_workbench(spec):
        contexts[spec.task.task_id] = get_context()
        return orig(spec)

    monkeypatch.setattr(s["runner"], "run_workbench", run_workbench)
    pipeline.run_scan(ROW)
    assert contexts["101-dynamic-H1"]["env"] == "h1"
    assert contexts["101-dynamic-H1"]["hypothesis_id"] == "H1"


# ------------------------------------------------------------ keep-for-debugging


KEEP = {"log_level": "info", "keep_minutes": 30}


def test_keep_leaves_containers_and_work_dir(env, timeline, monkeypatch):
    q = KeepQueue(monkeypatch)
    s = env(script=full_script(), q=q)
    pipeline.run_scan({**ROW, "lease_token": "tok-123456789abcdef", "debug": KEEP})
    work = settings().work_root / "101-tok-12345678"
    assert only(q)["status"] == ScanStatus.done
    assert q.kept == [(101, 30, str(work), "tok-123456789abcdef")]
    assert s["runner"].destroyed == []
    assert work.is_dir()
    assert s["revoked"] == ["sk-scan"]  # the gateway key is never kept
    kept = timeline.of("kept")[0]
    assert kept["message"].startswith("kept for 30 min for debugging")
    assert timeline.of("env_destroyed") == []


def test_keep_not_recorded_cleans_up_as_usual(env, timeline, monkeypatch):
    q = KeepQueue(monkeypatch, ok=False)  # e.g. the lease moved on meanwhile
    s = env(script=full_script(hyps=[]), q=q)
    pipeline.run_scan({**ROW, "debug": KEEP})
    assert s["runner"].destroyed == [101]
    assert not (settings().work_root / "101").exists()
    assert timeline.of("kept") == []


def test_keep_before_anything_was_allocated_is_a_no_op(env, timeline, monkeypatch):
    from .test_pipeline import CSS_DIFF

    q = KeepQueue(monkeypatch)
    env(diff=CSS_DIFF, q=q)
    pipeline.run_scan({**ROW, "debug": KEEP})
    assert q.kept == []


def test_lease_lost_never_keeps(env, monkeypatch):
    q = KeepQueue(monkeypatch)
    q.lease_lost_after = 1
    env(script=full_script(), q=q)
    pipeline.run_scan({**ROW, "lease_token": "tok-123456789abcdef", "debug": KEEP})
    assert q.kept == []


def test_invalid_debug_options_are_ignored(env, timeline, monkeypatch):
    q = KeepQueue(monkeypatch)
    s = env(script=full_script(hyps=[]), q=q)
    pipeline.run_scan({**ROW, "debug": {"keep_minutes": -5}})
    assert q.kept == []
    assert s["runner"].destroyed == [101]


def test_keep_leaves_dynamic_envs_up(dyn, timeline, monkeypatch):
    q = KeepQueue(monkeypatch)
    s = dyn(q=q, replay=lambda req, spec: not req.run_id.endswith("-base"))
    pipeline.run_scan({**ROW, "debug": KEEP})
    assert s["runner"].destroyed_envs == []
    assert s["runner"].destroyed == []
    assert (settings().work_root / "101" / "app" / "h1").is_dir()
    left = [r["data"]["env"] for r in timeline.of("env_destroyed")]
    assert left == ["h1", "h1r1", "h1r2", "h1b"]
    assert all(r["data"]["kept"] for r in timeline.of("env_destroyed"))


def test_keep_destroys_a_kept_env_before_reusing_its_name(dyn, monkeypatch):
    q = KeepQueue(monkeypatch)
    calls = {"n": 0}

    def replay(req, spec):
        calls["n"] += 1
        return None if calls["n"] == 1 else True  # first head replay's env fails: retried in the same env name

    s = dyn(q=q, replay=replay)
    pipeline.run_scan({**ROW, "debug": KEEP})
    assert s["runner"].destroyed_envs == ["h1r1"]


def test_scan_finished_is_written_before_the_status_turns_final(env, timeline, monkeypatch):
    q = FakeQueue()
    env(script=full_script(hyps=[]), q=q)
    monkeypatch.setattr(pipeline.timeline, "_insert", lambda row: q.events.append(row["kind"]))
    pipeline.run_scan(ROW)
    assert q.events[-2:] == ["scan_finished", "finish"]


def test_revived_kept_scan_tears_down_the_previous_keep_first(env, timeline, monkeypatch):
    q = KeepQueue(monkeypatch)
    s = env(script=full_script(hyps=[]), q=q)
    old = settings().work_root / "101-old"
    old.mkdir(parents=True)
    released = []
    monkeypatch.setattr(pipeline.queue, "release_kept",
                        lambda scan_id, lease_token=None: released.append(scan_id) or {"id": scan_id, "kept_dir": str(old)},
                        raising=False)
    pipeline.run_scan({**ROW, "keep_until": "2026-10-27T12:00:00Z"})
    assert released == [101]
    assert not old.exists()
    assert s["runner"].destroyed == [101, 101]  # the old keep, then this run's own cleanup
    assert timeline.of("env_destroyed")[0]["message"].startswith("a new run started")


def test_debug_scan_runs_its_stages_at_debug_log_level(env, monkeypatch):
    monkeypatch.setenv("PRSEC_LOG_LEVEL", "INFO")
    s = env(script=full_script(hyps=[]))
    pipeline.run_scan({**ROW, "debug": {"log_level": "debug", "keep_minutes": 0}})
    assert {sp.env["PRSEC_LOG_LEVEL"] for sp in s["runner"].specs} == {"DEBUG"}


def test_normal_scan_passes_the_worker_log_level(env, monkeypatch):
    monkeypatch.setenv("PRSEC_LOG_LEVEL", "INFO")
    s = env(script=full_script(hyps=[]))
    pipeline.run_scan(ROW)
    assert {sp.env["PRSEC_LOG_LEVEL"] for sp in s["runner"].specs} == {"INFO"}

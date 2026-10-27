import threading

from prsec.adapters import scm as scm_pkg
from prsec.config import load_policy, settings
from prsec.models import PRInfo
from prsec.orchestrator import reconciler, worker


def _pr(repo, n, sha, draft=False, fork=False):
    return PRInfo(repo=repo, number=n, title="t", base_ref="main", base_sha="b", head_ref="f", head_sha=sha,
                  draft=draft, is_fork=fork)


def test_reconcile_once(monkeypatch):
    prs = [_pr("a/x", 1, "s1"), _pr("a/x", 2, "s2"), _pr("a/x", 3, "s3", draft=True), _pr("a/x", 4, "s4", fork=True)]

    class SCM:
        def list_open_prs(self, installation_id=None):
            return prs

    monkeypatch.setattr(scm_pkg, "get_scm", lambda name="github": SCM())
    monkeypatch.setattr(reconciler.queue, "known_head", lambda repo, pr, sha, sv: pr == 1)
    enq = []
    monkeypatch.setattr(reconciler.queue, "enqueue", lambda req, sv, d, m: enq.append((req, sv, d, m)) or len(enq))
    policy = load_policy().model_copy(update={"scan_drafts": False, "scan_forks": False})
    assert reconciler.reconcile_once(policy=policy) == [1]
    req, sv, d, m = enq[0]
    assert (req.repo, req.pr, req.head_sha, req.reason) == ("a/x", 2, "s2", "reconcile")
    assert (sv, d, m) == (settings().skills_version, settings().debounce_s, settings().max_supersedes)

    enq.clear()
    policy = policy.model_copy(update={"scan_drafts": True, "scan_forks": True})
    reconciler.reconcile_once(policy=policy)
    assert [r.pr for r, *_ in enq] == [2, 3, 4]


def test_run_one_heartbeats(monkeypatch):
    beats = []
    monkeypatch.setattr(worker.queue, "lease_next", lambda lease_s: {"id": 9, "lease_token": "tok"})
    monkeypatch.setattr(worker.queue, "heartbeat", lambda sid, lease_s, token: beats.append((sid, token)) or True)
    ran = threading.Event()

    def run_scan(row):
        assert row["id"] == 9
        threading.Event().wait(0.2)
        ran.set()

    monkeypatch.setattr(worker.pipeline, "run_scan", run_scan)
    assert worker.run_one(lease_s=30, heartbeat_s=0.03)
    assert ran.is_set()
    assert beats
    assert set(beats) == {(9, "tok")}


def test_heartbeat_stops_once_lease_is_lost(monkeypatch):
    beats = []
    monkeypatch.setattr(worker.queue, "lease_next", lambda lease_s: {"id": 9, "lease_token": "tok"})
    monkeypatch.setattr(worker.queue, "heartbeat", lambda sid, lease_s, token: beats.append(sid) and False)
    monkeypatch.setattr(worker.pipeline, "run_scan", lambda row: threading.Event().wait(0.25))
    assert worker.run_one(lease_s=30, heartbeat_s=0.03)
    assert len(beats) == 1


def test_run_one_nothing_due(monkeypatch):
    monkeypatch.setattr(worker.queue, "lease_next", lambda lease_s: None)
    assert worker.run_one() is False


def test_serve_stops(monkeypatch):
    calls = {"requeue": 0}
    stop = threading.Event()

    def requeue():
        calls["requeue"] += 1
        if calls["requeue"] >= 3:
            stop.set()
        return 0

    monkeypatch.setattr(worker.queue, "requeue_expired_leases", requeue)
    monkeypatch.setattr(worker.queue, "lease_next", lambda lease_s: None)
    reaped = []
    monkeypatch.setattr(worker.pipeline, "reap_kept", lambda: reaped.append(1) or 0)
    worker.serve(stop, concurrency=2, poll_s=0.01, reconcile=False)
    assert calls["requeue"] >= 3
    assert reaped


def test_reap_kept_destroys_scan_and_removes_only_dirs_under_work_root(tmp_path, monkeypatch, timeline):
    from prsec.orchestrator import pipeline

    monkeypatch.setattr(settings(), "work_root", tmp_path / "work")
    kept = tmp_path / "work" / "7-abc"
    kept.mkdir(parents=True)
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    destroyed = []

    class Runner:
        name = "fake"

        def destroy_scan(self, scan_id):
            destroyed.append(scan_id)

    monkeypatch.setattr(pipeline.runner_pkg, "get_runner", lambda name: Runner(), raising=False)
    monkeypatch.setattr(pipeline.queue, "claim_due_kept",
                        lambda limit: [{"id": 7, "kept_dir": str(kept)}, {"id": 8, "kept_dir": str(outside)}])
    assert pipeline.reap_kept() == 2
    assert destroyed == [7, 8]
    assert not kept.exists()
    assert outside.exists()
    assert timeline.kinds() == ["env_destroyed", "env_destroyed"]

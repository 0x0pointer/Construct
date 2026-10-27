from __future__ import annotations

import threading

import psycopg
import pytest
from psycopg.rows import dict_row

from prsec.db import conn as db_conn
from prsec.db import queue
from prsec.models import ScanRequest, ScanStatus, Stage, StageResult, StageStatus, Usage

pytestmark = pytest.mark.db

SK = "sk-1"


def req(head: str, pr: int = 1, repo: str = "acme/api", **kw) -> ScanRequest:
    return ScanRequest(repo=repo, pr=pr, head_sha=head, base_sha="base", installation_id=5, **kw)


def row(sql, scan_id: int) -> dict:
    return sql.execute("SELECT *, not_before - now() AS delay FROM scans WHERE id = %s", (scan_id,)).fetchone()


def test_migrate_is_idempotent(dsn):
    with db_conn.get_pool().connection() as c:
        db_conn.migrate(c)
        db_conn.migrate(c)


def test_enqueue_idempotent(sql):
    a = queue.enqueue(req("h1"), SK, 0, 5)
    assert isinstance(a, int)
    assert queue.enqueue(req("h1"), SK, 0, 5) is None
    assert queue.enqueue(req("h1", reason="reconcile"), SK, 0, 5) is None
    b = queue.enqueue(req("h1"), "sk-2", 0, 5)
    assert b is not None and b != a
    assert sql.execute("SELECT count(*) AS n FROM scans").fetchone()["n"] == 2
    r = row(sql, a)
    assert (r["status"], r["installation_id"], r["base_sha"], r["skills_version"]) == ("queued", 5, "base", SK)
    assert queue.known_head("acme/api", 1, "h1", SK)
    assert not queue.known_head("acme/api", 1, "h2", SK)


def test_debounce_sets_not_before(sql):
    a = queue.enqueue(req("h1"), SK, 120, 5)
    delay = row(sql, a)["delay"].total_seconds()
    assert 110 < delay <= 120
    assert queue.lease_next() is None


def test_newer_head_supersedes_queued_and_running(sql):
    a = queue.enqueue(req("h1"), SK, 0, 5)
    leased = queue.lease_next()
    assert leased["id"] == a
    b = queue.enqueue(req("h2"), SK, 0, 5)
    assert row(sql, a)["status"] == "superseded"
    assert queue.is_superseded(a)
    c = queue.enqueue(req("h3"), SK, 0, 5)
    assert row(sql, b)["status"] == "superseded"
    assert row(sql, c)["status"] == "queued"
    assert not queue.is_superseded(c)
    assert not queue.heartbeat(a, 600)


def test_supersede_scoped_to_pr(sql):
    a = queue.enqueue(req("h1", pr=1), SK, 0, 5)
    b = queue.enqueue(req("h1", pr=2), SK, 0, 5)
    c = queue.enqueue(req("h1", repo="acme/web"), SK, 0, 5)
    queue.enqueue(req("h2", pr=1), SK, 0, 5)
    assert [row(sql, i)["status"] for i in (a, b, c)] == ["superseded", "queued", "queued"]


def test_done_scans_not_superseded(sql):
    a = queue.enqueue(req("h1"), SK, 0, 5)
    queue.lease_next()
    queue.finish(a, ScanStatus.done)
    b = queue.enqueue(req("h2"), SK, 60, 5)
    assert row(sql, a)["status"] == "done"
    assert row(sql, b)["supersede_count"] == 0


def test_supersede_count_inheritance_and_anti_starvation(sql):
    ids = [queue.enqueue(req(f"h{i}"), SK, 300, 3) for i in range(5)]
    counts = [row(sql, i)["supersede_count"] for i in ids]
    assert counts == [0, 1, 2, 3, 4]
    delays = [row(sql, i)["delay"].total_seconds() for i in ids]
    assert all(d > 290 for d in delays[:3])
    assert all(d <= 0 for d in delays[3:])
    assert queue.lease_next()["id"] == ids[-1]


def test_superseded_head_revived_on_force_push_back(sql):
    a = queue.enqueue(req("h1"), SK, 0, 5)
    b = queue.enqueue(req("h2"), SK, 0, 5)
    assert not queue.known_head("acme/api", 1, "h1", SK)
    again = queue.enqueue(req("h1", reason="synchronize"), SK, 0, 5)
    assert again == a
    r = row(sql, a)
    assert (r["status"], r["supersede_count"], r["reason"]) == ("queued", 2, "synchronize")
    assert row(sql, b)["status"] == "superseded"


def test_lease_sets_running(sql):
    a = queue.enqueue(req("h1"), SK, 0, 5)
    r = queue.lease_next(lease_s=300)
    assert r["id"] == a and r["status"] == "running" and r["attempts"] == 1
    assert r["started_at"] is not None and r["repo"] == "acme/api"
    assert 290 < (r["lease_until"] - r["started_at"]).total_seconds() <= 300
    assert queue.lease_next() is None


def test_lease_skip_locked_with_concurrent_connections(sql, dsn):
    a = queue.enqueue(req("h1", pr=1), SK, 0, 5)
    b = queue.enqueue(req("h1", pr=2), SK, 0, 5)
    with psycopg.connect(dsn, row_factory=dict_row) as holder:
        first = queue._lease(holder, 600)  # transaction left open: row a stays locked
        assert first["id"] == a
        second = queue.lease_next()
        assert second["id"] == b
        assert queue.lease_next() is None
        holder.rollback()
    assert queue.lease_next()["id"] == a


def test_parallel_leases_are_disjoint(sql):
    ids = {queue.enqueue(req("h", pr=i), SK, 0, 5) for i in range(12)}
    got: list[int] = []
    lock = threading.Lock()
    barrier = threading.Barrier(4)

    def worker():
        barrier.wait()
        while (r := queue.lease_next()) is not None:
            with lock:
                got.append(r["id"])

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(got) == sorted(ids)


def test_expired_lease_requeue(sql):
    a = queue.enqueue(req("h1", pr=1), SK, 0, 5)
    b = queue.enqueue(req("h1", pr=2), SK, 0, 5)
    queue.lease_next()
    queue.lease_next()
    sql.execute("UPDATE scans SET lease_until = now() - interval '1 second' WHERE id = %s", (a,))
    assert queue.requeue_expired_leases() == 1
    assert row(sql, a)["status"] == "queued" and row(sql, a)["lease_until"] is None
    assert row(sql, b)["status"] == "running"
    again = queue.lease_next()
    assert again["id"] == a and again["attempts"] == 2


def test_expired_lease_fails_after_max_attempts(sql):
    a = queue.enqueue(req("h1"), SK, 0, 5)
    queue.lease_next()
    sql.execute("UPDATE scans SET attempts = 3, lease_until = now() - interval '1 second' WHERE id = %s", (a,))
    assert queue.requeue_expired_leases(max_attempts=3) == 0
    r = row(sql, a)
    assert r["status"] == "failed" and "lease expired" in r["error"]


def test_heartbeat_extends_lease(sql):
    a = queue.enqueue(req("h1"), SK, 0, 5)
    queue.lease_next(lease_s=1)
    assert queue.heartbeat(a, 900)
    assert row(sql, a)["lease_until"] > sql.execute("SELECT now() + interval '800 seconds' AS t").fetchone()["t"]
    assert queue.requeue_expired_leases() == 0


def test_finish_add_cost_and_stage_runs(sql):
    a = queue.enqueue(req("h1"), SK, 0, 5)
    queue.lease_next()
    queue.add_cost(a, 0.25)
    queue.add_cost(a, 1.5)
    res = StageResult(
        task_id=f"{a}-triage", stage=Stage.triage, status=StageStatus.ok, output={"decision": "full"},
        usage=Usage(tokens_in=10, usd=0.25), harness="raw", model="agent-small", duration_s=1.5,
    )
    queue.record_stage_run(a, res, None)
    queue.record_stage_run(a, res.model_copy(update={"attempts": 2}), "s3://prsec/t.jsonl")
    queue.finish(a, ScanStatus.done, triage={"decision": "full"}, sarif_uri="s3://prsec/sarif/x.sarif")
    r = row(sql, a)
    assert r["status"] == "done" and float(r["cost_usd"]) == 1.75
    assert r["triage"] == {"decision": "full"} and r["sarif_uri"].endswith("x.sarif")
    assert r["finished_at"] is not None and r["lease_until"] is None
    runs = sql.execute("SELECT * FROM stage_runs WHERE scan_id = %s", (a,)).fetchall()
    assert len(runs) == 1
    assert runs[0]["attempts"] == 2 and runs[0]["transcript_uri"] == "s3://prsec/t.jsonl"
    assert runs[0]["usage"]["tokens_in"] == 10 and runs[0]["output"] == {"decision": "full"}


def test_finish_keeps_superseded(sql):
    a = queue.enqueue(req("h1"), SK, 0, 5)
    queue.lease_next()
    queue.enqueue(req("h2"), SK, 0, 5)
    queue.finish(a, ScanStatus.failed, error="boom")
    r = row(sql, a)
    assert r["status"] == "superseded" and r["error"] == "boom"


def test_concurrent_enqueue_same_key(sql):
    results: list[int | None] = []
    barrier = threading.Barrier(6)

    def go():
        barrier.wait()
        results.append(queue.enqueue(req("h1"), SK, 0, 5))

    threads = [threading.Thread(target=go) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len([r for r in results if r is not None]) == 1


def test_superseded_running_scan_not_revived_until_its_run_stops(sql):
    a = queue.enqueue(req("h1"), SK, 0, 5)
    lease = queue.lease_next()
    queue.enqueue(req("h2"), SK, 0, 5)  # supersedes a while its worker is still running
    assert row(sql, a)["status"] == "superseded"
    assert queue.known_head("acme/api", 1, "h1", SK)
    assert queue.enqueue(req("h1"), SK, 0, 5) is None  # old run still holds its lease
    assert queue.finish(a, ScanStatus.superseded, lease_token=lease["lease_token"])
    assert not queue.known_head("acme/api", 1, "h1", SK)
    assert queue.enqueue(req("h1"), SK, 0, 5) == a
    r = row(sql, a)
    assert (r["status"], r["attempts"], r["lease_token"]) == ("queued", 0, None)


def test_superseded_row_revivable_after_abandoned_lease_expires(sql):
    a = queue.enqueue(req("h1"), SK, 0, 5)
    queue.lease_next()
    queue.enqueue(req("h2"), SK, 0, 5)
    sql.execute("UPDATE scans SET lease_until = now() - interval '1 second' WHERE id = %s", (a,))
    assert queue.enqueue(req("h1"), SK, 0, 5) == a


def test_stale_lease_holder_cannot_write(sql):
    a = queue.enqueue(req("h1"), SK, 0, 5)
    first = queue.lease_next()
    sql.execute("UPDATE scans SET lease_until = now() - interval '1 second' WHERE id = %s", (a,))
    assert queue.requeue_expired_leases() == 1
    second = queue.lease_next()
    assert second["id"] == a and second["lease_token"] != first["lease_token"]
    assert not queue.owns_lease(a, first["lease_token"]) and queue.owns_lease(a, second["lease_token"])
    assert not queue.heartbeat(a, 600, first["lease_token"])
    assert queue.heartbeat(a, 600, second["lease_token"])
    res = StageResult(task_id=f"{a}-triage", stage=Stage.triage, status=StageStatus.ok, harness="raw", model="m")
    queue.record_stage_run(a, res, None, lease_token=first["lease_token"])
    assert sql.execute("SELECT count(*) AS n FROM stage_runs").fetchone()["n"] == 0
    assert not queue.finish(a, ScanStatus.failed, error="stale", lease_token=first["lease_token"])
    assert row(sql, a)["status"] == "running"
    queue.record_stage_run(a, res, None, lease_token=second["lease_token"])
    assert sql.execute("SELECT count(*) AS n FROM stage_runs").fetchone()["n"] == 1
    assert queue.finish(a, ScanStatus.done, lease_token=second["lease_token"])
    r = row(sql, a)
    assert r["status"] == "done" and r["lease_token"] is None and r["error"] is None


def test_failed_scan_retried_with_backoff_and_cap(sql):
    a = queue.enqueue(req("h1"), SK, 0, 5)
    lease = queue.lease_next()
    queue.finish(a, ScanStatus.failed, error="github 502", lease_token=lease["lease_token"])
    assert queue.known_head("acme/api", 1, "h1", SK)  # within backoff
    assert queue.enqueue(req("h1"), SK, 0, 5) is None
    for n in range(1, queue.FAILED_RETRY_MAX + 1):
        sql.execute("UPDATE scans SET finished_at = now() - interval '1 day' WHERE id = %s", (a,))
        assert not queue.known_head("acme/api", 1, "h1", SK)
        assert queue.enqueue(req("h1", reason="reconcile"), SK, 0, 5) == a
        r = row(sql, a)
        assert (r["status"], r["retries"], r["attempts"], r["error"]) == ("queued", n, 0, None)
        lease = queue.lease_next()
        queue.finish(a, ScanStatus.failed, error="again", lease_token=lease["lease_token"])
    sql.execute("UPDATE scans SET finished_at = now() - interval '30 days' WHERE id = %s", (a,))
    assert queue.known_head("acme/api", 1, "h1", SK)  # cap reached
    assert queue.enqueue(req("h1"), SK, 0, 5) is None

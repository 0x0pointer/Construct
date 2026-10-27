import pytest
from _prsec_dbutil import insert_scan, jsonb as psycopg_json
from _factories import finding

from prsec.db import findings as db

pytestmark = pytest.mark.db


def _state(pool):
    with pool.connection() as c:
        return {r[0]: (r[1], r[2], r[3]) for r in c.execute(
            "SELECT title, status, last_scan_id, label FROM findings").fetchall()}


def test_insert_then_update_preserves_triage(pg_pool):
    s1 = insert_scan(pg_pool, head_sha="1" * 40)
    f = finding()
    db.upsert_findings(s1, "acme/shop", 7, [f], {"app/orders.py"})
    [row] = db.list_findings({"repo": "acme/shop"})
    assert row["status"] == "open"
    assert row["first_scan_id"] == s1
    assert row["label"] == "likely"
    db.set_triage(row["id"], "tp", "real", actor="alice@example.com")

    s2 = insert_scan(pg_pool, head_sha="2" * 40)
    db.upsert_findings(s2, "acme/shop", 7, [finding(label="reproduced", sink=f.sink.model_copy(update={"line": 50}))], set())
    got = db.get_finding(row["id"])
    assert got["first_scan_id"] == s1
    assert got["last_scan_id"] == s2
    assert got["label"] == "reproduced"
    assert got["sink_line"] == 50
    assert got["triage_state"] == "tp"
    assert "alice@example.com" in got["triage_note"]
    assert [o["scan_id"] for o in got["occurrences"]] == [s2, s1]
    assert got["data"]["label"] == "reproduced"


def test_stale_only_when_sink_file_changed(pg_pool):
    s1 = insert_scan(pg_pool, head_sha="1" * 40)
    a = finding(symbol="a", sink_file="app/a.py")
    b = finding(symbol="b", sink_file="app/b.py")
    db.upsert_findings(s1, "acme/shop", 7, [a, b], {"app/a.py", "app/b.py"})

    s2 = insert_scan(pg_pool, head_sha="2" * 40)
    db.upsert_findings(s2, "acme/shop", 7, [], {"./app/a.py"})  # a's file changed, b's did not
    by_fp = {r["fingerprint"]: r for r in db.list_findings()}
    assert by_fp[a.fingerprint]["status"] == "stale"
    assert by_fp[b.fingerprint]["status"] == "open"  # carried over
    assert all(r["status"] != "fixed" for r in by_fp.values())

    s3 = insert_scan(pg_pool, head_sha="3" * 40)
    db.upsert_findings(s3, "acme/shop", 7, [a], {"app/a.py"})
    assert {r["fingerprint"]: r["status"] for r in db.list_findings()}[a.fingerprint] == "open"


def test_other_prs_and_repos_untouched(pg_pool):
    s1 = insert_scan(pg_pool, pr=7)
    s2 = insert_scan(pg_pool, pr=8, head_sha="c" * 40)
    s3 = insert_scan(pg_pool, repo="acme/other", pr=7)
    db.upsert_findings(s1, "acme/shop", 7, [finding(symbol="x")], set())
    db.upsert_findings(s3, "acme/other", 7, [finding(symbol="x")], set())
    db.upsert_findings(s2, "acme/shop", 8, [], {"app/orders.py"})
    assert {r["status"] for r in db.list_findings()} == {"open"}
    assert len(db.list_findings()) == 2


def test_idempotent_rescan(pg_pool):
    s1 = insert_scan(pg_pool)
    db.upsert_findings(s1, "acme/shop", 7, [finding()], {"app/orders.py"})
    db.upsert_findings(s1, "acme/shop", 7, [finding()], {"app/orders.py"})
    [row] = db.list_findings()
    assert len(db.get_finding(row["id"])["occurrences"]) == 1
    assert row["status"] == "open"


def test_set_triage_validates(pg_pool):
    with pytest.raises(ValueError):
        db.set_triage(1, "maybe", None)
    assert db.set_triage(12345, "fp", "x") is None


def test_queries_and_metrics(pg_pool):
    s1 = insert_scan(pg_pool, status="done", cost_usd=1.5, triage=psycopg_json({"decision": "full", "rationale": "touches SQL"}))
    s2 = insert_scan(pg_pool, head_sha="d" * 40, status="skipped", cost_usd=0.01)
    with pg_pool.connection() as c:
        c.execute("UPDATE scans SET started_at = now() - interval '90 seconds', finished_at = now() WHERE id = %s", (s1,))
        for h, st, usd in [("claude-code", "ok", 0.5), ("codex", "ok", 0.3), ("codex", "timeout", 0.2)]:
            c.execute(
                """INSERT INTO stage_runs (scan_id, task_id, stage, harness, model, status, usage, duration_s)
                   VALUES (%s, %s, 'hypothesise', %s, 'agent-large', %s, %s, 30)""",
                (s1, f"{s1}-{h}-{st}", h, st, psycopg_json({"usd": usd, "tokens_in": 100, "tokens_out": 10})),
            )
    db.upsert_findings(s1, "acme/shop", 7, [finding(symbol="a"), finding(symbol="b"),
                                           finding(bug_class="idor", symbol="c", label="reproduced")], set())
    rows = db.list_findings({"bug_class": "sqli"})
    db.set_triage(rows[0]["id"], "tp", None)
    db.set_triage(rows[1]["id"], "fp", None)

    scans = db.list_scans()
    assert [s["id"] for s in scans] == [s2, s1]
    s = db.get_scan(s1)
    assert s["triage_decision"] == "full"
    assert s["findings_total"] == 3
    assert s["findings_reproduced"] == 1
    assert len(s["stage_runs"]) == 3
    assert 89 <= s["duration_s"] <= 120
    assert db.list_scans({"status": "skipped"})[0]["id"] == s2
    assert db.list_findings({"label": "reproduced"})[0]["bug_class"] == "idor"
    assert db.list_findings({"triage_state": "fp", "bug_class": "sqli", "bogus": 1})[0]["id"] == rows[1]["id"]

    m = db.metrics()
    assert m["scans_by_status"]["30d"] == {"done": 1, "skipped": 1}
    assert m["skip_rate"] == 0.5
    assert m["total_cost_usd"] == 1.51
    prec = {r["key"]: r for r in m["precision_by_bug_class"]}
    assert prec["sqli"]["precision"] == 0.5
    assert prec["idor"]["precision"] is None
    harness = {r["harness"]: r for r in m["per_harness"]}
    assert harness["codex"]["runs"] == 2
    assert harness["codex"]["ok_rate"] == 0.5
    assert harness["claude-code"]["total_cost"] == 0.5
    assert {(r["stage"], r["harness"]) for r in m["per_stage_harness"]} == {("hypothesise", "claude-code"),
                                                                           ("hypothesise", "codex")}



def test_not_stale_while_another_pr_still_reports_it(pg_pool):
    shared = finding(symbol="shared", sink_file="app/a.py")
    a1 = insert_scan(pg_pool, pr=7, head_sha="1" * 40, status="done")
    db.upsert_findings(a1, "acme/shop", 7, [shared], {"app/a.py"})
    b1 = insert_scan(pg_pool, pr=8, head_sha="2" * 40, status="done")
    db.upsert_findings(b1, "acme/shop", 8, [shared], {"app/a.py"})  # last_pr -> 8
    b2 = insert_scan(pg_pool, pr=8, head_sha="3" * 40)
    db.upsert_findings(b2, "acme/shop", 8, [], {"app/a.py"})  # PR 8 no longer has it, PR 7 still does
    assert {r["fingerprint"]: r["status"] for r in db.list_findings()}[shared.fingerprint] == "open"

    a2 = insert_scan(pg_pool, pr=7, head_sha="4" * 40, status="done")  # PR 7's latest done scan drops it too
    db.upsert_findings(a2, "acme/shop", 7, [], {"app/a.py"})
    b3 = insert_scan(pg_pool, pr=8, head_sha="5" * 40)
    db.upsert_findings(b3, "acme/shop", 8, [], {"app/a.py"})
    assert {r["fingerprint"]: r["status"] for r in db.list_findings()}[shared.fingerprint] == "stale"


def test_open_findings(pg_pool):
    s1 = insert_scan(pg_pool)
    db.upsert_findings(s1, "acme/shop", 7, [finding(symbol="a", severity="low"), finding(symbol="b", severity="high")], set())
    rows = db.open_findings("acme/shop", 7)
    assert [r["severity"] for r in rows] == ["high", "low"]
    assert rows[0]["data"]["fingerprint"] == rows[0]["fingerprint"]
    assert db.open_findings("acme/shop", 8) == []

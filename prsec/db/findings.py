"""Findings index: upsert from scans, plus read/triage helpers for the dashboard.

Lifecycle (phase 1): a finding is `open` while it is reported. When a later scan of
the same PR does not report it, it becomes `stale` only if its sink file changed in
the PR diff (`scanned_files`); otherwise it is carried over as `open` (the scan may
simply not have looked there). A finding is shared by every PR that reports the same
fingerprint, so it is not marked stale while the latest done scan of another PR still
reported it. `fixed` needs positive evidence (phase 2 replay) and is never set here.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any, Iterator

from psycopg import Connection
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from prsec.models import Finding
from prsec.sarif.fingerprint import normalise_file

TRIAGE_STATES = ("new", "tp", "fp", "accepted")
FINDING_STATUSES = ("open", "stale", "fixed")
_SEVERITY_ORDER = "CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END"


def _pool():
    from prsec.db.conn import get_pool

    return get_pool()


@contextmanager
def _conn() -> Iterator[Connection]:
    with _pool().connection() as conn:
        prev = conn.row_factory
        conn.row_factory = dict_row
        try:
            yield conn
        finally:
            conn.row_factory = prev


# --------------------------------------------------------------------- write


_UPSERT = """
INSERT INTO findings (repo, fingerprint, bug_class, vuln_class, title, severity, label, introduced,
                      sink_file, sink_line, first_scan_id, last_scan_id, last_pr, status, data)
VALUES (%(repo)s, %(fingerprint)s, %(bug_class)s, %(vuln_class)s, %(title)s, %(severity)s, %(label)s,
        %(introduced)s, %(sink_file)s, %(sink_line)s, %(scan_id)s, %(scan_id)s, %(pr)s, 'open', %(data)s)
ON CONFLICT (repo, fingerprint) DO UPDATE SET
    bug_class = EXCLUDED.bug_class,
    vuln_class = EXCLUDED.vuln_class,
    title = EXCLUDED.title,
    severity = EXCLUDED.severity,
    label = EXCLUDED.label,
    introduced = COALESCE(EXCLUDED.introduced, findings.introduced),
    sink_file = EXCLUDED.sink_file,
    sink_line = EXCLUDED.sink_line,
    last_scan_id = EXCLUDED.last_scan_id,
    last_pr = EXCLUDED.last_pr,
    status = 'open',
    data = EXCLUDED.data,
    updated_at = now()
RETURNING id
"""


def upsert_findings(scan_id: int, repo: str, pr: int, findings: list[Finding], scanned_files: set[str]) -> None:
    changed = {normalise_file(p) for p in scanned_files}
    with _conn() as conn, conn.transaction():
        seen: list[int] = []
        for f in findings:
            row = conn.execute(
                _UPSERT,
                {
                    "repo": repo,
                    "fingerprint": f.fingerprint,
                    "bug_class": f.bug_class,
                    "vuln_class": f.vuln_class,
                    "title": f.title,
                    "severity": str(f.severity),
                    "label": str(f.label),
                    "introduced": f.introduced,
                    "sink_file": f.sink.file,
                    "sink_line": f.sink.line,
                    "scan_id": scan_id,
                    "pr": pr,
                    "data": Jsonb(f.model_dump(mode="json")),
                },
            ).fetchone()
            seen.append(row["id"])
            conn.execute(
                """INSERT INTO finding_occurrences (finding_id, scan_id, label) VALUES (%s, %s, %s)
                   ON CONFLICT (finding_id, scan_id) DO UPDATE SET label = EXCLUDED.label""",
                (row["id"], scan_id, str(f.label)),
            )

        candidates = conn.execute(
            """SELECT f.id, f.sink_file FROM findings f
               WHERE f.repo = %(repo)s AND f.last_pr = %(pr)s AND f.status = 'open' AND NOT (f.id = ANY(%(seen)s))
                 AND NOT EXISTS (
                     SELECT 1 FROM finding_occurrences o JOIN scans s ON s.id = o.scan_id
                     WHERE o.finding_id = f.id AND s.repo = f.repo AND s.pr <> %(pr)s
                       AND s.id = (SELECT max(s2.id) FROM scans s2
                                   WHERE s2.repo = s.repo AND s2.pr = s.pr AND s2.status = 'done'))""",
            {"repo": repo, "pr": pr, "seen": seen},
        ).fetchall()
        stale = [c["id"] for c in candidates if normalise_file(c["sink_file"]) in changed]
        if stale:
            conn.execute(
                "UPDATE findings SET status = 'stale', updated_at = now() WHERE id = ANY(%s)",
                (stale,),
            )


def open_findings(repo: str, pr: int, limit: int = 50) -> list[dict]:
    """Findings currently open for this PR (the hypothesise stage re-evaluates them)."""
    with _conn() as conn:
        return conn.execute(
            f"""SELECT f.id, f.fingerprint, f.bug_class, f.vuln_class, f.title, f.severity, f.label,
                       f.sink_file, f.sink_line, f.data
                FROM findings f WHERE f.repo = %s AND f.last_pr = %s AND f.status = 'open'
                ORDER BY {_SEVERITY_ORDER}, f.id LIMIT %s""",
            (repo, pr, limit),
        ).fetchall()


def set_triage(finding_id: int, state: str, note: str | None, actor: str | None = None) -> dict | None:
    if state not in TRIAGE_STATES:
        raise ValueError(f"invalid triage state {state!r}; expected one of {TRIAGE_STATES}")
    stamp = f"[{datetime.now(UTC):%Y-%m-%d %H:%M}Z {actor or 'unknown'} -> {state}]"
    full_note = f"{stamp} {note.strip()}" if note and note.strip() else stamp
    with _conn() as conn:
        return conn.execute(
            """UPDATE findings SET triage_state = %s, triage_note = %s, updated_at = now()
               WHERE id = %s RETURNING id, triage_state, triage_note, updated_at""",
            (state, full_note, finding_id),
        ).fetchone()


# ---------------------------------------------------------------------- read


def _where(filters: dict[str, Any] | None, allowed: dict[str, str]) -> tuple[str, list[Any]]:
    clauses, params = [], []
    for key, value in (filters or {}).items():
        if value in (None, "") or key not in allowed:
            continue
        clauses.append(f"{allowed[key]} = %s")
        params.append(value)
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", params


_SCAN_COLS = """
    s.id, s.scm, s.repo, s.pr, s.head_sha, s.base_sha, s.skills_version, s.reason, s.status,
    s.not_before, s.attempts, s.supersede_count, s.triage, s.error, s.cost_usd::float AS cost_usd,
    s.sarif_uri, s.created_at, s.started_at, s.finished_at,
    s.triage->>'decision' AS triage_decision,
    EXTRACT(EPOCH FROM (COALESCE(s.finished_at, CASE WHEN s.status = 'running' THEN now() END) - s.started_at))::float
        AS duration_s,
    COALESCE(fc.total, 0) AS findings_total,
    COALESCE(fc.reproduced, 0) AS findings_reproduced,
    COALESCE(fc.likely, 0) AS findings_likely,
    COALESCE(fc.inconclusive, 0) AS findings_inconclusive
"""
_SCAN_COUNTS = """
LEFT JOIN LATERAL (
    SELECT count(*) AS total,
           count(*) FILTER (WHERE o.label = 'reproduced') AS reproduced,
           count(*) FILTER (WHERE o.label = 'likely') AS likely,
           count(*) FILTER (WHERE o.label = 'inconclusive') AS inconclusive
    FROM finding_occurrences o WHERE o.scan_id = s.id
) fc ON true
"""
_SCAN_FILTERS = {"repo": "s.repo", "pr": "s.pr", "status": "s.status", "head_sha": "s.head_sha"}


def list_scans(filters: dict[str, Any] | None = None, limit: int = 50, offset: int = 0) -> list[dict]:
    where, params = _where(filters, _SCAN_FILTERS)
    with _conn() as conn:
        return conn.execute(
            f"SELECT {_SCAN_COLS} FROM scans s {_SCAN_COUNTS}{where} ORDER BY s.id DESC LIMIT %s OFFSET %s",
            [*params, limit, offset],
        ).fetchall()


def get_scan(scan_id: int) -> dict | None:
    with _conn() as conn:
        scan = conn.execute(f"SELECT {_SCAN_COLS} FROM scans s {_SCAN_COUNTS} WHERE s.id = %s", (scan_id,)).fetchone()
        if scan is None:
            return None
        scan["stage_runs"] = conn.execute(
            """SELECT id, task_id, stage, harness, harness_version, model, status, attempts, usage, output,
                      errors, transcript_uri, duration_s, created_at
               FROM stage_runs WHERE scan_id = %s ORDER BY id""",
            (scan_id,),
        ).fetchall()
        scan["findings"] = conn.execute(
            f"""SELECT f.id, f.fingerprint, f.bug_class, f.vuln_class, f.title, f.severity, o.label,
                       f.status, f.triage_state, f.sink_file, f.sink_line
                FROM finding_occurrences o JOIN findings f ON f.id = o.finding_id
                WHERE o.scan_id = %s ORDER BY {_SEVERITY_ORDER}, f.id""",
            (scan_id,),
        ).fetchall()
        return scan


def stage_run_transcript_uri(stage_run_id: int) -> str | None:
    with _conn() as conn:
        row = conn.execute("SELECT transcript_uri FROM stage_runs WHERE id = %s", (stage_run_id,)).fetchone()
        return row["transcript_uri"] if row else None


_FINDING_FILTERS = {
    "repo": "f.repo",
    "label": "f.label",
    "bug_class": "f.bug_class",
    "triage_state": "f.triage_state",
    "status": "f.status",
    "severity": "f.severity",
    "pr": "f.last_pr",
}


def list_findings(filters: dict[str, Any] | None = None, limit: int = 100, offset: int = 0) -> list[dict]:
    where, params = _where(filters, _FINDING_FILTERS)
    with _conn() as conn:
        return conn.execute(
            f"""SELECT f.id, f.repo, f.fingerprint, f.bug_class, f.vuln_class, f.title, f.severity, f.label,
                       f.introduced, f.sink_file, f.sink_line, f.first_scan_id, f.last_scan_id, f.last_pr,
                       f.status, f.triage_state, f.created_at, f.updated_at
                FROM findings f{where}
                ORDER BY {_SEVERITY_ORDER}, f.updated_at DESC, f.id DESC LIMIT %s OFFSET %s""",
            [*params, limit, offset],
        ).fetchall()


def get_finding(finding_id: int) -> dict | None:
    with _conn() as conn:
        f = conn.execute("SELECT * FROM findings WHERE id = %s", (finding_id,)).fetchone()
        if f is None:
            return None
        f["occurrences"] = conn.execute(
            """SELECT o.scan_id, o.label, s.pr, s.head_sha, s.status AS scan_status, s.created_at
               FROM finding_occurrences o JOIN scans s ON s.id = o.scan_id
               WHERE o.finding_id = %s ORDER BY o.scan_id DESC""",
            (finding_id,),
        ).fetchall()
        return f


def distinct_values() -> dict[str, list[str]]:
    """Filter dropdown options."""
    with _conn() as conn:
        return {
            "repo": [r["v"] for r in conn.execute("SELECT DISTINCT repo AS v FROM findings ORDER BY 1")],
            "bug_class": [r["v"] for r in conn.execute("SELECT DISTINCT bug_class AS v FROM findings ORDER BY 1")],
        }


def _precision(tp: int, fp: int) -> float | None:
    return round(tp / (tp + fp), 3) if tp + fp else None


def metrics() -> dict[str, Any]:
    """Dashboard metrics. Precision = tp / (tp + fp) over triaged findings;
    'accepted' (real but risk-accepted) is reported separately and excluded."""
    with _conn() as conn:
        by_status = conn.execute(
            """SELECT status,
                      count(*) FILTER (WHERE created_at > now() - interval '7 days') AS d7,
                      count(*) AS d30
               FROM scans WHERE created_at > now() - interval '30 days'
               GROUP BY status ORDER BY status"""
        ).fetchall()
        agg = conn.execute(
            """SELECT count(*) FILTER (WHERE status IN ('done', 'skipped', 'failed')) AS finished,
                      count(*) FILTER (WHERE status = 'skipped') AS skipped,
                      count(*) FILTER (WHERE status = 'done') AS done,
                      COALESCE(avg(cost_usd) FILTER (WHERE status IN ('done', 'skipped', 'failed')), 0)::float AS avg_cost,
                      COALESCE(sum(cost_usd), 0)::float AS total_cost,
                      avg(EXTRACT(EPOCH FROM (finished_at - started_at)))::float AS avg_duration_s
               FROM scans WHERE created_at > now() - interval '30 days'"""
        ).fetchone()

        def precision_by(col: str) -> list[dict]:
            rows = conn.execute(
                f"""SELECT {col} AS key,
                           count(*) AS total,
                           count(*) FILTER (WHERE triage_state = 'tp') AS tp,
                           count(*) FILTER (WHERE triage_state = 'fp') AS fp,
                           count(*) FILTER (WHERE triage_state = 'accepted') AS accepted,
                           count(*) FILTER (WHERE triage_state = 'new') AS untriaged
                    FROM findings GROUP BY {col} ORDER BY {col}"""
            ).fetchall()
            for r in rows:
                r["precision"] = _precision(r["tp"], r["fp"])
            return rows

        harness_sql = """SELECT {cols},
                   count(*) AS runs,
                   count(*) FILTER (WHERE status = 'ok') AS ok,
                   avg(duration_s)::float AS avg_duration_s,
                   COALESCE(sum((usage->>'usd')::float), 0)::float AS total_cost,
                   COALESCE(avg((usage->>'usd')::float), 0)::float AS avg_cost,
                   COALESCE(avg((usage->>'tokens_in')::float + (usage->>'tokens_out')::float), 0)::float AS avg_tokens
            FROM stage_runs WHERE created_at > now() - interval '30 days'
            GROUP BY {cols} ORDER BY {cols}"""
        per_harness = conn.execute(harness_sql.format(cols="harness")).fetchall()
        per_stage_harness = conn.execute(harness_sql.format(cols="stage, harness, model")).fetchall()
        for r in [*per_harness, *per_stage_harness]:
            r["ok_rate"] = round(r["ok"] / r["runs"], 3) if r["runs"] else None
        by_bug_class = precision_by("bug_class")
        by_label = precision_by("label")

    decided = agg["skipped"] + agg["done"]
    return {
        "scans_by_status": {
            "7d": {r["status"]: r["d7"] for r in by_status},
            "30d": {r["status"]: r["d30"] for r in by_status},
        },
        "skip_rate": round(agg["skipped"] / decided, 3) if decided else None,
        "finished_scans": agg["finished"],
        "avg_cost_usd": round(agg["avg_cost"], 4),
        "total_cost_usd": round(agg["total_cost"], 4),
        "avg_duration_s": agg["avg_duration_s"],
        "precision_by_bug_class": by_bug_class,
        "precision_by_label": by_label,
        "per_harness": per_harness,
        "per_stage_harness": per_stage_harness,
    }

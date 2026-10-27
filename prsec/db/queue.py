"""Scan job queue on Postgres (`scans` table).

Lifecycle: queued -> running -> done|skipped|failed, or -> superseded when a newer
head_sha arrives for the same repo/pr. Workers lease with FOR UPDATE SKIP LOCKED and
keep the lease alive with heartbeat(); expired leases are requeued.

Every lease gets a fresh `lease_token`. Passing it to heartbeat/finish/record_stage_run makes
those writes conditional on still holding that lease, so a worker that lost its lease (requeued
after a stall) or whose superseded scan was revived cannot clobber the new run. finish() releases
the token; a superseded row is only revived once its old run has released it (or its lease ran out).
Failed scans are retried for the same head up to FAILED_RETRY_MAX times with exponential backoff.
"""
from __future__ import annotations

from typing import Any

import psycopg
from psycopg.types.json import Jsonb

from prsec.db.conn import get_pool
from prsec.models import ScanRequest, ScanStatus, StageResult

_ACTIVE = (ScanStatus.queued.value, ScanStatus.running.value)
FAILED_RETRY_MAX = 3
FAILED_RETRY_BASE_S = 300

# A row for the same head that may be (re)queued: a superseded scan whose run has stopped, or a
# failed scan whose retry backoff has elapsed.
_REVIVABLE = f"""(
    (status = 'superseded' AND (lease_token IS NULL OR lease_until IS NULL OR lease_until < now()))
    OR (status = 'failed' AND retries < {FAILED_RETRY_MAX}
        AND COALESCE(finished_at, created_at) < now() - make_interval(secs => {FAILED_RETRY_BASE_S} * power(2, retries)))
)"""


def _lock_pr(conn: psycopg.Connection, repo: str, pr: int) -> None:
    """Serialise enqueues for one repo/pr within the current transaction."""
    conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (f"{repo}#{pr}",))


def _supersede_others(conn: psycopg.Connection, req: ScanRequest) -> int:
    """Mark queued/running scans of other heads superseded; return the supersede_count to inherit."""
    rows = conn.execute(
        """
        UPDATE scans SET status = 'superseded', finished_at = now(),
            lease_until = CASE WHEN status = 'running' THEN lease_until END
        WHERE repo = %s AND pr = %s AND head_sha <> %s AND status = ANY(%s)
        RETURNING supersede_count
        """,
        (req.repo, req.pr, req.head_sha, list(_ACTIVE)),
    ).fetchall()
    return max((r["supersede_count"] for r in rows), default=-1) + 1


def enqueue(req: ScanRequest, skills_version: str, debounce_s: int, max_supersedes: int) -> int | None:
    """Queue a scan; returns the scan id, or None if this (repo, pr, head_sha, skills_version) is already known.

    A superseded row for the same head (e.g. force-push back) is revived once its previous run has
    stopped, and a failed row is revived after its retry backoff; otherwise the head counts as known.
    """
    with get_pool().connection() as conn:
        _lock_pr(conn, req.repo, req.pr)
        existing = conn.execute(
            f"SELECT id, status, {_REVIVABLE} AS revivable FROM scans"
            " WHERE repo = %s AND pr = %s AND head_sha = %s AND skills_version = %s",
            (req.repo, req.pr, req.head_sha, skills_version),
        ).fetchone()
        if existing and not existing["revivable"]:
            return None

        count = _supersede_others(conn, req)
        delay = 0 if count >= max_supersedes else max(debounce_s, 0)
        if existing:
            conn.execute(
                """
                UPDATE scans SET status = 'queued', supersede_count = %s,
                    not_before = now() + make_interval(secs => %s), lease_until = NULL, lease_token = NULL,
                    attempts = 0, retries = retries + (status = 'failed')::int,
                    finished_at = NULL, error = NULL, reason = %s,
                    base_sha = COALESCE(%s, base_sha), installation_id = COALESCE(%s, installation_id)
                WHERE id = %s
                """,
                (count, delay, req.reason, req.base_sha, req.installation_id, existing["id"]),
            )
            return int(existing["id"])

        row = conn.execute(
            """
            INSERT INTO scans (scm, repo, pr, head_sha, base_sha, installation_id, skills_version,
                               reason, status, supersede_count, not_before)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'queued', %s, now() + make_interval(secs => %s))
            ON CONFLICT (repo, pr, head_sha, skills_version) DO NOTHING
            RETURNING id
            """,
            (req.scm, req.repo, req.pr, req.head_sha, req.base_sha, req.installation_id,
             skills_version, req.reason, count, delay),
        ).fetchone()
        return int(row["id"]) if row else None


def _lease(conn: psycopg.Connection, lease_s: int) -> dict[str, Any] | None:
    return conn.execute(
        """
        UPDATE scans SET status = 'running', attempts = attempts + 1, started_at = now(),
            lease_until = now() + make_interval(secs => %s), lease_token = gen_random_uuid()::text
        WHERE id = (
            SELECT id FROM scans
            WHERE status = 'queued' AND not_before <= now()
            ORDER BY not_before, id
            FOR UPDATE SKIP LOCKED
            LIMIT 1
        )
        RETURNING *
        """,
        (lease_s,),
    ).fetchone()


def lease_next(lease_s: int = 600) -> dict[str, Any] | None:
    """Claim the next due queued scan (status -> running). Returns the full scan row (incl. lease_token)."""
    with get_pool().connection() as conn:
        return _lease(conn, lease_s)


def heartbeat(scan_id: int, lease_s: int = 600, lease_token: str | None = None) -> bool:
    """Extend a running scan's lease. False if the scan is no longer running (superseded) or the lease was lost."""
    with get_pool().connection() as conn:
        cur = conn.execute(
            "UPDATE scans SET lease_until = now() + make_interval(secs => %s)"
            " WHERE id = %s AND status = 'running' AND (%s::text IS NULL OR lease_token = %s)",
            (lease_s, scan_id, lease_token, lease_token),
        )
        return cur.rowcount == 1


def owns_lease(scan_id: int, lease_token: str) -> bool:
    """True while `lease_token` is still the scan's current lease (it may have been superseded meanwhile)."""
    with get_pool().connection() as conn:
        row = conn.execute("SELECT lease_token FROM scans WHERE id = %s", (scan_id,)).fetchone()
        return bool(row) and row["lease_token"] == lease_token


def is_superseded(scan_id: int) -> bool:
    with get_pool().connection() as conn:
        row = conn.execute("SELECT status FROM scans WHERE id = %s", (scan_id,)).fetchone()
        return bool(row) and row["status"] == ScanStatus.superseded


def finish(
    scan_id: int,
    status: ScanStatus,
    *,
    triage: dict[str, Any] | None = None,
    error: str | None = None,
    sarif_uri: str | None = None,
    lease_token: str | None = None,
) -> bool:
    """Record the terminal state and release the lease. A scan superseded mid-run stays 'superseded';
    its results are still stored. With `lease_token`, nothing is written unless that lease is current.
    Returns whether the row was updated."""
    with get_pool().connection() as conn:
        cur = conn.execute(
            """
            UPDATE scans SET
                status = CASE WHEN status = 'superseded' THEN status ELSE %s END,
                finished_at = now(), lease_until = NULL, lease_token = NULL,
                triage = COALESCE(%s, triage), error = COALESCE(%s, error),
                sarif_uri = COALESCE(%s, sarif_uri)
            WHERE id = %s AND (%s::text IS NULL OR lease_token = %s)
            """,
            (ScanStatus(status).value, Jsonb(triage) if triage is not None else None, error, sarif_uri, scan_id,
             lease_token, lease_token),
        )
        return cur.rowcount == 1


def add_cost(scan_id: int, usd: float) -> None:
    with get_pool().connection() as conn:
        conn.execute("UPDATE scans SET cost_usd = cost_usd + %s WHERE id = %s", (usd, scan_id))


def record_stage_run(scan_id: int, result: StageResult, transcript_uri: str | None, lease_token: str | None = None) -> None:
    """Upsert one stage run (keyed by task_id). The transcript itself lives at transcript_uri.
    With `lease_token`, a run that no longer holds the scan's lease records nothing."""
    with get_pool().connection() as conn:
        conn.execute(
            """
            INSERT INTO stage_runs (scan_id, task_id, stage, harness, harness_version, model, status,
                                    attempts, usage, output, errors, transcript_uri, duration_s)
            SELECT %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            WHERE %s::text IS NULL OR EXISTS (SELECT 1 FROM scans WHERE id = %s AND lease_token = %s)
            ON CONFLICT (task_id) DO UPDATE SET
                status = EXCLUDED.status, harness_version = EXCLUDED.harness_version,
                model = EXCLUDED.model, attempts = EXCLUDED.attempts, usage = EXCLUDED.usage,
                output = EXCLUDED.output, errors = EXCLUDED.errors,
                transcript_uri = EXCLUDED.transcript_uri, duration_s = EXCLUDED.duration_s
            """,
            (
                scan_id, result.task_id, result.stage.value, result.harness, result.harness_version,
                result.model, result.status.value, result.attempts,
                Jsonb(result.usage.model_dump()),
                Jsonb(result.output) if result.output is not None else None,
                Jsonb(result.errors), transcript_uri, result.duration_s,
                lease_token, scan_id, lease_token,
            ),
        )


def requeue_expired_leases(max_attempts: int = 3) -> int:
    """Return expired running scans to the queue; ones that already used max_attempts become 'failed'.

    Returns the number requeued.
    """
    with get_pool().connection() as conn:
        conn.execute(
            """
            UPDATE scans SET status = 'failed', finished_at = now(), lease_until = NULL, lease_token = NULL,
                error = COALESCE(error, 'lease expired after ' || attempts || ' attempts')
            WHERE status = 'running' AND lease_until < now() AND attempts >= %s
            """,
            (max_attempts,),
        )
        cur = conn.execute(
            """
            UPDATE scans SET status = 'queued', lease_until = NULL, lease_token = NULL, not_before = now()
            WHERE status = 'running' AND lease_until < now()
            """
        )
        return cur.rowcount


def known_head(repo: str, pr: int, head_sha: str, skills_version: str) -> bool:
    """True if this idempotency key has a scan that enqueue() would not revive (reconciler: nothing to enqueue)."""
    with get_pool().connection() as conn:
        row = conn.execute(
            "SELECT 1 FROM scans WHERE repo = %s AND pr = %s AND head_sha = %s AND skills_version = %s"
            f" AND NOT {_REVIVABLE}",
            (repo, pr, head_sha, skills_version),
        ).fetchone()
        return row is not None

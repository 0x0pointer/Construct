"""Per-scan timeline: one `scan_events` row per meaningful step, each with a short human reason.

    emit(scan_id, "triage", "triage: full (touches a SQL query)", data={...})
    list_events(scan_id, after_id=0)   # ordered by id; poll with the last id seen to follow a scan live

`emit` never raises: a timeline that cannot be written must not fail a scan. It also logs the line
(logger `prsec.events`), so the event shows up in the service log with the bound context. Fields not
given (stage, task_id, hypothesis_id) default to the bound logging context (`prsec.obs.logging.bind`).
When the database is unreachable, inserts pause for `_BACKOFF_S` instead of stalling every step.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from typing import Any

from prsec.obs.logging import get_context

log = logging.getLogger("prsec.events")

KINDS = frozenset({
    "scan_started", "rules", "triage", "stage_started", "stage_finished", "agent", "hypotheses",
    "hypothesis_dropped", "static_verdict", "skeptic", "env_created", "env_destroyed", "dynamic_outcome",
    "replay", "label", "kept", "scan_finished", "error",
})
LEVELS = {"debug": logging.DEBUG, "info": logging.INFO, "warning": logging.WARNING, "error": logging.ERROR}
MESSAGE_MAX = 2000
DATA_MAX = 64_000  # serialised bytes; bigger payloads are replaced by a preview
LIST_MAX = 5000
_CONNECT_TIMEOUT_S = 5.0
_BACKOFF_S = 30.0

_down_until = 0.0
_down_lock = threading.Lock()


def _db_available() -> bool:
    return time.monotonic() >= _down_until


def _mark_down() -> None:
    global _down_until
    with _down_lock:
        first = _db_available()
        _down_until = time.monotonic() + _BACKOFF_S
    if first:
        log.warning("scan_events: database unavailable; timeline inserts paused for %.0fs", _BACKOFF_S, exc_info=True)


def _jsonable(data: dict[str, Any] | None) -> dict[str, Any] | None:
    """A JSON-safe copy of `data` (unknown types as str), or a preview when it is too big."""
    if not data:
        return None
    text = json.dumps(data, default=str, ensure_ascii=False)
    if len(text) > DATA_MAX:
        return {"truncated": True, "preview": text[:4000]}
    return json.loads(text)


def _insert(row: dict[str, Any]) -> None:
    """Seam (tests replace it): write one row."""
    from psycopg.types.json import Jsonb

    from prsec.db.conn import get_pool

    with get_pool().connection(timeout=_CONNECT_TIMEOUT_S) as conn:
        conn.execute(
            "INSERT INTO scan_events (scan_id, kind, level, stage, task_id, hypothesis_id, message, data)"
            " VALUES (%(scan_id)s, %(kind)s, %(level)s, %(stage)s, %(task_id)s, %(hypothesis_id)s, %(message)s,"
            " %(data)s)",
            {**row, "data": Jsonb(row["data"]) if row["data"] is not None else None},
        )


def _row(scan_id: int, kind: str, message: str, level: str, fields: dict[str, Any], data: Any) -> dict[str, Any]:
    ctx = get_context()
    return {
        "scan_id": int(scan_id),
        "kind": kind if kind in KINDS else "error",
        "level": level if level in LEVELS else "info",
        "stage": fields.get("stage") or ctx.get("stage"),
        "task_id": fields.get("task_id") or ctx.get("task_id"),
        "hypothesis_id": fields.get("hypothesis_id") or ctx.get("hypothesis_id"),
        "message": str(message)[:MESSAGE_MAX],
        "data": _jsonable(data),
    }


def emit(
    scan_id: int,
    kind: str,
    message: str,
    *,
    level: str = "info",
    stage: str | None = None,
    task_id: str | None = None,
    hypothesis_id: str | None = None,
    data: dict[str, Any] | None = None,
) -> None:
    """Record one timeline event and log it. Never raises."""
    try:
        row = _row(scan_id, kind, message, level, {"stage": stage, "task_id": task_id, "hypothesis_id": hypothesis_id},
                   data)
        if row["kind"] != kind:
            row["message"] = f"[unknown kind {kind!r}] {row['message']}"[:MESSAGE_MAX]
        log.log(LEVELS[row["level"]], "[%s] %s", row["kind"], row["message"])
    except Exception:
        log.warning("scan %s: could not build %s event", scan_id, kind, exc_info=True)
        return
    if not _db_available():
        return
    try:
        _insert(row)
    except Exception:
        _mark_down()


def list_events(scan_id: int, after_id: int = 0, limit: int = 500) -> list[dict[str, Any]]:
    """Events of a scan with id > after_id, oldest first (at most `limit`, capped at LIST_MAX)."""
    from prsec.db.conn import get_pool

    with get_pool().connection() as conn:
        return conn.execute(
            "SELECT id, scan_id, ts, kind, level, stage, task_id, hypothesis_id, message, data FROM scan_events"
            " WHERE scan_id = %s AND id > %s ORDER BY id LIMIT %s",
            (int(scan_id), int(after_id), max(1, min(int(limit), LIST_MAX))),
        ).fetchall()


def reset_backoff() -> None:
    """Resume inserts right away (tests, or after the database is known to be back)."""
    global _down_until
    with _down_lock:
        _down_until = 0.0

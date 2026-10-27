"""Postgres connection pool and idempotent schema migration."""
from __future__ import annotations

import threading
from pathlib import Path

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from prsec.config import settings

SCHEMA_PATH = Path(__file__).parent / "schema.sql"
_MIGRATE_LOCK_ID = 0x70727365  # "prse": serialises concurrent migrations across processes

_pool: ConnectionPool | None = None
_pool_lock = threading.Lock()


def get_pool() -> ConnectionPool:
    """Process-wide pool on settings().database_url; rows are returned as dicts."""
    global _pool
    if _pool is None:
        with _pool_lock:
            if _pool is None:
                s = settings()
                _pool = ConnectionPool(
                    s.database_url,
                    min_size=1,
                    max_size=max(4, s.worker_concurrency + 4),
                    kwargs={"row_factory": dict_row},
                    open=True,
                    name="prsec",
                )
    return _pool


def close_pool() -> None:
    """Close and forget the pool (tests, shutdown, or after changing settings)."""
    global _pool
    with _pool_lock:
        if _pool is not None:
            _pool.close()
            _pool = None


def migrate(conn: psycopg.Connection) -> None:
    """Apply schema.sql. Every statement is IF NOT EXISTS, so this is safe to run repeatedly."""
    with conn.transaction():
        conn.execute("SELECT pg_advisory_xact_lock(%s)", (_MIGRATE_LOCK_ID,))
        conn.execute(SCHEMA_PATH.read_text())

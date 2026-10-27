from __future__ import annotations

import os
import uuid

import psycopg
import pytest
from psycopg.conninfo import make_conninfo
from psycopg.rows import dict_row

from prsec.config import settings
from prsec.db import conn as db_conn


@pytest.fixture
def dsn(monkeypatch):
    """A fresh, migrated schema per test; settings()/get_pool() point at it via search_path."""
    base = os.environ.get("PRSEC_TEST_DATABASE_URL")
    if not base:
        pytest.skip("PRSEC_TEST_DATABASE_URL not set")
    schema = f"t_queue_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(base, autocommit=True) as c:
        c.execute(f'CREATE SCHEMA "{schema}"')
    url = make_conninfo(base, options=f"-csearch_path={schema}")
    monkeypatch.setenv("PRSEC_DATABASE_URL", url)
    settings.cache_clear()
    db_conn.close_pool()
    with db_conn.get_pool().connection() as c:
        db_conn.migrate(c)
    try:
        yield url
    finally:
        db_conn.close_pool()
        settings.cache_clear()
        with psycopg.connect(base, autocommit=True) as c:
            c.execute(f'DROP SCHEMA "{schema}" CASCADE')


@pytest.fixture
def sql(dsn):
    """Autocommit side connection on the test schema for assertions and time travel."""
    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row) as c:
        yield c

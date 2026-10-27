import os
import sys
import uuid
from pathlib import Path

import psycopg
import pytest
from psycopg_pool import ConnectionPool

sys.path.insert(0, str(Path(__file__).parents[1] / "sarif"))
sys.path.insert(0, str(Path(__file__).parent))

SCHEMA_SQL = (Path(__file__).parents[2] / "prsec" / "db" / "schema.sql").read_text()


@pytest.fixture
def pg_pool(monkeypatch):
    """Pool bound to a throwaway schema; prsec.db.findings is pointed at it."""
    url = os.environ.get("PRSEC_TEST_DATABASE_URL")
    if not url:
        pytest.skip("PRSEC_TEST_DATABASE_URL not set")
    schema = f"t_sink_{uuid.uuid4().hex[:10]}"
    with psycopg.connect(url, autocommit=True) as c:
        c.execute(f'CREATE SCHEMA "{schema}"')
        c.execute(f'SET search_path TO "{schema}"')
        c.execute(SCHEMA_SQL)
    pool = ConnectionPool(url, kwargs={"options": f"-c search_path={schema}"}, min_size=1, max_size=4, open=True)
    from prsec.db import findings

    monkeypatch.setattr(findings, "_pool", lambda: pool)
    try:
        yield pool
    finally:
        pool.close()
        with psycopg.connect(url, autocommit=True) as c:
            c.execute(f'DROP SCHEMA "{schema}" CASCADE')


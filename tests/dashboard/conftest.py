import os
import sys
import uuid
from pathlib import Path

import psycopg
import pytest
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

sys.path.insert(0, str(Path(__file__).parents[1] / "sarif"))

SCHEMA_SQL = (Path(__file__).parents[2] / "prsec" / "db" / "schema.sql").read_text()


@pytest.fixture
def pg_pool(monkeypatch):
    url = os.environ.get("PRSEC_TEST_DATABASE_URL")
    if not url:
        pytest.skip("PRSEC_TEST_DATABASE_URL not set")
    schema = f"t_dash_{uuid.uuid4().hex[:10]}"
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


@pytest.fixture
def seeded(pg_pool, tmp_path, monkeypatch):
    """Two scans, stage runs, three findings, and a locally stored SARIF for scan 1."""
    from _factories import finding, pr

    from prsec.adapters.sinks.sarif_store import SarifStoreSink
    from prsec.config import settings

    monkeypatch.setenv("PRSEC_SARIF_DIR", str(tmp_path))
    monkeypatch.setattr(settings(), "s3_access_key", "")
    with pg_pool.connection() as c:
        s1 = c.execute(
            """INSERT INTO scans (repo, pr, head_sha, skills_version, status, cost_usd, triage, started_at, finished_at)
               VALUES ('acme/shop', 7, %s, 'dev', 'done', 1.25, %s, now() - interval '2 minutes', now()) RETURNING id""",
            ("a" * 40, Jsonb({"decision": "full", "rationale": "New <b>SQL</b> endpoint", "risk_tags": ["sqli"]})),
        ).fetchone()[0]
        s2 = c.execute(
            """INSERT INTO scans (repo, pr, head_sha, skills_version, status, triage)
               VALUES ('acme/web', 3, %s, 'dev', 'skipped', %s) RETURNING id""",
            ("c" * 40, Jsonb({"decision": "skip", "rationale": "css only"})),
        ).fetchone()[0]
        c.execute(
            """INSERT INTO stage_runs (scan_id, task_id, stage, harness, harness_version, model, status, usage, errors, duration_s)
               VALUES (%s, 't1', 'hypothesise', 'codex', '0.50.0', 'agent-large', 'ok', %s, %s, 42),
                      (%s, 't2', 'static_verify', 'claude-code', '2.1.0', 'agent-large', 'output_invalid', %s, %s, 80)""",
            (s1, Jsonb({"usd": 0.4, "tokens_in": 1000, "tokens_out": 200}), Jsonb([]),
             s1, Jsonb({"usd": 0.8}), Jsonb(["schema: citations missing"])),
        )
    fs = [finding(scan_id=s1), finding(scan_id=s1, bug_class="idor", symbol="get", label="reproduced", severity="critical"),
          finding(scan_id=s1, symbol="other", severity="low", label="inconclusive")]
    uri = SarifStoreSink().write_scan(s1, pr(), fs, {"changed_files": ["app/orders.py"]})
    with pg_pool.connection() as c:
        c.execute("UPDATE scans SET sarif_uri = %s WHERE id = %s", (uri, s1))
    return {"scans": (s1, s2), "findings": fs}


@pytest.fixture
def client(seeded):
    from fastapi.testclient import TestClient

    from prsec.dashboard.main import app

    return TestClient(app)

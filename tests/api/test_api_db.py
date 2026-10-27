"""Webhook -> real queue, end to end."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import uuid

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg.conninfo import make_conninfo

from prsec.api import main
from prsec.config import Policy, StagePolicy, settings
from prsec.db import conn as db_conn

from .payloads import pr_payload

pytestmark = pytest.mark.db


@pytest.fixture
def client(monkeypatch):
    base = os.environ.get("PRSEC_TEST_DATABASE_URL")
    if not base:
        pytest.skip("PRSEC_TEST_DATABASE_URL not set")
    schema = f"t_api_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(base, autocommit=True) as c:
        c.execute(f'CREATE SCHEMA "{schema}"')
    monkeypatch.setenv("PRSEC_DATABASE_URL", make_conninfo(base, options=f"-csearch_path={schema}"))
    monkeypatch.setenv("PRSEC_GITHUB_WEBHOOK_SECRET", "k")
    monkeypatch.setenv("PRSEC_DEBOUNCE_S", "0")
    settings.cache_clear()
    db_conn.close_pool()
    app = main.create_app()  # migrates on startup
    app.dependency_overrides[main.get_policy] = lambda: Policy(defaults={"t": StagePolicy(harness="raw")})
    try:
        with TestClient(app) as c:
            yield c
    finally:
        db_conn.close_pool()
        settings.cache_clear()
        with psycopg.connect(base, autocommit=True) as c:
            c.execute(f'DROP SCHEMA "{schema}" CASCADE')


def post(client, payload):
    body = json.dumps(payload).encode()
    sig = "sha256=" + hmac.new(b"k", body, hashlib.sha256).hexdigest()
    return client.post("/webhooks/github", content=body,
                       headers={"X-GitHub-Event": "pull_request", "X-Hub-Signature-256": sig})


def test_webhook_enqueues_then_dedupes(client):
    r = post(client, pr_payload())
    assert r.status_code == 202
    scan_id = r.json()["scan_id"]
    assert post(client, pr_payload(action="synchronize")).json() == {"ignored": "duplicate"}
    from prsec.db import queue

    leased = queue.lease_next()
    assert leased["id"] == scan_id
    assert leased["installation_id"] == 99

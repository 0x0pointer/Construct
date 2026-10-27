from __future__ import annotations

import hashlib
import hmac
import json

import pytest
from fastapi.testclient import TestClient

from prsec.api import main
from prsec.config import Policy, Settings, StagePolicy
from prsec.db import queue
from .payloads import pr_payload

SECRET = "s3cret"


def sign(body: bytes, secret: str = SECRET) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


@pytest.fixture
def calls(monkeypatch):
    seen: list[tuple] = []

    def fake_enqueue(req, skills_version, debounce_s, max_supersedes):
        seen.append((req, skills_version, debounce_s, max_supersedes))
        return None if req.head_sha == "d" * 40 else 42

    monkeypatch.setattr(queue, "enqueue", fake_enqueue)
    return seen


@pytest.fixture
def pol() -> Policy:
    return Policy(defaults={"triage": StagePolicy(harness="raw")}, scan_drafts=False)


@pytest.fixture
def client(pol):
    app = main.create_app(migrate_on_startup=False)
    s = Settings(github_webhook_secret=SECRET, skills_version="sk-1", debounce_s=120, max_supersedes=5)
    app.dependency_overrides[main.get_settings] = lambda: s
    app.dependency_overrides[main.get_policy] = lambda: pol
    with TestClient(app) as c:
        yield c


def post(client, payload, event="pull_request", signature=None, raw: bytes | None = None):
    body = raw if raw is not None else json.dumps(payload).encode()
    headers = {"X-GitHub-Event": event, "Content-Type": "application/json"}
    sig = signature if signature is not None else sign(body)
    if sig:
        headers["X-Hub-Signature-256"] = sig
    return client.post("/webhooks/github", content=body, headers=headers)


def test_verify_signature():
    body = b'{"a":1}'
    assert main.verify_signature(SECRET, body, sign(body))
    assert not main.verify_signature(SECRET, body, sign(body, "other"))
    assert not main.verify_signature(SECRET, body + b" ", sign(body))
    assert not main.verify_signature(SECRET, body, sign(body).replace("sha256=", "sha1="))
    assert not main.verify_signature(SECRET, body, None)
    assert not main.verify_signature("", body, sign(body, ""))


def test_valid_signature_enqueues(client, calls):
    r = post(client, pr_payload(action="synchronize"))
    assert r.status_code == 202 and r.json() == {"scan_id": 42}
    req, skills, debounce, max_sup = calls[0]
    assert (req.repo, req.pr, req.reason, skills, debounce, max_sup) == ("acme/api", 7, "synchronize", "sk-1", 120, 5)


def test_invalid_signature_rejected(client, calls):
    r = post(client, pr_payload(), signature=sign(b"something else"))
    assert r.status_code == 401
    assert post(client, pr_payload(), signature="").status_code == 401
    assert calls == []


def test_signature_checked_before_parsing(client, calls):
    assert post(client, None, raw=b"not json", signature="sha256=00").status_code == 401
    assert post(client, None, raw=b"not json").status_code == 400


def test_missing_secret_fails_closed(pol, calls):
    app = main.create_app(migrate_on_startup=False)
    app.dependency_overrides[main.get_settings] = lambda: Settings(github_webhook_secret="")
    app.dependency_overrides[main.get_policy] = lambda: pol
    with TestClient(app) as c:
        assert post(c, pr_payload(), signature=sign(b"", "")).status_code == 503
    assert calls == []


def test_ping(client, calls):
    r = post(client, {"zen": "Keep it logically awesome.", "hook_id": 1}, event="ping")
    assert r.status_code == 200 and r.json()["pong"] is True
    assert calls == []


@pytest.mark.parametrize(
    "payload,event,reason",
    [
        (pr_payload(action="closed"), "pull_request", "action:closed"),
        (pr_payload(action="labeled"), "pull_request", "action:labeled"),
        (pr_payload(pull_request__draft=True), "pull_request", "draft"),
        (pr_payload(pull_request__head={"sha": "c" * 40, "repo": {"full_name": "x/api"}}), "pull_request", "fork"),
        ({"ref": "refs/heads/main"}, "push", "event:push"),
    ],
)
def test_ignored(client, calls, payload, event, reason):
    r = post(client, payload, event=event)
    assert r.status_code == 200 and r.json() == {"ignored": reason}
    assert calls == []


def test_duplicate_is_200(client, calls):
    r = post(client, pr_payload(pull_request__head={"sha": "d" * 40, "repo": {"full_name": "acme/api"}}))
    assert r.status_code == 200 and r.json() == {"ignored": "duplicate"}


def test_healthz(client):
    assert client.get("/healthz").json() == {"ok": True}


def test_manual_scan_requires_admin_token(client, calls, monkeypatch):
    body = {"repo": "acme/api", "pr": 3, "head_sha": "e" * 40}
    monkeypatch.delenv("PRSEC_ADMIN_TOKEN", raising=False)
    assert client.post("/scans", json=body, headers={"X-PRSec-Admin": ""}).status_code == 403
    monkeypatch.setenv("PRSEC_ADMIN_TOKEN", "tok")
    assert client.post("/scans", json=body).status_code == 403
    assert client.post("/scans", json=body, headers={"X-PRSec-Admin": "nope"}).status_code == 403
    assert calls == []
    r = client.post("/scans", json=body, headers={"X-PRSec-Admin": "tok"})
    assert r.status_code == 202 and r.json() == {"scan_id": 42}
    req, _, debounce, _ = calls[0]
    assert req.reason == "manual" and req.pr == 3 and debounce == 0


def test_manual_scan_validates_body(client, monkeypatch):
    monkeypatch.setenv("PRSEC_ADMIN_TOKEN", "tok")
    assert client.post("/scans", json={"repo": "acme/api"}, headers={"X-PRSec-Admin": "tok"}).status_code == 422

"""Response-header and body-regex oracles, requests to EnvSpec services, and parallel (race) steps."""
from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from prsec.dynamic.poc import PoC, Step
from prsec.dynamic.replay import PocEngine, Session, StepError, header_matches, resolve_url, run_poc
from prsec.dynamic.results import Canaries

CANARIES = Canaries(token="tok123", host="tok123.canary.invalid", url="http://tok123.canary.invalid/tok123",
                    file="/tmp/prsec-canary-tok123", file_content="secret-tok123")


def poc(**kw: Any) -> PoC:
    return PoC.model_validate({"kind": "http", "hypothesis_id": "h1", "description": "t"} | kw)


def engine(handler, services: list[str] | None = None) -> PocEngine:
    eng = PocEngine({}, "http://app.test", CANARIES, Path("."), env={}, services=services or [])
    eng.sessions["_anonymous"] = Session(client=httpx.Client(transport=httpx.MockTransport(handler)))
    return eng


def run(p: PoC, handler, services: list[str] | None = None):
    eng = engine(handler, services)
    try:
        return run_poc(p, eng)
    finally:
        eng.close()


# ------------------------------------------------------------------ response_header


def redirect_to(target: str):
    return lambda req: httpx.Response(302, headers={"Location": target})


OPEN_REDIRECT = poc(
    steps=[{"name": "go", "path": "/login?next=http://${CANARY.host}/x"}],
    oracles=[{"type": "response_status", "step": "go", "status": [301, 302, 303, 307, 308]},
             {"type": "response_header", "step": "go", "name": "location", "op": "starts_with",
              "value": "http://${CANARY.host}"}],
)


def test_open_redirect_fires_on_external_location():
    assert run(OPEN_REDIRECT, redirect_to("http://tok123.canary.invalid/x")).fired


def test_open_redirect_does_not_fire_on_local_location():
    assert not run(OPEN_REDIRECT, redirect_to("/home")).fired


def test_redirect_is_not_followed():
    calls: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(str(req.url))
        return httpx.Response(302, headers={"Location": "http://tok123.canary.invalid/x"})

    run(OPEN_REDIRECT, handler)
    assert len(calls) == 1


def test_set_cookie_without_httponly_checks_every_value():
    def handler(req):
        return httpx.Response(200, headers=[("Set-Cookie", "theme=dark; HttpOnly"), ("Set-Cookie", "session=abc; Path=/")])

    p = poc(steps=[{"name": "login", "path": "/login"}],
            oracles=[{"type": "response_header", "step": "login", "name": "Set-Cookie", "op": "regex",
                      "value": "^session=(?!.*HttpOnly)"}])
    assert run(p, handler).fired


def test_set_cookie_with_httponly_does_not_fire():
    p = poc(steps=[{"name": "login", "path": "/login"}],
            oracles=[{"type": "response_header", "step": "login", "name": "Set-Cookie", "op": "regex",
                      "value": "^session=(?!.*HttpOnly)"}])
    assert not run(p, lambda req: httpx.Response(200, headers={"Set-Cookie": "session=abc; HttpOnly"})).fired


@pytest.mark.parametrize(("values", "op", "value", "expected"), [
    (["https://evil.example"], "equals", "https://evil.example", True),
    (["text/html; charset=utf-8"], "contains", "text/html", True),
    (["application/json"], "contains", "text/html", False),
    ([], "present", "", False),
    ([], "absent", "", True),
    (["x"], "absent", "", False),
])
def test_header_matches(values, op, value, expected):
    assert header_matches(values, op, value) is expected


def test_header_oracle_needs_a_value():
    with pytest.raises(ValidationError):
        poc(steps=[{"name": "a", "path": "/"}],
            oracles=[{"type": "response_header", "step": "a", "name": "Location", "op": "contains"}])


def test_header_oracle_present_takes_no_value():
    with pytest.raises(ValidationError):
        poc(steps=[{"name": "a", "path": "/"}],
            oracles=[{"type": "response_header", "step": "a", "name": "Location", "op": "present", "value": "x"}])


def test_cors_reflection_fires():
    p = poc(steps=[{"name": "cors", "path": "/api/me", "headers": {"Origin": "http://${CANARY.host}"}}],
            oracles=[{"type": "response_header", "step": "cors", "name": "Access-Control-Allow-Origin",
                      "op": "equals", "value": "http://${CANARY.host}"},
                     {"type": "response_header", "step": "cors", "name": "Access-Control-Allow-Credentials",
                      "op": "equals", "value": "true"}])

    def handler(req):
        return httpx.Response(200, headers={"Access-Control-Allow-Origin": req.headers["origin"],
                                            "Access-Control-Allow-Credentials": "true"})

    assert run(p, handler).fired


# ------------------------------------------------------------------ response_regex


def test_regex_matches_server_built_value():
    p = poc(steps=[{"name": "q", "path": "/search?q=x"}],
            oracles=[{"type": "response_regex", "step": "q", "pattern": r"prsec42[a-z0-9]+"}])
    assert run(p, lambda req: httpx.Response(200, text="row: prsec42tok123")).fired


def test_regex_match_echoed_from_request_does_not_count():
    p = poc(steps=[{"name": "q", "path": "/search?q=prsec42tok123"}],
            oracles=[{"type": "response_regex", "step": "q", "pattern": r"prsec42[a-z0-9]+"}])
    assert not run(p, lambda req: httpx.Response(200, text="no results for prsec42tok123")).fired


def test_regex_must_compile():
    with pytest.raises(ValidationError):
        poc(steps=[{"name": "q", "path": "/"}], oracles=[{"type": "response_regex", "step": "q", "pattern": "("}])


# ------------------------------------------------------------------ service URLs


def test_service_url_allowed():
    assert resolve_url("http://mail:8025/api/v1/messages", "http://127.0.0.1:8000", ["mail"]) == "http://mail:8025/api/v1/messages"


@pytest.mark.parametrize("url", [
    "http://tok123.canary.invalid/x",
    "http://sink/__prsec/hits",
    "http://llm-gateway:4000/v1/models",
    "http://user:pw@mail:8025/",
    "ftp://mail/x",
])
def test_other_absolute_urls_refused(url):
    with pytest.raises(StepError):
        resolve_url(url, "http://127.0.0.1:8000", ["mail"])


def test_poc_reads_mail_from_service():
    seen: list[str] = []

    def handler(req):
        seen.append(req.url.host)
        return httpx.Response(200, json={"messages": [{"Subject": "reset"}]})

    p = poc(steps=[{"name": "mail", "path": "http://mail:8025/api/v1/messages"}],
            oracles=[{"type": "json_compare", "step": "mail", "path": "messages.0.Subject", "op": "eq", "value": "reset"}])
    assert run(p, handler, services=["mail"]).fired
    assert seen == ["mail"]


# ------------------------------------------------------------------ parallel steps


def race_handler(n: int):
    """Waits until n requests are in flight at once: proves the copies really run concurrently."""
    barrier = threading.Barrier(n, timeout=5)
    redeemed = {"count": 0}
    lock = threading.Lock()

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/redeem":
            barrier.wait()
            with lock:
                redeemed["count"] += 1
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(200, json={"redeemed": redeemed["count"]})

    return handler


RACE = poc(
    steps=[{"name": "redeem", "method": "POST", "path": "/redeem", "parallel": 5, "expect_status": [200, 409]},
           {"name": "count", "path": "/coupon"}],
    oracles=[{"type": "json_compare", "step": "count", "path": "redeemed", "op": "gt", "value": 1}],
)


def test_parallel_requests_run_concurrently_and_race_fires():
    result = run(RACE, race_handler(5))
    assert result.fired


def test_parallel_step_records_every_request():
    result = run(RACE, race_handler(5))
    assert len([s for s in result.steps if s.name.startswith("redeem#")]) == 5


def test_parallel_step_oracle_any_response():
    calls = {"n": 0}
    lock = threading.Lock()

    def handler(req):
        with lock:
            calls["n"] += 1
            first = calls["n"] == 1
        return httpx.Response(200 if first else 409)

    p = poc(steps=[{"name": "r", "method": "POST", "path": "/r", "parallel": 3}],
            oracles=[{"type": "response_status", "step": "r", "status": [200]}])
    assert run(p, handler).fired


def test_parallel_expect_status_applies_to_every_response():
    p = poc(steps=[{"name": "r", "method": "POST", "path": "/r", "parallel": 3, "expect_status": [200]}],
            oracles=[{"type": "response_status", "step": "r", "status": [200]}])
    result = run(p, lambda req: httpx.Response(500))
    assert result.aborted is not None


def test_parallel_step_cannot_extract():
    with pytest.raises(ValidationError):
        Step.model_validate({"name": "r", "path": "/r", "parallel": 2, "extract": {"x": {"json": "id"}}})


def test_parallel_is_capped():
    with pytest.raises(ValidationError):
        Step.model_validate({"name": "r", "path": "/r", "parallel": 51})

import json

import httpx
import pytest
import respx

from prsec import gateway
from prsec.config import settings

GW = "http://gw.test:4000"


@pytest.fixture
def gw_settings(monkeypatch):
    monkeypatch.setattr(settings(), "gateway_url", GW)
    monkeypatch.setattr(settings(), "gateway_master_key", "sk-master")
    monkeypatch.delenv(gateway.DEV_KEY_ENV, raising=False)


@respx.mock
def test_mint_key(gw_settings):
    route = respx.post(f"{GW}/key/generate").mock(return_value=httpx.Response(200, json={"key": "sk-scan-1"}))
    key = gateway.mint_key(12, 5.123456, 3600, ["agent-large", "judge", "agent-large"])
    assert key == "sk-scan-1"
    req = route.calls.last.request
    assert req.headers["authorization"] == "Bearer sk-master"
    body = json.loads(req.content)
    assert body == {"max_budget": 5.1235, "duration": "3600s", "models": ["agent-large", "judge"], "metadata": {"scan_id": 12}}


@respx.mock
def test_mint_key_error(gw_settings):
    respx.post(f"{GW}/key/generate").mock(return_value=httpx.Response(500, text="boom"))
    with pytest.raises(gateway.GatewayError):
        gateway.mint_key(1, 1.0, 60, ["m"])


@respx.mock
def test_revoke_key(gw_settings):
    route = respx.post(f"{GW}/key/delete").mock(return_value=httpx.Response(200, json={}))
    gateway.revoke_key("sk-scan-1")
    assert json.loads(route.calls.last.request.content) == {"keys": ["sk-scan-1"]}


@respx.mock
def test_revoke_failure_is_swallowed(gw_settings):
    respx.post(f"{GW}/key/delete").mock(side_effect=httpx.ConnectError("down"))
    gateway.revoke_key("sk-scan-1")


@respx.mock
def test_revoke_never_deletes_master_or_empty(gw_settings):
    route = respx.post(f"{GW}/key/delete").mock(return_value=httpx.Response(200))
    gateway.revoke_key("")
    gateway.revoke_key("sk-master")
    assert not route.called


@respx.mock
def test_dev_passthrough(monkeypatch):
    monkeypatch.setattr(settings(), "gateway_master_key", "")
    monkeypatch.setenv(gateway.DEV_KEY_ENV, "sk-dev")
    assert gateway.mint_key(1, 1.0, 60, ["m"]) == "sk-dev"
    gateway.revoke_key("sk-dev")
    monkeypatch.delenv(gateway.DEV_KEY_ENV)
    assert gateway.mint_key(1, 1.0, 60, ["m"]) == ""
    assert not respx.calls


@respx.mock
def test_mint_task_key_metadata(gw_settings):
    route = respx.post(f"{GW}/key/generate").mock(return_value=httpx.Response(200, json={"key": "sk-task"}))
    assert gateway.per_task_keys()
    assert gateway.mint_key(12, 2.0, 900, ["agent-large"], task_id="12-hypothesise") == "sk-task"
    assert json.loads(route.calls.last.request.content)["metadata"] == {"scan_id": 12, "task_id": "12-hypothesise"}


@respx.mock
def test_key_spend(gw_settings):
    route = respx.get(f"{GW}/key/info").mock(return_value=httpx.Response(200, json={"key": "x", "info": {"spend": 1.25}}))
    assert gateway.key_spend("sk-task") == 1.25
    assert route.calls.last.request.url.params["key"] == "sk-task"
    assert route.calls.last.request.headers["authorization"] == "Bearer sk-master"
    route.mock(return_value=httpx.Response(404, json={"error": "nope"}))
    assert gateway.key_spend("sk-task") is None
    route.mock(side_effect=httpx.ConnectError("down"))
    assert gateway.key_spend("sk-task") is None
    assert gateway.key_spend("sk-master") is None


@respx.mock
def test_self_spend_uses_own_key():
    route = respx.get("http://gw:4000/key/info").mock(return_value=httpx.Response(200, json={"info": {"spend": 0.5}}))
    assert gateway.self_spend("http://gw:4000/", "sk-task") == 0.5
    assert route.calls.last.request.headers["authorization"] == "Bearer sk-task"
    assert gateway.self_spend("http://gw:4000", "") is None


def test_dev_mode_has_no_task_keys(monkeypatch):
    monkeypatch.setattr(settings(), "gateway_master_key", "")
    assert not gateway.per_task_keys()
    assert gateway.key_spend("sk-anything") is None

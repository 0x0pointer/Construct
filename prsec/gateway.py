"""Per-scan virtual keys on the LiteLLM gateway.

Provider keys (Anthropic, OpenAI) live only in the gateway; each scan gets a
short-lived key capped by budget, TTL and model aliases.

With a master key, the orchestrator mints one key per stage task instead (`per_task_keys()`), capped
at that stage's budget; the gateway then enforces the stage budget itself and `key_spend()` is the
authoritative per-task cost, independent of what each harness reports.

Dev mode: with no master key configured, `PRSEC_GATEWAY_DEV_KEY` is passed through
as-is; with neither, `mint_key` returns "" and callers must not override the
harness's own login (GatewayConfig None).
"""
from __future__ import annotations

import logging
import os

import httpx

from prsec.config import settings

log = logging.getLogger(__name__)

DEV_KEY_ENV = "PRSEC_GATEWAY_DEV_KEY"
_TIMEOUT = httpx.Timeout(15.0)


class GatewayError(RuntimeError):
    pass


def _client() -> httpx.Client:
    s = settings()
    return httpx.Client(
        base_url=s.gateway_url.rstrip("/"),
        headers={"Authorization": f"Bearer {s.gateway_master_key}"},
        timeout=_TIMEOUT,
    )


def _passthrough_keys() -> set[str]:
    return {k for k in (settings().gateway_master_key, os.environ.get(DEV_KEY_ENV, "")) if k}


def per_task_keys() -> bool:
    """True when keys can be minted (master key configured), so each stage task gets its own key."""
    return bool(settings().gateway_master_key)


def mint_key(scan_id: int, usd_budget: float, ttl_s: int, models: list[str], task_id: str | None = None) -> str:
    if not settings().gateway_master_key:
        return os.environ.get(DEV_KEY_ENV, "")
    metadata: dict[str, object] = {"scan_id": scan_id}
    if task_id:
        metadata["task_id"] = task_id
    body = {
        "max_budget": round(float(usd_budget), 4),
        "duration": f"{int(ttl_s)}s",
        "models": sorted(set(models)),
        "metadata": metadata,
    }
    try:
        with _client() as c:
            r = c.post("/key/generate", json=body)
    except httpx.HTTPError as e:
        raise GatewayError(f"key/generate failed: {e}") from e
    if r.status_code >= 400:
        raise GatewayError(f"key/generate HTTP {r.status_code}: {r.text[:300]}")
    key = r.json().get("key")
    if not isinstance(key, str) or not key:
        raise GatewayError("key/generate returned no key")
    return key


def _spend_from(r: httpx.Response) -> float | None:
    if r.status_code >= 400:
        return None
    try:
        info = r.json().get("info") or {}
        spend = info.get("spend")
    except (ValueError, AttributeError):
        return None
    return float(spend) if isinstance(spend, (int, float)) else None


def key_spend(key: str) -> float | None:
    """USD the gateway has booked on `key` (master-key lookup), or None if unknown."""
    if not key or key in _passthrough_keys() or not settings().gateway_master_key:
        return None
    try:
        with _client() as c:
            return _spend_from(c.get("/key/info", params={"key": key}))
    except httpx.HTTPError as e:
        log.warning("gateway key/info failed: %s", e)
        return None


def self_spend(base_url: str, key: str, timeout_s: float = 10.0) -> float | None:
    """USD booked on `key`, asked with the key itself (used inside the sandbox). None if unknown."""
    if not key:
        return None
    try:
        r = httpx.get(f"{base_url.rstrip('/')}/key/info", headers={"Authorization": f"Bearer {key}"}, timeout=timeout_s)
    except httpx.HTTPError:
        return None
    return _spend_from(r)


def revoke_key(key: str) -> None:
    """Best effort: a failed revoke is logged, the key still expires by TTL."""
    if not key or key in _passthrough_keys() or not settings().gateway_master_key:
        return
    try:
        with _client() as c:
            r = c.post("/key/delete", json={"keys": [key]})
        if r.status_code >= 400:
            log.warning("gateway key revoke HTTP %s: %s", r.status_code, r.text[:300])
    except httpx.HTTPError as e:
        log.warning("gateway key revoke failed: %s", e)

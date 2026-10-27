"""Webhook ingest API: verify, normalise, enqueue. Reads nothing from the SCM itself."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from functools import lru_cache
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

from prsec.api.normalize import github_event_to_request
from prsec.config import current_skills_version, load_policy, Policy, settings, Settings
from prsec.db import conn as db_conn
from prsec.db import queue
from prsec.models import ScanRequest
from prsec.obs.logging import setup_logging

log = logging.getLogger("prsec.api")


def get_settings() -> Settings:
    return settings()


@lru_cache
def get_policy() -> Policy:
    return load_policy()


def verify_signature(secret: str, body: bytes, header: str | None) -> bool:
    if not secret or not header or not header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected.encode(), header.encode())


def _enqueue_response(req: ScanRequest, s: Settings, debounce_s: int) -> JSONResponse:
    scan_id = queue.enqueue(req, current_skills_version(s), debounce_s, s.max_supersedes)
    if scan_id is None:
        return JSONResponse({"ignored": "duplicate"}, status_code=200)
    log.info("queued scan %s for %s#%s@%s (%s)%s", scan_id, req.repo, req.pr, req.head_sha, req.reason,
             f" debug={req.debug.model_dump()}" if req.debug else "")
    return JSONResponse({"scan_id": scan_id}, status_code=202)


async def _verified_payload(request: Request, secret: str | None, signature: str | None) -> dict[str, Any]:
    """The HMAC-verified webhook body as a JSON object; raises HTTPException 503/401/400 otherwise."""
    if not secret:
        raise HTTPException(503, "webhook secret not configured")
    body = await request.body()
    if not verify_signature(secret, body, signature):
        raise HTTPException(401, "invalid signature")
    try:
        payload: Any = json.loads(body)
    except ValueError:
        raise HTTPException(400, "invalid JSON") from None
    if not isinstance(payload, dict):
        raise HTTPException(400, "payload must be an object")
    return payload


def _require_admin(s: Settings, header: str | None) -> None:
    token = s.admin_token or os.environ.get("PRSEC_ADMIN_TOKEN", "")
    if not token or not header or not hmac.compare_digest(token.encode(), header.encode()):
        raise HTTPException(403, "forbidden")


def _migrate() -> None:
    with db_conn.get_pool().connection() as c:
        db_conn.migrate(c)


def create_app(migrate_on_startup: bool = True) -> FastAPI:
    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        if migrate_on_startup:
            await run_in_threadpool(_migrate)
        yield
        if migrate_on_startup:
            await run_in_threadpool(db_conn.close_pool)

    app = FastAPI(title="prsec-api", lifespan=lifespan)

    @app.get("/healthz")
    def healthz() -> dict[str, bool]:
        return {"ok": True}

    @app.post(
        "/webhooks/github",
        responses={  # raised by _verified_payload
            400: {"description": "Body is not a JSON object"},
            401: {"description": "Missing or invalid X-Hub-Signature-256"},
            503: {"description": "Webhook secret not configured"},
        },
    )
    async def github_webhook(
        request: Request,
        s: Annotated[Settings, Depends(get_settings)],
        policy: Annotated[Policy, Depends(get_policy)],
        x_github_event: Annotated[str | None, Header()] = None,
        x_hub_signature_256: Annotated[str | None, Header()] = None,
    ) -> JSONResponse:
        payload = await _verified_payload(request, s.github_webhook_secret, x_hub_signature_256)
        if x_github_event == "ping":
            return JSONResponse({"pong": True, "zen": payload.get("zen")})
        req, reason = github_event_to_request(x_github_event or "", payload, policy)
        if req is None:
            return JSONResponse({"ignored": reason})
        return await run_in_threadpool(_enqueue_response, req, s, s.debounce_s)

    @app.post("/scans", responses={403: {"description": "Missing or invalid X-Prsec-Admin token"}})
    def manual_scan(
        req: ScanRequest,
        s: Annotated[Settings, Depends(get_settings)],
        x_prsec_admin: Annotated[str | None, Header()] = None,
    ) -> JSONResponse:
        _require_admin(s, x_prsec_admin)
        # req.debug (log level, keep minutes) rides along into scans.debug; webhooks never set it.
        return _enqueue_response(req.model_copy(update={"reason": "manual"}), s, debounce_s=0)

    return app


app = create_app()


def run() -> None:
    import uvicorn

    setup_logging("api")
    # Loopback by default; the service image and compose stack set PRSEC_API_HOST=0.0.0.0 inside
    # the container, where only Caddy (webhooks) and the private network can reach it.
    uvicorn.run(
        "prsec.api.main:app",
        host=os.environ.get("PRSEC_API_HOST", "127.0.0.1"),
        port=int(os.environ.get("PRSEC_API_PORT", "8080")),
        proxy_headers=True,
        log_config=None,  # uvicorn logs through setup_logging's handler
    )

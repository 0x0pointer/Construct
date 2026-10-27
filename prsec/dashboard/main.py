"""AppSec dashboard (read-mostly). Runs behind an SSO proxy (oauth2-proxy); no auth in-app."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from prsec.adapters.sinks import sarif_store
from prsec.db import findings as db

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
PAGE_SIZE = 50


def _fmt_usd(v: Any) -> str:
    return "-" if v is None else f"${float(v):.2f}"


def _fmt_dur(v: Any) -> str:
    if v is None:
        return "-"
    s = int(v)
    return f"{s // 60}m{s % 60:02d}s" if s >= 60 else f"{s}s"


def _fmt_pct(v: Any) -> str:
    return "-" if v is None else f"{v * 100:.0f}%"


def _fmt_json(v: Any) -> str:
    return json.dumps(v, indent=2, default=str, sort_keys=True)


TEMPLATES.env.filters.update(usd=_fmt_usd, dur=_fmt_dur, pct=_fmt_pct, tojson_pretty=_fmt_json)

app = FastAPI(title="PRSec dashboard", docs_url=None, redoc_url=None)


def _user(request: Request) -> str | None:
    return request.headers.get("x-forwarded-email") or request.headers.get("x-forwarded-user")


def _render(request: Request, name: str, **ctx: Any) -> HTMLResponse:
    return TEMPLATES.TemplateResponse(request, name, {"user": _user(request), **ctx})


def _clean(params: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in params.items() if v not in (None, "")}


@app.get("/healthz", response_class=PlainTextResponse)
def healthz() -> str:
    return "ok"


@app.get("/", response_class=HTMLResponse)
def scans(request: Request, repo: str | None = None, status: str | None = None, pr: int | None = None, page: int = 1):
    filters = _clean({"repo": repo, "status": status, "pr": pr})
    page = max(page, 1)
    rows = db.list_scans(filters, limit=PAGE_SIZE + 1, offset=(page - 1) * PAGE_SIZE)
    return _render(
        request,
        "scans.html",
        scans=rows[:PAGE_SIZE],
        filters=filters,
        page=page,
        has_next=len(rows) > PAGE_SIZE,
        statuses=["queued", "running", "done", "skipped", "failed", "superseded"],
    )


@app.get("/scans/{scan_id}", response_class=HTMLResponse)
def scan_detail(request: Request, scan_id: int):
    scan = db.get_scan(scan_id)
    if scan is None:
        raise HTTPException(404, "scan not found")
    return _render(request, "scan.html", scan=scan)


@app.get("/findings", response_class=HTMLResponse)
def findings(
    request: Request,
    repo: str | None = None,
    label: str | None = None,
    bug_class: str | None = None,
    triage_state: str | None = None,
    status: str | None = None,
    severity: str | None = None,
    page: int = 1,
):
    filters = _clean(
        {"repo": repo, "label": label, "bug_class": bug_class, "triage_state": triage_state, "status": status, "severity": severity}
    )
    page = max(page, 1)
    rows = db.list_findings(filters, limit=PAGE_SIZE + 1, offset=(page - 1) * PAGE_SIZE)
    ctx = dict(findings=rows[:PAGE_SIZE], filters=filters, page=page, has_next=len(rows) > PAGE_SIZE)
    if request.headers.get("hx-request") and request.headers.get("hx-target") == "findings-table":
        return _render(request, "_findings_table.html", **ctx)
    return _render(
        request,
        "findings.html",
        options={
            **db.distinct_values(),
            "label": ["reproduced", "likely", "inconclusive"],
            "triage_state": list(db.TRIAGE_STATES),
            "status": list(db.FINDING_STATUSES),
            "severity": ["critical", "high", "medium", "low", "info"],
        },
        **ctx,
    )


@app.get("/findings/{finding_id}", response_class=HTMLResponse)
def finding_detail(request: Request, finding_id: int):
    f = db.get_finding(finding_id)
    if f is None:
        raise HTTPException(404, "finding not found")
    data = f["data"] or {}
    flow = []
    if data.get("source"):
        flow.append(("source", data["source"]))
    flow.extend((f"step {i}", p) for i, p in enumerate(data.get("path") or [], 1))
    flow.append(("sink", data.get("sink") or {"file": f["sink_file"], "line": f["sink_line"]}))
    return _render(request, "finding.html", f=f, data=data, flow=flow, triage_states=db.TRIAGE_STATES)


@app.post("/findings/{finding_id}/triage", response_class=HTMLResponse)
def triage(request: Request, finding_id: int, state: str = Form(...), note: str = Form("")):
    if state not in db.TRIAGE_STATES:
        raise HTTPException(422, f"state must be one of {db.TRIAGE_STATES}")
    row = db.set_triage(finding_id, state, note, actor=_user(request))
    if row is None:
        raise HTTPException(404, "finding not found")
    if not request.headers.get("hx-request"):
        return RedirectResponse(f"/findings/{finding_id}", status_code=303)
    return _render(request, "_triage.html", f={"id": finding_id, **row}, triage_states=db.TRIAGE_STATES, saved=True)


@app.get("/metrics", response_class=HTMLResponse)
def metrics(request: Request):
    return _render(request, "metrics.html", m=db.metrics())


@app.get("/sarif/{scan_id}")
def sarif(scan_id: int) -> Response:
    scan = db.get_scan(scan_id)
    if scan is None or not scan.get("sarif_uri"):
        raise HTTPException(404, "no SARIF for this scan")
    try:
        body = sarif_store.read_uri(scan["sarif_uri"])
    except (FileNotFoundError, PermissionError, ValueError) as e:
        raise HTTPException(404, f"SARIF unavailable: {e}") from e
    name = f"prsec-{scan['repo'].replace('/', '_')}-{scan['pr']}-{scan['head_sha'][:12]}.sarif"
    return Response(
        body,
        media_type="application/sarif+json",
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )


def _artifact(uri: str | None, what: str) -> bytes:
    if not uri:
        raise HTTPException(404, f"no {what} stored")
    try:
        return sarif_store.read_uri(uri)
    except (FileNotFoundError, PermissionError, ValueError) as e:
        raise HTTPException(404, f"{what} unavailable: {e}") from e
    except Exception as e:  # object store errors
        raise HTTPException(502, f"{what} unavailable: {type(e).__name__}") from e


@app.get("/stage-runs/{stage_run_id}/transcript", response_class=PlainTextResponse)
def stage_transcript(stage_run_id: int) -> Response:
    body = _artifact(db.stage_run_transcript_uri(stage_run_id), "transcript")
    return Response(body, media_type="text/plain; charset=utf-8")


@app.get("/findings/{finding_id}/evidence", response_class=PlainTextResponse)
def finding_evidence(finding_id: int) -> Response:
    f = db.get_finding(finding_id)
    if f is None:
        raise HTTPException(404, "finding not found")
    body = _artifact((f["data"] or {}).get("evidence_uri"), "evidence")
    return Response(body, media_type="text/plain; charset=utf-8")


def run() -> None:
    import uvicorn

    uvicorn.run("prsec.dashboard.main:app", host="0.0.0.0", port=8081, proxy_headers=True, forwarded_allow_ips="*")

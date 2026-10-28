"""AppSec dashboard (read-mostly). Runs behind an SSO proxy (oauth2-proxy); no auth in-app."""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlencode, urlsplit

import yaml
from fastapi import FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from prsec.adapters.sinks import sarif_store
from prsec.db import findings as db
from prsec.models import Stage
from prsec.obs import events as obs_events
from prsec.obs.logging import setup_logging

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
PAGE_SIZE = 50
FINDING_NOT_FOUND = "finding not found"
SCAN_NOT_FOUND = "scan not found"
TIMELINE_INITIAL = 2000  # events rendered with the page; the poller fetches the rest
TIMELINE_PAGE = 500  # events per poll
ACTIVE_STATUSES = frozenset({"queued", "running"})
EVIDENCE_KINDS = frozenset({"replay", "dynamic_outcome", "label", "kept"})
DATA_KEYS_MAX = 20
DATA_VALUE_MAX = 300
# Stored artifacts are agent/PR-derived text: always served as text/plain, never sniffed as HTML.
PLAIN_HEADERS = {"X-Content-Type-Options": "nosniff"}



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

# ---------------------------------------------------- per-agent observability

# Friendly names and canonical pipeline order (single source of truth: the Stage enum).
STAGE_ROLES = {
    "rules": "Rules gate", "triage": "Triage", "hypothesise": "Hypothesise",
    "static_verify": "Static verify", "skeptic": "Skeptic", "env": "Env builder", "dynamic": "Dynamic",
}
STAGE_ORDER = {s.value: i for i, s in enumerate(Stage)}


def _stage_summary(stage: str | None, output: Any) -> str:
    """One-line, human-readable decision for an agent stage, derived from its structured output."""
    if not isinstance(output, dict):
        return ""
    g = output.get
    if stage == "rules":
        return " — ".join(x for x in (g("decision"), g("reason")) if x)
    if stage == "triage":
        tags = g("risk_tags") or []
        return str(g("decision") or "") + (f" · {', '.join(tags)}" if tags else "")
    if stage == "hypothesise":
        hyps = g("hypotheses") or []
        ids = ", ".join(h.get("id", "") for h in hyps if isinstance(h, dict))
        return f"{len(hyps)} hypothesis(es)" + (f": {ids}" if ids else "")
    if stage == "static_verify":
        return " · ".join(str(x) for x in (g("verdict"), g("severity"),
                                           f"reachable={g('reachable')}" if g("reachable") else None) if x)
    if stage == "skeptic":
        return ("refuted" if g("refuted") else "upheld") + (f" ({g('confidence')})" if g("confidence") else "")
    if stage == "env":
        return "envspec written" if g("envspec") else str(g("notes") or "")[:80]
    if stage == "dynamic":
        return " — ".join(x for x in (g("outcome"), g("reason")) if x)
    return ""


def _turns(usage: Any) -> int:
    return int((usage or {}).get("turns") or 0) if isinstance(usage, dict) else 0


def _enrich_stage_runs(stage_runs: list[dict[str, Any]]) -> None:
    """Attach a friendly role name, decision summary and turn count to each stage run (in place)."""
    for r in stage_runs:
        st = r.get("stage")
        r["role"] = STAGE_ROLES.get(st, st)
        r["summary"] = _stage_summary(st, r.get("output"))
        r["turns"] = _turns(r.get("usage"))


def _agent_pipeline(stage_runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Per-agent rollup for one scan: one row per canonical stage, in pipeline order.

    Fan-out stages (static_verify, skeptic run per hypothesis) collapse into a single agent row
    whose decisions list every run's verdict.
    """
    agents: dict[str, dict[str, Any]] = {}
    for r in stage_runs:
        st = r.get("stage") or "?"
        a = agents.setdefault(st, {"stage": st, "role": STAGE_ROLES.get(st, st), "runs": 0, "ok": 0,
                                   "failed": 0, "cost": 0.0, "tokens": 0, "turns": 0, "duration_s": 0.0,
                                   "decisions": []})
        usage = r.get("usage") if isinstance(r.get("usage"), dict) else {}
        a["runs"] += 1
        a["ok" if r.get("status") == "ok" else "failed"] += 1
        a["cost"] += float(usage.get("usd") or 0)
        a["tokens"] += int(usage.get("tokens_in") or 0) + int(usage.get("tokens_out") or 0)
        a["turns"] += _turns(usage)
        a["duration_s"] += float(r.get("duration_s") or 0)
        if summary := _stage_summary(st, r.get("output")):
            a["decisions"].append(summary)
    rows = sorted(agents.values(), key=lambda a: STAGE_ORDER.get(a["stage"], 99))
    for a in rows:
        a["health"] = "ok" if a["failed"] == 0 else ("failed" if a["ok"] == 0 else "partial")
    return rows


def _user(request: Request) -> str | None:
    return request.headers.get("x-forwarded-email") or request.headers.get("x-forwarded-user")


def _render(request: Request, name: str, **ctx: Any) -> HTMLResponse:
    return TEMPLATES.TemplateResponse(request, name, {"user": _user(request), **ctx})


def _local_path(path: str, fallback: str = "/findings") -> str:
    """`path` if it is a same-site absolute path, else `fallback`: never redirect off-site.

    Refuses anything with a scheme or host, protocol-relative `//host`, backslashes (browsers read
    `/\\host` as `//host`) and control characters (stripped by browsers before parsing).
    """
    parts = urlsplit(path)
    if (
        not path.startswith("/")
        or path.startswith("//")
        or "\\" in path
        or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in path)
        or parts.scheme
        or parts.netloc
    ):
        return fallback
    return path


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


@app.get("/scans/{scan_id}", response_class=HTMLResponse, responses={404: {"description": "Scan not found"}})
def scan_detail(request: Request, scan_id: int):
    scan = db.get_scan(scan_id)
    if scan is None:
        raise HTTPException(404, SCAN_NOT_FOUND)
    stage_runs = scan.get("stage_runs") or []
    _enrich_stage_runs(stage_runs)
    agents = _agent_pipeline(stage_runs)
    events = obs_events.list_events(scan_id, after_id=0, limit=TIMELINE_INITIAL)
    return _render(request, "scan.html", scan=scan, agents=agents,
                   tl=_timeline_ctx(scan, events, 0, set(), TIMELINE_INITIAL))


@app.get("/scans/{scan_id}/events", response_class=HTMLResponse, responses={404: {"description": "Scan not found"}})
def scan_events(request: Request, scan_id: int, after_id: int = 0, g: Annotated[list[str] | None, Query()] = None):
    """HTMX poll: events after `after_id`, appended to the page out of band. `g` lists the agent
    groups already on the page, so their new events go into the existing (collapsible) group."""
    scan = db.get_scan(scan_id)  # status first: every event written before it turned final is fetched below
    if scan is None:
        raise HTTPException(404, SCAN_NOT_FOUND)
    events = obs_events.list_events(scan_id, after_id=max(after_id, 0), limit=TIMELINE_PAGE)
    tl = _timeline_ctx(scan, events, max(after_id, 0), set(g or []), TIMELINE_PAGE)
    return _render(request, "_timeline_poll.html", scan=scan, tl=tl)


# ---------------------------------------------------------------- timeline


def _group_dom_id(key: str) -> str:
    return "ag-" + hashlib.sha256(key.encode()).hexdigest()[:12]


def _kv(data: Any) -> list[tuple[str, str]]:
    """An event's data as short (key, text) pairs for the key/value list."""
    if not isinstance(data, dict):
        return []
    pairs = []
    for k, v in list(data.items())[:DATA_KEYS_MAX]:
        text = v if isinstance(v, str) else json.dumps(v, default=str, separators=(", ", ": "))
        pairs.append((str(k), text if len(text) <= DATA_VALUE_MAX else text[: DATA_VALUE_MAX - 3] + "..."))
    return pairs


def _int_or_none(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _finding_link(ev: dict[str, Any], data: dict[str, Any], by_hyp: dict[str, int]) -> int | None:
    """The finding an evidence event is about: data.finding_id, else the scan's finding of its hypothesis."""
    if ev.get("kind") not in EVIDENCE_KINDS:
        return None
    return _int_or_none(data.get("finding_id")) or by_hyp.get(str(ev.get("hypothesis_id") or ""))


def _event_view(ev: dict[str, Any], transcripts: dict[str, int], by_hyp: dict[str, int] | None = None) -> dict[str, Any]:
    ts = ev.get("ts")
    data = ev.get("data") if isinstance(ev.get("data"), dict) else {}
    finding_id = _finding_link(ev, data, by_hyp or {})
    return {
        **ev,
        "level": str(ev.get("level") or "info").lower(),
        "clock": ts.strftime("%H:%M:%S") if isinstance(ts, datetime) else str(ts or "")[11:19],
        "iso": ts.isoformat() if isinstance(ts, datetime) else str(ts or ""),
        "kv": _kv(data),
        "transcript_id": transcripts.get(ev.get("task_id") or ""),
        "finding_id": finding_id,
    }


def _timeline(
    events: list[dict[str, Any]], known: set[str], transcripts: dict[str, int], by_hyp: dict[str, int] | None = None
) -> tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    """Split events into top-level items (event rows, or new agent groups in order of first
    appearance) and agent rows for groups already on the page (by DOM id)."""
    items: list[dict[str, Any]] = []
    groups: dict[str, dict[str, Any]] = {}
    appended: dict[str, list[dict[str, Any]]] = {}
    for ev in events:
        view = _event_view(ev, transcripts, by_hyp)
        if ev.get("kind") != "agent":
            items.append({"type": "event", "ev": view})
            continue
        key = str(ev.get("task_id") or ev.get("stage") or "scan")
        if key in known:
            appended.setdefault(_group_dom_id(key), []).append(view)
            continue
        if key not in groups:
            groups[key] = {"type": "group", "key": key, "dom_id": _group_dom_id(key), "stage": ev.get("stage"),
                           "task_id": ev.get("task_id"), "transcript_id": view["transcript_id"], "events": []}
            items.append(groups[key])
        groups[key]["events"].append(view)
    return items, appended


def _timeline_ctx(
    scan: dict[str, Any], events: list[dict[str, Any]], after_id: int, known: set[str], page: int
) -> dict[str, Any]:
    transcripts = {r["task_id"]: r["id"] for r in scan.get("stage_runs") or [] if r.get("transcript_uri")}
    # Findings are written at the end of the scan; until then label/replay rows have no link.
    by_hyp = {str(f["hypothesis_id"]): int(f["id"]) for f in scan.get("findings") or [] if f.get("hypothesis_id")}
    items, appended = _timeline(events, known, transcripts, by_hyp)
    last_id = int(events[-1]["id"]) if events else after_id
    groups = sorted(known | {i["key"] for i in items if i["type"] == "group"})
    query = urlencode({"after_id": last_id, "g": groups}, doseq=True)
    return {
        "items": items,
        "appended": appended,
        "live": scan.get("status") in ACTIVE_STATUSES or len(events) >= page,
        "poll_url": f"/scans/{int(scan['id'])}/events?{query}",
        "count": len(events),
    }


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
    ctx = {"findings": rows[:PAGE_SIZE], "filters": filters, "page": page, "has_next": len(rows) > PAGE_SIZE}
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


@app.get("/findings/{finding_id}", response_class=HTMLResponse, responses={404: {"description": "Finding not found"}})
def finding_detail(request: Request, finding_id: int):
    f = db.get_finding(finding_id)
    if f is None:
        raise HTTPException(404, FINDING_NOT_FOUND)
    data = f["data"] or {}
    flow = []
    if data.get("source"):
        flow.append(("source", data["source"]))
    flow.extend((f"step {i}", p) for i, p in enumerate(data.get("path") or [], 1))
    flow.append(("sink", data.get("sink") or {"file": f["sink_file"], "line": f["sink_line"]}))
    return _render(request, "finding.html", f=f, data=data, flow=flow, dyn=_dynamic_view(data.get("dynamic")),
                   triage_states=db.TRIAGE_STATES)


def _dynamic_view(dyn: dict[str, Any] | None) -> dict[str, Any] | None:
    """Phase-2 evidence for the finding page: the PoC as YAML, each replay tagged head or base."""
    if not dyn:
        return None
    poc = dyn.get("poc")
    replays = [{**r, "target": "base" if str(r.get("run_id", "")).endswith("-base") else "head"}
               for r in dyn.get("replays") or []]
    poc_yaml = yaml.safe_dump(poc, sort_keys=False, allow_unicode=True) if poc else None
    return {**dyn, "replays": replays, "poc_yaml": poc_yaml}


@app.post(
    "/findings/{finding_id}/triage",
    response_class=HTMLResponse,
    responses={404: {"description": "Finding not found"}, 422: {"description": "Unknown triage state"}},
)
def triage(request: Request, finding_id: int, state: Annotated[str, Form()], note: Annotated[str, Form()] = ""):
    if state not in db.TRIAGE_STATES:
        raise HTTPException(422, f"state must be one of {db.TRIAGE_STATES}")
    row = db.set_triage(finding_id, state, note, actor=_user(request))
    if row is None:
        raise HTTPException(404, FINDING_NOT_FOUND)
    if not request.headers.get("hx-request"):
        # Built from the database row's integer id, and still checked to stay on this site.
        return RedirectResponse(_local_path(f"/findings/{int(row['id'])}"), status_code=303)
    return _render(request, "_triage.html", f={"id": finding_id, **row}, triage_states=db.TRIAGE_STATES, saved=True)


@app.get("/metrics", response_class=HTMLResponse)
def metrics(request: Request):
    return _render(request, "metrics.html", m=db.metrics())


@app.get("/sarif/{scan_id}", responses={404: {"description": "No SARIF stored for this scan, or it is unreadable"}})
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


@app.get(
    "/stage-runs/{stage_run_id}/transcript",
    response_class=PlainTextResponse,
    responses={404: {"description": "Artifact not stored or unreadable"}, 502: {"description": "Object store error"}},
)
def stage_transcript(stage_run_id: int) -> Response:
    body = _artifact(db.stage_run_transcript_uri(stage_run_id), "transcript")
    return PlainTextResponse(body, headers=PLAIN_HEADERS)  # NOSONAR(S5131) text/plain + nosniff: never rendered as HTML


@app.get(
    "/findings/{finding_id}/evidence",
    response_class=PlainTextResponse,
    responses={404: {"description": "Artifact not stored or unreadable"}, 502: {"description": "Object store error"}},
)
def finding_evidence(finding_id: int) -> Response:
    f = db.get_finding(finding_id)
    if f is None:
        raise HTTPException(404, FINDING_NOT_FOUND)
    body = _artifact((f["data"] or {}).get("evidence_uri"), "evidence")
    return PlainTextResponse(body, headers=PLAIN_HEADERS)  # NOSONAR(S5131) text/plain + nosniff: never rendered as HTML


@app.get(
    "/findings/{finding_id}/dynamic-evidence",
    response_class=PlainTextResponse,
    responses={404: {"description": "Artifact not stored or unreadable"}, 502: {"description": "Object store error"}},
)
def finding_dynamic_evidence(finding_id: int) -> Response:
    f = db.get_finding(finding_id)
    if f is None:
        raise HTTPException(404, FINDING_NOT_FOUND)
    body = _artifact(((f["data"] or {}).get("dynamic") or {}).get("evidence_uri"), "dynamic evidence")
    return PlainTextResponse(body, headers=PLAIN_HEADERS)  # NOSONAR(S5131) text/plain + nosniff: never rendered as HTML


def run() -> None:
    import uvicorn

    setup_logging("dashboard")
    # Loopback by default; the prsec image and compose stack set PRSEC_DASHBOARD_HOST=0.0.0.0 so
    # oauth2-proxy can reach it. That port is NOT isolated: every service on the compose `control`
    # network (llm-gateway included, which also joins the per-scan networks) can connect directly,
    # and identity comes from X-Forwarded-* headers trusted from any peer (forwarded_allow_ips="*").
    # Do not publish this port; only oauth2-proxy should be the dashboard's entry point.
    uvicorn.run(
        "prsec.dashboard.main:app",
        host=os.environ.get("PRSEC_DASHBOARD_HOST", "127.0.0.1"),
        port=int(os.environ.get("PRSEC_DASHBOARD_PORT", "8081")),
        proxy_headers=True,
        forwarded_allow_ips="*",
        log_config=None,  # uvicorn logs through setup_logging's handler
    )

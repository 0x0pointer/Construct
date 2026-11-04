"""prsec-eval: run labelled eval cases through the real pipeline and score them against expected.json.

    prsec-eval list                                   cases (dynamic ones marked)
    prsec-eval run [CASE ...] [--tag dynamic] [--out DIR] [--timeout S]
    prsec-eval score SCAN_ID [SCAN_ID ...] [--out DIR]  re-score finished eval scans

`run` queues one scan per case (scm "evals", repo evals/<case-id>, a fresh PR number) and waits for
workers to finish them, then scores each scan and writes report.json + report.md. Workers must run
against the same database with the runner, policy and models under test: `prsec-worker` locally,
the worker Deployment in a cluster. Nothing here talks to an LLM itself.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from prsec.config import current_skills_version, settings
from prsec.evals.cases import DEFAULT_CASES, REPO_OWNER, Case, CaseSCM, case_sha, list_cases
from prsec.evals.score import FINAL_STATUSES, CaseScore, Observed, Reported, render_markdown, score_case, summarize

TIMELINE_KINDS = ("hypotheses", "static_verdict", "hypothesis_dropped", "dynamic_outcome")


# ------------------------------------------------------------------ database


def _db():
    from prsec.db.conn import get_pool

    return get_pool().connection()


def _scan_row(scan_id: int) -> dict[str, Any] | None:
    with _db() as c:
        return c.execute(
            "SELECT id, repo, pr, status, triage, error, cost_usd, sarif_uri, started_at, finished_at"
            " FROM scans WHERE id = %s", (scan_id,)).fetchone()


def _events(scan_id: int) -> list[dict[str, Any]]:
    with _db() as c:
        return c.execute("SELECT kind, hypothesis_id, data FROM scan_events WHERE scan_id = %s AND kind = ANY(%s)"
                         " ORDER BY id", (scan_id, list(TIMELINE_KINDS))).fetchall()


def enqueue(case: Case, number: int) -> int:
    from prsec.db import queue
    from prsec.models import ScanRequest

    req = ScanRequest(scm=REPO_OWNER, repo=f"{REPO_OWNER}/{case.id}", pr=number, head_sha=case_sha(number),
                      base_sha=case_sha(number, base=True), reason="manual")
    scan_id = queue.enqueue(req, current_skills_version(), 0, 5)
    if scan_id is None:
        raise RuntimeError(f"{case.id}: scan for PR #{number} already known; pick another --pr")
    return scan_id


# --------------------------------------------------------------- observation


def _triage(row: dict[str, Any]) -> str | None:
    t = row.get("triage") or {}
    decision = t.get("decision") or (t.get("rules") or {}).get("decision")
    return decision or ("skip" if row["status"] == "skipped" else None)


def _rules_arms(row: dict[str, Any]) -> dict[str, str | None]:
    """skip|scan per rules arm: the primary agent and every shadow arm (policy `shadows`)."""
    t = row.get("triage") or {}
    rec = t.get("rules") or {}
    if not rec:
        return {}
    arms: dict[str, str | None] = {"primary": rec.get("decision")}
    arms.update({str(sh.get("name")): sh.get("decision") for sh in rec.get("shadows") or []})
    return arms


def _sarif_results(uri: str | None) -> list[dict[str, Any]]:
    if not uri:
        return []
    from prsec.adapters.sinks.sarif_store import read_uri

    doc = json.loads(read_uri(uri))
    return [r for run in doc.get("runs") or [] for r in run.get("results") or []]


def _reported(res: dict[str, Any], verdicts: dict[str, str]) -> Reported:
    loc = (res.get("locations") or [{}])[0].get("physicalLocation") or {}
    props = res.get("properties") or {}
    hid = str(props.get("hypothesis_id") or "")
    return Reported(
        bug_class=str(res.get("ruleId") or ""), file=unquote((loc.get("artifactLocation") or {}).get("uri", "")),
        line=int((loc.get("region") or {}).get("startLine") or 0), label=str(props.get("label") or ""),
        severity=str(props.get("severity") or ""), hypothesis_id=hid, introduced=props.get("introduced"),
        static_verdict=verdicts.get(hid), dynamic=(props.get("dynamic") or {}).get("outcome"),
    )


def observe(scan_id: int) -> tuple[dict[str, Any], Observed]:
    """The scan row and what the scan produced (SARIF results + timeline facts)."""
    row = _scan_row(scan_id)
    if row is None:
        raise RuntimeError(f"no scan {scan_id}")
    hypotheses: dict[str, str] = {}
    verdicts: dict[str, str] = {}
    dropped: dict[str, str] = {}
    dynamic: dict[str, str] = {}
    for ev in _events(scan_id):
        data, hid = ev.get("data") or {}, ev.get("hypothesis_id")
        if ev["kind"] == "hypotheses":
            hypotheses.update({h["id"]: h.get("bug_class", "") for h in data.get("hypotheses") or []})
        elif ev["kind"] == "static_verdict" and hid and data.get("verdict"):
            verdicts[hid] = data["verdict"]
        elif ev["kind"] == "hypothesis_dropped" and hid:
            dropped[hid] = str(data.get("reason") or "dropped")
        elif ev["kind"] == "dynamic_outcome" and hid and data.get("outcome"):
            dynamic[hid] = data["outcome"]
    started, finished = row.get("started_at"), row.get("finished_at")
    obs = Observed(
        scan_id=scan_id, status=row["status"], triage=_triage(row),
        findings=[_reported(r, verdicts) for r in _sarif_results(row.get("sarif_uri"))],
        hypotheses=hypotheses, dropped=dropped, dynamic=dynamic, rules=_rules_arms(row), error=row.get("error"),
        cost_usd=float(row.get("cost_usd") or 0),
        duration_s=(finished - started).total_seconds() if started and finished else None,
    )
    return row, obs


def wait(scan_ids: dict[int, str], timeout_s: float, poll_s: float = 15.0) -> None:
    """Until every scan is final (or the timeout); prints each status change."""
    seen: dict[int, str] = {}
    deadline = time.monotonic() + timeout_s
    while True:
        for sid, case_id in scan_ids.items():
            row = _scan_row(sid) or {"status": "missing"}
            if seen.get(sid) != row["status"]:
                seen[sid] = row["status"]
                print(f"{datetime.now(UTC):%H:%M:%S} scan {sid} ({case_id}): {row['status']}", flush=True)
        if all(s in FINAL_STATUSES for s in seen.values()):
            return
        if time.monotonic() >= deadline:
            print(f"timeout after {timeout_s:.0f}s; scoring what finished", file=sys.stderr)
            return
        time.sleep(poll_s)


# ------------------------------------------------------------------- report


def aliases() -> dict[str, str]:
    """alias -> canonical bug class from the mounted skills' bug-classes.yaml (else the repo's copy)."""
    from prsec.skills_lint import bug_class_aliases

    for root in (settings().skills_dir, DEFAULT_CASES.parents[1]):
        if (root / "bug-classes.yaml").is_file():
            return bug_class_aliases(root)
    return {}


def score_scans(scan_ids: list[int]) -> list[CaseScore]:
    known = aliases()
    scm = CaseSCM()
    scores = []
    for sid in scan_ids:
        row, obs = observe(sid)
        scores.append(score_case(scm.case(row["repo"]), obs, known))
    return scores


def write_report(scores: list[CaseScore], meta: dict[str, Any], out: Path) -> dict[str, Any]:
    summary = summarize(scores)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(json.dumps(
        {"meta": meta, "summary": summary, "cases": [s.to_dict() for s in scores]}, indent=2, default=str))
    md = render_markdown(scores, summary, meta)
    (out / "report.md").write_text(md)
    print(md)
    print(f"report: {out / 'report.md'}")
    return summary


def _meta(run: str) -> dict[str, Any]:
    s = settings()
    return {"run": run, "started_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "policy": str(s.policy_path), "skills_version": current_skills_version(), "runner": s.runner}


def select(cases: list[Case], ids: list[str], tag: str | None) -> list[Case]:
    by_id = {c.id: c for c in cases}
    unknown = [i for i in ids if i not in by_id]
    if unknown:
        raise SystemExit(f"unknown case(s): {', '.join(unknown)}; see `prsec-eval list`")
    picked = [by_id[i] for i in ids] if ids else cases
    return [c for c in picked if not tag or tag in c.tags]


# ---------------------------------------------------------------------- CLI


def _cmd_list(_: argparse.Namespace) -> int:
    for c in list_cases(CaseSCM().root):
        flags = ", ".join(t for t in c.tags) or "-"
        print(f"{c.id:28} {'dynamic' if c.dynamic else 'static ':8} {flags}")
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    cases = select(list_cases(CaseSCM().root), args.cases, args.tag)
    if not cases:
        print("no cases selected", file=sys.stderr)
        return 2
    number = args.pr or int(time.time()) % 2_000_000_000  # fresh PR number: scans are unique per head
    run = f"{datetime.now(UTC):%Y%m%dT%H%M%SZ}-pr{number}"
    scan_ids = {enqueue(c, number): c.id for c in cases}
    print(f"queued {len(scan_ids)} eval scan(s) as PR #{number}: "
          + ", ".join(f"{sid}={cid}" for sid, cid in scan_ids.items()), flush=True)
    wait(scan_ids, args.timeout, args.poll)
    summary = write_report(score_scans(list(scan_ids)), _meta(run), Path(args.out or f"work/evals/{run}"))
    return 0 if summary["passed"] == summary["cases"] else 1


def _cmd_score(args: argparse.Namespace) -> int:
    run = f"rescore-{datetime.now(UTC):%Y%m%dT%H%M%SZ}"
    summary = write_report(score_scans(args.scan_ids), _meta(run), Path(args.out or f"work/evals/{run}"))
    return 0 if summary["passed"] == summary["cases"] else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="prsec-eval", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="list the eval cases").set_defaults(fn=_cmd_list)
    r = sub.add_parser("run", help="queue the cases, wait for the workers, score")
    r.add_argument("cases", nargs="*", help="case ids (default: all)")
    r.add_argument("--tag", help="only cases with this tag, e.g. dynamic")
    r.add_argument("--pr", type=int, help="PR number to use (default: derived from the clock)")
    r.add_argument("--timeout", type=float, default=6 * 3600, help="seconds to wait for the scans (default 6h)")
    r.add_argument("--poll", type=float, default=15.0, help="seconds between status checks")
    r.add_argument("--out", help="report dir (default work/evals/<run>)")
    r.set_defaults(fn=_cmd_run)
    s = sub.add_parser("score", help="score finished eval scans again")
    s.add_argument("scan_ids", nargs="+", type=int)
    s.add_argument("--out", help="report dir (default work/evals/rescore-<time>)")
    s.set_defaults(fn=_cmd_score)
    args = p.parse_args(argv)
    from prsec.obs.logging import setup_logging

    setup_logging("eval")
    return int(args.fn(args))


if __name__ == "__main__":
    raise SystemExit(main())

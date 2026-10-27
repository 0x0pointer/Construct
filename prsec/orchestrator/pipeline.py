"""Scan pipeline: rules -> triage -> hypothesise -> static_verify (fan-out) -> skeptic -> dynamic -> verdict -> sink.

Phase 2 (`prsec.orchestrator.dynamic`) runs after the skeptics: an env stage, then per selected
survivor a dynamic stage in its own environment and agent-free replays on head and base. Its
DynamicEvidence feeds `verdict.decide` (reproduced / introduced) and is stored on the Finding; any
dynamic failure is recorded there, never a scan failure.

Ownership: every write about the scan (stage runs, terminal status) carries the worker's lease token,
and the pipeline stops at the next stage boundary once the lease is gone (superseded, or requeued
after a stall and leased by someone else). A scan whose hypothesise stage failed is *incomplete*:
its SARIF says executionSuccessful=false, nothing is marked stale, and it finishes `failed` (retried).

Observability: every meaningful step is a `prsec.obs.events` timeline event with a short human
reason, and the scan / each stage run inside `prsec.obs.logging.bind(...)` so every log line carries
scan_id, task_id, stage, hypothesis_id and env. While a stage runs its live agent stream
(<out_dir>/events.jsonl) is relayed as `agent` events. A scan requested with debug.keep_minutes > 0
keeps its work dir and environments (`kept`) until the worker's `reap_kept` tears them down.
"""
from __future__ import annotations

import contextvars
import fnmatch
import json
import logging
import re
import shutil
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ValidationError

from prsec import gateway, triage_rules
from prsec.adapters import runner as runner_pkg
from prsec.adapters import scm as scm_pkg
from prsec.adapters import sinks as sinks_pkg
from prsec.adapters.protocols import Runner, WorkbenchSpec
from prsec.adapters.runner.common import EventTail
from prsec.citations import repo_relative
from prsec.config import Policy, current_skills_version, load_policy, settings
from prsec.db import queue
from prsec.dynamic.results import DynamicEvidence
from prsec.models import (
    CodeLoc,
    Finding,
    Label,
    PRInfo,
    ScanDebug,
    ScanRequest,
    ScanStatus,
    Severity,
    Stage,
    StageResult,
    StageStatus,
    StageTask,
)
from prsec.obs import events as timeline
from prsec.obs.logging import bind, child_log_env, submit_with_context
from prsec.orchestrator import dynamic, stages, verdict
from prsec.orchestrator.symbols import enclosing_symbol
from prsec.sarif.fingerprint import fingerprint
from prsec.stages.outputs import (
    Citation,
    HypothesesOutput,
    Hypothesis,
    SkepticOutput,
    StaticVerifyOutput,
    TriageOutput,
    model_for,
)

log = logging.getLogger(__name__)

VERIFY_CONCURRENCY = 3
KEY_GRACE_S = 600  # gateway key TTL beyond the stage wall clock
MAX_PRIOR_FINDINGS = 25
_SEV_RANK = {Severity.info: 0, Severity.low: 1, Severity.medium: 2, Severity.high: 3, Severity.critical: 4}
_LABEL_RANK = {Label.inconclusive: 0, Label.likely: 1, Label.reproduced: 2}
_BASE_FILES = ["pr.json", "diff.patch", "changed_files.txt"]
AGENT_FLUSH_S = 2.0  # live agent events reach the timeline in batches at most this often
AGENT_TEXT_MAX = 2000
AGENT_BATCH_MAX = 100  # per flush; the rest of a burst is summarised
_DROP_REASONS = {
    "hypothesis_citations_unverified": "its citations do not match the code at head",
    "over_cap": "over the max_hypotheses cap",
    "below_static_verify_min_severity": "severity guess below the static-verify floor",
    "static_refuted": "static verification refuted it",
    "static_citations_unverified": "static verification cited code that does not exist at head",
}


class Superseded(Exception):
    pass


class LeaseLost(Exception):
    """Another worker now owns this scan (our lease expired); stop without writing anything."""


# ------------------------------------------------- seams (lazy, monkeypatchable)


def _verify_all(cits: list[Citation], src_root: Path) -> list[str]:
    from prsec.citations import verify_all

    return verify_all(cits, src_root)


def _snippet(src_root: Path, file: str, line: int, end_line: int | None) -> str:
    from prsec.citations import snippet

    return snippet(src_root, file, line, end_line)


def _open_findings(repo: str, pr: int) -> list[dict]:
    from prsec.db.findings import open_findings

    return open_findings(repo, pr, limit=MAX_PRIOR_FINDINGS)


def _put_evidence(key: str, data: bytes, content_type: str) -> str:
    from prsec.adapters.sinks.sarif_store import put_bytes

    return put_bytes(key, data, content_type)


# --------------------------------------------------------------------- context


@dataclass
class Ctx:
    scan_id: int
    repo: str
    pr: PRInfo
    policy: Policy
    root: Path
    src: Path
    runner: Runner
    network: str | None
    gw_key: str
    image: str
    skills_version: str
    shared: dict[str, str] = field(default_factory=dict)  # file name -> content copied into every task
    lease_token: str | None = None
    per_task_keys: bool = False  # mint a gateway key per task (authoritative per-stage cost + cap)
    scm: Any = None  # phase 2: fetches the base source for the base replay
    installation_id: int | None = None
    keep: bool = False  # debug.keep_minutes > 0: leave environments and work dirs for inspection

    def emit(self, kind: str, message: str, **kw: Any) -> None:
        timeline.emit(self.scan_id, kind, message, **kw)

    def check(self) -> None:
        if queue.is_superseded(self.scan_id):
            raise Superseded("a newer head of the PR was queued")
        if self.lease_token and not queue.owns_lease(self.scan_id, self.lease_token):
            raise LeaseLost()


@dataclass
class Ran:
    task: StageTask
    choice: stages.StageChoice
    result: StageResult
    output: BaseModel | None
    evidence_uri: str | None = None

    def provenance(self, ctx: Ctx) -> dict[str, Any]:
        return {
            "task_id": self.task.task_id,
            "harness": self.result.harness,
            "harness_version": self.result.harness_version,
            "model": self.result.model,
            "skills": self.task.skills,
            "skills_version": ctx.skills_version,
            "image": ctx.image,
            "experiment": self.choice.experiment,
            "status": self.result.status.value,
        }


def _gateway_env(ctx: Ctx, task: StageTask, key: str) -> dict[str, str]:
    if not key:
        return {}
    env = {
        "PRSEC_GATEWAY_URL": settings().gateway_url,
        "PRSEC_GATEWAY_KEY": key,
        "PRSEC_GATEWAY_MODEL": task.model_alias,
    }
    if ctx.per_task_keys:
        env["PRSEC_GATEWAY_KEY_SCOPE"] = "task"
    return env


def _upload_evidence(ctx: Ctx, task: StageTask, out_dir: Path) -> str | None:
    """Copy the stage transcript and output to the artifact store (the work dir is deleted after the
    scan). Returns the transcript's URI, or None if it could not be stored."""
    from prsec.adapters.sinks.sarif_store import evidence_key

    uri = None
    for name, ctype in (("transcript.jsonl", "application/x-ndjson"), ("output.json", "application/json")):
        f = out_dir / name
        if f.is_symlink() or not f.is_file():  # out_dir is container-writable: never follow a link out of it
            continue
        try:
            u = _put_evidence(evidence_key(ctx.repo, ctx.pr.number, ctx.pr.head_sha, task.task_id, name), f.read_bytes(), ctype)
        except Exception:
            log.warning("scan %s: could not store %s of %s", ctx.scan_id, name, task.task_id, exc_info=True)
            continue
        if name == "transcript.jsonl":
            uri = u
    return uri


def _book_gateway_cost(result: StageResult, task_key: str) -> StageResult:
    """The per-task key's gateway spend is the cost of record; harness-reported cost is best effort
    (several harnesses report $0 behind the gateway). Never lower than what the harness reported,
    since the gateway books spend asynchronously."""
    booked = gateway.key_spend(task_key)
    if booked is None or booked <= result.usage.usd:
        return result
    return result.model_copy(update={"usage": result.usage.model_copy(update={"usd": booked})})


def _agent_message(ev: dict[str, Any]) -> tuple[str, dict[str, Any], str]:
    """(message, data, level) of one live transcript event; agent-written text is truncated."""
    kind = str(ev.get("kind") or "event")[:40]
    tool = ev.get("tool") if isinstance(ev.get("tool"), str) else None
    text = ev.get("text") if isinstance(ev.get("text"), str) else ""
    if not text and ev.get("data"):
        text = json.dumps(ev["data"], default=str)
    text = text[:AGENT_TEXT_MAX]
    head = f"{kind} {tool[:80]}" if tool else kind
    data = {"event_kind": kind, "tool": tool, "text": text, "ts": ev.get("ts")}
    return f"{head}: {text}" if text else head, data, "warning" if kind == "error" else "info"


class _AgentStream:
    """Relays <out_dir>/events.jsonl as `agent` events while a stage runs (batched every flush_s)."""

    def __init__(self, scan_id: int, out_dir: Path, flush_s: float = AGENT_FLUSH_S):
        self.scan_id = scan_id
        self.tail = EventTail(out_dir)
        self.flush_s = flush_s
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.thread: threading.Thread | None = None

    def __enter__(self) -> "_AgentStream":
        ctx = contextvars.copy_context()  # the relay's log lines carry the stage's bound fields
        self.thread = threading.Thread(target=ctx.run, args=(self._loop,), name=f"agent-stream-{self.scan_id}",
                                       daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.stop.set()
        if self.thread is not None:
            self.thread.join(timeout=10)
        self.flush()  # whatever arrived after the last tick

    def _loop(self) -> None:
        while not self.stop.wait(self.flush_s):
            self.flush()

    def flush(self) -> None:
        with self.lock:
            try:
                batch = self.tail.read()
            except Exception:
                log.debug("agent stream: could not read events", exc_info=True)
                return
            for ev in batch[:AGENT_BATCH_MAX]:
                message, data, level = _agent_message(ev)
                timeline.emit(self.scan_id, "agent", message, level=level, data=data)
            if len(batch) > AGENT_BATCH_MAX:
                timeline.emit(self.scan_id, "agent", f"{len(batch) - AGENT_BATCH_MAX} more agent events in this "
                              f"{self.flush_s:.0f}s burst not shown (see the transcript)")


def _stage_started(ctx: Ctx, task: StageTask, choice: stages.StageChoice, env_name: str | None) -> None:
    where = f", in env {env_name}" if env_name else ""
    ctx.emit("stage_started", f"{task.stage.value} started: harness {task.harness}, model {task.model_alias}{where}",
             data={"harness": task.harness, "model": task.model_alias, "env": env_name,
                   "usd_budget": task.limits.usd_budget, "wall_clock_s": task.limits.wall_clock_s,
                   "experiment": choice.experiment})


def _stage_finished(ctx: Ctx, result: StageResult, evidence: str | None, invalid: str | None) -> None:
    ok = result.status == StageStatus.ok and invalid is None
    msg = (f"{result.stage.value} {result.status.value} in {result.duration_s or 0:.1f}s, ${result.usage.usd:.4f}"
           f" ({result.harness} {result.harness_version or '?'}, {result.model}, {result.attempts} attempt(s))")
    why = invalid or (result.errors[0] if result.errors else "")
    if why:
        msg += f": {why[:300]}"
    ctx.emit("stage_finished", msg, level="info" if ok else "warning", data={
        "status": result.status.value, "harness": result.harness, "harness_version": result.harness_version,
        "model": result.model, "usd": result.usage.usd, "tokens_in": result.usage.tokens_in,
        "tokens_out": result.usage.tokens_out, "duration_s": result.duration_s, "attempts": result.attempts,
        "errors": [e[:500] for e in result.errors[:3]], "output_invalid": invalid, "transcript_uri": evidence,
    })


def _run(
    ctx: Ctx, stage: Stage, files: dict[str, str], *, prompt_ctx: dict[str, Any], hyp_id: str | None = None,
    env_name: str | None = None, app_dir: Path | None = None,
) -> Ran:
    """One agent stage. With `env_name` it runs inside that dynamic environment (its network and
    DNS, `app_dir` writable at /work/app) instead of on the static scan network."""
    names = list(files)
    task, choice = stages.build_task(
        ctx.policy, stage, ctx.scan_id, ctx.repo, context_files=names, prompt_ctx=prompt_ctx, hyp_id=hyp_id
    )
    with bind(task_id=task.task_id, stage=stage.value, hypothesis_id=hyp_id, env=env_name):
        return _run_task(ctx, task, choice, files, env_name, app_dir)


def _run_task(
    ctx: Ctx, task: StageTask, choice: stages.StageChoice, files: dict[str, str], env_name: str | None,
    app_dir: Path | None,
) -> Ran:
    stage = task.stage
    in_dir = ctx.root / "in" / task.task_id
    out_dir = ctx.root / "out" / task.task_id
    for d in (in_dir, out_dir):
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True)
    for name, content in files.items():
        (in_dir / name).write_text(content)
    (in_dir / stages.SCHEMA_FILE).write_text(json.dumps(task.output_schema, indent=2))
    (in_dir / "task.json").write_text(task.model_dump_json(indent=2))

    _stage_started(ctx, task, choice, env_name)
    task_key = ""
    try:
        if ctx.per_task_keys:
            task_key = gateway.mint_key(ctx.scan_id, task.limits.usd_budget, task.limits.wall_clock_s + KEY_GRACE_S,
                                        [task.model_alias], task_id=task.task_id)
        spec = WorkbenchSpec(
            scan_id=ctx.scan_id,
            task=task,
            image=ctx.image,
            harness_volume=str(settings().harness_root / task.harness / "current"),
            src_dir=ctx.src,
            in_dir=in_dir,
            out_dir=out_dir,
            skills_dir=settings().skills_dir,
            env={**child_log_env(), **_gateway_env(ctx, task, task_key or ctx.gw_key)},
            network=None if env_name else ctx.network,
            env_name=env_name,
            app_dir=app_dir,
        )
        with _AgentStream(ctx.scan_id, out_dir):
            result = ctx.runner.run_workbench(spec)
    except Exception as e:  # runner / key failure is a stage failure, not a scan failure
        log.exception("stage %s failed in runner", task.task_id)
        result = StageResult(
            task_id=task.task_id, stage=stage, status=StageStatus.harness_error,
            errors=[f"runner: {type(e).__name__}: {e}"], harness=task.harness, model=task.model_alias,
        )
    if task_key:
        try:
            result = _book_gateway_cost(result, task_key)
        finally:
            gateway.revoke_key(task_key)
    evidence = _upload_evidence(ctx, task, out_dir)
    queue.record_stage_run(ctx.scan_id, result, evidence, lease_token=ctx.lease_token)
    if result.usage.usd:
        queue.add_cost(ctx.scan_id, result.usage.usd)

    output: BaseModel | None = None
    invalid = None
    if result.status == StageStatus.ok and result.output is not None:
        try:
            output = model_for(stage).model_validate(result.output)
        except ValidationError as e:
            log.warning("stage %s output failed validation: %s", task.task_id, e)
            invalid = f"output failed validation ({e.error_count()} error(s))"
    _stage_finished(ctx, result, evidence, invalid)
    return Ran(task, choice, result, output, evidence)


# ---------------------------------------------------------------- helpers


def _hyp_citations(h: Hypothesis) -> list[Citation]:
    return [h.sink, *([h.source] if h.source else []), *h.path]


def _static_citations(s: StaticVerifyOutput) -> list[Citation]:
    return [*s.citations, *(g.citation for g in s.guards if g.citation)]


def _bug_class_aliases() -> dict[str, str]:
    """alias -> canonical bug_class from the mounted skills' bug-classes.yaml ({} if absent)."""
    from prsec.skills_lint import bug_class_aliases

    try:
        return bug_class_aliases(Path(settings().skills_dir))
    except Exception:
        log.warning("could not load bug-classes.yaml from %s", settings().skills_dir, exc_info=True)
        return {}


def _canonical_bug_classes(hyps: list[Hypothesis], aliases: dict[str, str]) -> list[Hypothesis]:
    out = []
    for h in hyps:
        key = re.sub(r"[\s_]+", "-", h.bug_class.strip().lower())
        canon = aliases.get(key, key)
        out.append(h if canon == h.bug_class else h.model_copy(update={"bug_class": canon}))
    return out


def _relative(c: Citation, src: Path) -> Citation:
    f = repo_relative(c.file, src)
    return c if f == c.file else c.model_copy(update={"file": f})


def _relativise(hyps: list[Hypothesis], src: Path) -> list[Hypothesis]:
    """Agents may cite absolute container paths (/work/src/...); findings use repo-relative ones."""
    return [
        h.model_copy(update={
            "sink": _relative(h.sink, src),
            "source": _relative(h.source, src) if h.source else None,
            "path": [_relative(c, src) for c in h.path],
        })
        for h in hyps
    ]


def _normalise_ids(hyps: list[Hypothesis]) -> list[Hypothesis]:
    seen: set[str] = set()
    out = []
    for i, h in enumerate(hyps, 1):
        hid = re.sub(r"[^A-Za-z0-9_.]", "", h.id)[:32] or f"H{i}"
        while hid in seen:
            hid = f"{hid}_{i}"
        seen.add(hid)
        out.append(h if hid == h.id else h.model_copy(update={"id": hid}))
    return out


def _safe_snippet(ctx: Ctx, file: str, line: int, end_line: int | None) -> str | None:
    try:
        return _snippet(ctx.src, file, line, end_line) or None
    except Exception:
        return None


def _loc(ctx: Ctx, c: Citation) -> CodeLoc:
    return CodeLoc(file=c.file, line=c.line, end_line=c.end_line, snippet=_safe_snippet(ctx, c.file, c.line, c.end_line))


def _strip_quotes(obj: Any) -> Any:
    """Replace agent-written quotes with a pointer to the trusted excerpts."""
    if isinstance(obj, dict):
        if {"file", "line", "quote"} <= obj.keys():
            end = obj.get("end_line") or obj["line"]
            return {"file": obj["file"], "line": obj["line"], "end_line": end, "excerpt": f"code_slices.md#{obj['file']}:{obj['line']}-{end}"}
        return {k: _strip_quotes(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_strip_quotes(v) for v in obj]
    return obj


def _code_slices(ctx: Ctx, cits: list[Citation]) -> str:
    parts = ["# Code excerpts (repository at PR head)", ""]
    seen: set[tuple[str, int, int]] = set()
    for c in cits:
        end = c.end_line or c.line
        if (c.file, c.line, end) in seen:
            continue
        seen.add((c.file, c.line, end))
        lo, hi = max(1, c.line - 3), end + 3
        text = _safe_snippet(ctx, c.file, lo, hi) or _safe_snippet(ctx, c.file, c.line, end) or "(unavailable)"
        parts += [f"## {c.file}:{c.line}-{end}", f"(lines {lo}-{hi} shown)", "```", text.rstrip("\n"), "```", ""]
    return "\n".join(parts)


def _finding(
    ctx: Ctx, h: Hypothesis, hyp_run: Ran, sv: Ran | None, sk: Ran | None, label: Label, reason: str,
    dyn: DynamicEvidence | None = None,
) -> Finding:
    static = sv.output if sv else None
    assert static is None or isinstance(static, StaticVerifyOutput)
    description = h.description + f"\n\nImpact: {h.impact}"
    if static:
        description += f"\n\nStatic verification ({static.verdict}, reachable={static.reachable}): {static.reasoning}"
    provenance = {"hypothesise": hyp_run.provenance(ctx)}
    if sv:
        provenance["static_verify"] = sv.provenance(ctx)
    if sk:
        provenance["skeptic"] = sk.provenance(ctx)
    if dyn and dyn.provenance:
        provenance["dynamic"] = dyn.provenance
    provenance["introduced_by_diff_claim"] = h.introduced_by_diff
    return Finding(
        fingerprint=fingerprint(h.bug_class, h.sink.file, enclosing_symbol(ctx.src, h.sink.file, h.sink.line), h.entry_point),
        scan_id=ctx.scan_id,
        repo=ctx.repo,
        pr=ctx.pr.number,
        head_sha=ctx.pr.head_sha,
        hypothesis_id=h.id,
        vuln_class=h.vuln_class,
        bug_class=h.bug_class,
        title=h.title,
        description=description,
        label=label,
        label_reason=reason,
        severity=static.severity if static else h.severity_guess,
        introduced=verdict.introduced(dyn),
        entry_point=h.entry_point,
        source=_loc(ctx, h.source) if h.source else None,
        sink=_loc(ctx, h.sink),
        path=[_loc(ctx, c) for c in h.path],
        guards=[f"{'effective' if g.effective else 'ineffective'}: {g.description}" for g in static.guards] if static else list(h.assumed_guards),
        remediation=static.remediation if static else None,
        evidence_uri=(sv.evidence_uri if sv else None) or hyp_run.evidence_uri,
        provenance=provenance,
        dynamic=dyn.model_dump(mode="json", by_alias=True) if dyn else None,
    )


def _dedupe(findings: list[Finding]) -> list[Finding]:
    best: dict[str, Finding] = {}
    for f in findings:
        cur = best.get(f.fingerprint)
        if cur is None or (_LABEL_RANK[f.label], _SEV_RANK[f.severity]) > (_LABEL_RANK[cur.label], _SEV_RANK[cur.severity]):
            best[f.fingerprint] = f
    return list(best.values())


def _changed_files(pr: PRInfo, diff: str) -> list[str]:
    return sorted(set(pr.changed_files) | set(triage_rules.parse_diff(diff)))


def _prior_findings_json(ctx: Ctx) -> str | None:
    """Open findings of this PR from earlier commits, for hypothesise to re-confirm or retire.
    Only our own records and trusted snapshot excerpts, never agent-written quotes."""
    try:
        rows = _open_findings(ctx.repo, ctx.pr.number)
    except Exception:
        log.warning("scan %s: could not load prior findings", ctx.scan_id, exc_info=True)
        return None
    if not rows:
        return None
    items = []
    for r in rows:
        data = r.get("data") or {}
        sink = data.get("sink") or {}
        items.append({
            "fingerprint": r["fingerprint"],
            "bug_class": r["bug_class"],
            "vuln_class": r["vuln_class"],
            "title": r["title"],
            "severity": r["severity"],
            "label": r["label"],
            "entry_point": data.get("entry_point"),
            "sink": {"file": r["sink_file"], "line": r["sink_line"], "snippet_at_previous_head": sink.get("snippet")},
            "reported_at_head": data.get("head_sha"),
        })
    return json.dumps({"prior_findings": items}, indent=2)


def _work_dir(scan_id: int, lease_token: str | None) -> Path:
    """Per-lease work dir, so a stale run and its successor never share (or delete) each other's files."""
    return settings().work_root / (f"{scan_id}-{lease_token[:12]}" if lease_token else str(scan_id))


def _enqueue_current_head(scan_row: dict, pr: PRInfo) -> None:
    s = settings()
    req = ScanRequest(scm=pr.scm, repo=pr.repo, pr=pr.number, head_sha=pr.head_sha, base_sha=pr.base_sha,
                      installation_id=scan_row.get("installation_id"), reason="synchronize")
    try:
        queue.enqueue(req, scan_row.get("skills_version") or current_skills_version(), s.debounce_s, s.max_supersedes)
    except Exception:  # the reconciler catches the new head later
        log.exception("scan %s: could not enqueue current head %s", scan_row["id"], pr.head_sha)


def _pr_json(pr: PRInfo) -> str:
    keep = {"repo", "number", "title", "body", "author", "base_ref", "head_ref", "base_sha", "head_sha", "draft", "commits", "url"}
    return json.dumps(pr.model_dump(include=keep, mode="json"), indent=2)


# -------------------------------------------------------------------- stages


def _triage(ctx: Ctx, rules: dict[str, Any], audited: bool) -> tuple[dict[str, Any], str]:
    """Returns (triage record, effective decision skip|light|full)."""
    ran = _run(ctx, Stage.triage, dict(ctx.shared), prompt_ctx={"pr_number": ctx.pr.number})
    record: dict[str, Any] = {"rules": rules, "llm_task_id": ran.task.task_id, "audit_sample": audited}
    out = ran.output
    if isinstance(out, TriageOutput):
        record.update(out.model_dump())
        decision = out.decision
        record["source"] = "llm"
    else:
        record.update(decision="full", rationale=f"triage stage {ran.result.status.value}; failing open", source="fallback")
        decision = "full"
    if rules["decision"] == "skip":  # only reached for audit samples
        record["source"] = "rules"
        record["would_skip"] = True
    elif decision == "skip" and audited:
        record["would_skip"] = True
    if decision == "skip" and audited:
        decision = "light"
    note = " (audit sample: would have skipped)" if record.get("would_skip") else ""
    ctx.emit("triage", f"triage: {decision} ({record['source']}){note}: {str(record.get('rationale') or '')[:300]}",
             data={"decision": decision, "source": record["source"], "rationale": record.get("rationale"),
                   "risk_tags": record.get("risk_tags"), "focus_files": record.get("focus_files"),
                   "audit_sample": audited})
    return record, decision


def _verify_one(ctx: Ctx, h: Hypothesis, hyp_files: dict[str, str]) -> tuple[Ran, list[str]]:
    files = {**hyp_files, "hypothesis.json": h.model_dump_json(indent=2)}
    ran = _run(ctx, Stage.static_verify, files, prompt_ctx={"pr_number": ctx.pr.number, "bug_class": h.bug_class}, hyp_id=h.id)
    errs = _verify_all(_static_citations(ran.output), ctx.src) if isinstance(ran.output, StaticVerifyOutput) else []
    return ran, errs


def _skeptic_one(ctx: Ctx, h: Hypothesis, sv: StaticVerifyOutput) -> Ran:
    files = {
        "hypothesis.json": json.dumps(_strip_quotes(h.model_dump(mode="json")), indent=2),
        "static_verify.json": json.dumps(_strip_quotes(sv.model_dump(mode="json")), indent=2),
        "code_slices.md": _code_slices(ctx, _hyp_citations(h) + _static_citations(sv)),
    }
    return _run(ctx, Stage.skeptic, files, prompt_ctx={"pr_number": ctx.pr.number}, hyp_id=h.id)


def _drop(ctx: Ctx, meta: dict[str, Any], hid: str, reason: str, errors: list[str] | None = None) -> None:
    """Record a dropped hypothesis in the scan meta and on the timeline."""
    entry: dict[str, Any] = {"id": hid, "reason": reason}
    if errors is not None:
        entry["errors"] = errors[:5]
    meta["dropped"].append(entry)
    why = _DROP_REASONS.get(reason, reason)
    detail = f" ({errors[0][:200]})" if errors else ""
    ctx.emit("hypothesis_dropped", f"{hid} dropped: {why}{detail}", hypothesis_id=hid, data=entry)


def _select_hypotheses(ctx: Ctx, raw: list[Hypothesis], limit: int, meta: dict[str, Any]) -> list[Hypothesis]:
    """Hypotheses with verified citations, capped at `limit`, at or above the static-verify severity floor."""
    kept: list[Hypothesis] = []
    hyps = _relativise(_normalise_ids(raw), ctx.src)
    for h in _canonical_bug_classes(hyps, _bug_class_aliases()):
        errs = _verify_all(_hyp_citations(h), ctx.src)
        if errs:
            _drop(ctx, meta, h.id, "hypothesis_citations_unverified", errs)
        else:
            kept.append(h)
    for h in kept[limit:]:
        _drop(ctx, meta, h.id, "over_cap")
    kept = kept[:limit]

    min_rank = _SEV_RANK[Severity(ctx.policy.static_verify_min_severity)]
    to_verify = [h for h in kept if _SEV_RANK[h.severity_guess] >= min_rank]
    for h in kept:
        if h not in to_verify:
            _drop(ctx, meta, h.id, "below_static_verify_min_severity")
    return to_verify


def _static_survivors(
    ctx: Ctx, to_verify: list[Hypothesis], hyp_files: dict[str, str], meta: dict[str, Any]
) -> list[tuple[Hypothesis, Ran, list[str]]]:
    """Run static_verify on every hypothesis; keep those `verdict.drop_reason` does not drop."""
    with ThreadPoolExecutor(max_workers=min(VERIFY_CONCURRENCY, len(to_verify))) as pool:
        futures = [submit_with_context(pool, _verify_one, ctx, h, hyp_files) for h in to_verify]
        verified = [(h, *f.result()) for h, f in zip(to_verify, futures)]

    survivors: list[tuple[Hypothesis, Ran, list[str]]] = []
    for h, sv, errs in verified:
        static = sv.output if isinstance(sv.output, StaticVerifyOutput) else None
        _static_verdict(ctx, h, sv, static, errs)
        reason = verdict.drop_reason(static, errs)
        if reason:
            _drop(ctx, meta, h.id, reason, errs)
        else:
            survivors.append((h, sv, errs))
    return survivors


def _static_verdict(ctx: Ctx, h: Hypothesis, sv: Ran, static: StaticVerifyOutput | None, errs: list[str]) -> None:
    if static is None:
        ctx.emit("static_verdict", f"{h.id}: no usable static verdict (stage {sv.result.status.value})",
                 level="warning", hypothesis_id=h.id, data={"status": sv.result.status.value})
        return
    cites = f"; {len(errs)} citation(s) unverified" if errs else ""
    ctx.emit("static_verdict", f"{h.id}: {static.verdict}, severity {static.severity.value}, "
             f"reachable={static.reachable}{cites}: {static.reasoning[:300]}", hypothesis_id=h.id,
             data={"verdict": static.verdict, "severity": static.severity.value, "reachable": static.reachable,
                   "citation_errors": errs[:5]})


def _skeptics(ctx: Ctx, survivors: list[tuple[Hypothesis, Ran, list[str]]]) -> dict[str, Ran]:
    """Skeptic runs, by hypothesis id, for the survivors `verdict.needs_skeptic` selects."""
    need = [(h, sv) for h, sv, errs in survivors if verdict.needs_skeptic(sv.output, errs, h)]  # type: ignore[arg-type]
    skeptics: dict[str, Ran] = {}
    if need:
        with ThreadPoolExecutor(max_workers=min(VERIFY_CONCURRENCY, len(need))) as pool:
            futures = [submit_with_context(pool, _skeptic_one, ctx, h, sv.output) for h, sv in need]
            for (h, _), f in zip(need, futures):
                skeptics[h.id] = f.result()
                _skeptic_event(ctx, h, skeptics[h.id])
    return skeptics


def _skeptic_event(ctx: Ctx, h: Hypothesis, ran: Ran) -> None:
    out = ran.output
    if not isinstance(out, SkepticOutput):
        ctx.emit("skeptic", f"{h.id}: no usable skeptic verdict (stage {ran.result.status.value})", level="warning",
                 hypothesis_id=h.id, data={"status": ran.result.status.value})
        return
    ctx.emit("skeptic", f"{h.id}: skeptic {'refuted' if out.refuted else 'upheld'} it ({out.confidence}): "
             f"{out.reasoning[:300]}", hypothesis_id=h.id,
             data={"refuted": out.refuted, "confidence": out.confidence})


def _analyse(ctx: Ctx, triage: dict[str, Any], decision: str, meta: dict[str, Any]) -> list[Finding]:
    policy = ctx.policy
    limit = policy.max_hypotheses if decision == "full" else max(1, (policy.max_hypotheses + 1) // 2)
    hyp_files = {**ctx.shared, "triage.json": json.dumps(triage, indent=2)}
    prior = _prior_findings_json(ctx)
    hyp_only = {"prior_findings.json": prior} if prior else {}

    ctx.check()
    hyp_run = _run(
        ctx, Stage.hypothesise, {**hyp_files, **hyp_only},
        prompt_ctx={"pr_number": ctx.pr.number, "max_hypotheses": limit, "triage_decision": decision,
                    "focus_files": triage.get("focus_files") or []},
    )
    if not isinstance(hyp_run.output, HypothesesOutput):
        status = hyp_run.result.status.value
        meta["hypothesise_status"] = status
        meta["complete"] = False
        meta["errors"].append(f"hypothesise stage {status}: " + "; ".join(hyp_run.result.errors[:3])[:1000])
        ctx.emit("error", f"hypothesise {status}: the scan is incomplete and will be retried", level="error",
                 data={"errors": [e[:500] for e in hyp_run.result.errors[:3]]})
        return []
    meta["summary"] = hyp_run.output.summary

    to_verify = _select_hypotheses(ctx, hyp_run.output.hypotheses, limit, meta)
    _hypotheses_event(ctx, hyp_run.output, to_verify)
    if not to_verify:
        return []

    ctx.check()
    survivors = _static_survivors(ctx, to_verify, hyp_files, meta)

    ctx.check()
    skeptics = _skeptics(ctx, survivors)

    ctx.check()
    evidence = dynamic.run_dynamic(ctx, survivors, meta)

    findings = []
    for h, sv, errs in survivors:
        static = sv.output if isinstance(sv.output, StaticVerifyOutput) else None
        sk = skeptics.get(h.id)
        skeptic = sk.output if sk and isinstance(sk.output, SkepticOutput) else None
        dyn = evidence.get(h.id)
        label, reason = verdict.decide(h, static, skeptic, errs, dyn)
        ctx.emit("label", f"{h.id} labelled {label.value}: {reason}", hypothesis_id=h.id,
                 data={"label": label.value, "reason": reason, "title": h.title, "bug_class": h.bug_class,
                       "dynamic": dyn.outcome if dyn else None})
        findings.append(_finding(ctx, h, hyp_run, sv, sk, label, reason, dyn))
    return _dedupe(findings)


def _hypotheses_event(ctx: Ctx, out: HypothesesOutput, to_verify: list[Hypothesis]) -> None:
    listing = ", ".join(f"{h.id} {h.bug_class} ({h.severity_guess.value})" for h in out.hypotheses[:20])
    ctx.emit("hypotheses", f"hypothesise produced {len(out.hypotheses)} hypothesis(es), {len(to_verify)} go to "
             f"static verification" + (f": {listing}" if listing else ""),
             data={"summary": out.summary[:1000], "to_verify": [h.id for h in to_verify],
                   "hypotheses": [{"id": h.id, "bug_class": h.bug_class, "title": h.title,
                                   "severity_guess": h.severity_guess.value} for h in out.hypotheses[:50]]})


# ------------------------------------------------------------------- entry


@dataclass
class _ScanResources:
    """What a scan has allocated so far; released by `run_scan` however the scan ends."""

    gw_key: str = ""
    runner: Runner | None = None
    root: Path | None = None
    findings: int | None = None  # how many findings were written (for the scan_finished event)


def _current_pr(scm: Any, scan_row: dict, repo: str, number: int, inst: Any) -> PRInfo:
    pr = scm.get_pr(repo, number, inst)
    if pr.head_sha != scan_row["head_sha"]:
        # The diff, commits and file list from the SCM describe the current head, not the queued
        # one: scanning would mix two commits. The current head gets (or already has) its own scan.
        log.info("scan %s: PR head moved %s -> %s; superseding", scan_row["id"], scan_row["head_sha"], pr.head_sha)
        _enqueue_current_head(scan_row, pr)
        raise Superseded(f"PR head moved to {pr.head_sha[:12]}")
    return pr.model_copy(update={"base_sha": scan_row.get("base_sha") or pr.base_sha})


def _fresh_src(root: Path) -> Path:
    src = root / "src"
    if src.exists():
        shutil.rmtree(src)
    src.mkdir(parents=True)
    return src


def _workbench_image(policy: Policy, repo: str) -> str:
    override = next((ov.workbench_image for p, ov in policy.repos.items()
                     if ov.workbench_image and fnmatch.fnmatch(repo, p)), None)
    return override or policy.workbench_image


def _shared_files(repo: str, pr: PRInfo, diff: str, changed: list[str]) -> dict[str, str]:
    shared = {"pr.json": _pr_json(pr), "diff.patch": diff, "changed_files.txt": "\n".join(changed) + "\n"}
    profile = settings().work_root / "profiles" / f"{repo.replace('/', '__')}.json"
    if profile.is_file():
        shared["repo_profile.json"] = profile.read_text()
    return shared


def _write_results(
    ctx: Ctx, triage: dict[str, Any], changed: list[str], meta: dict[str, Any], findings: list[Finding]
) -> dict[str, Any]:
    """Write the scan's findings to the sink; returns the queue outcome."""
    run_meta = {
        **meta,
        "triage": triage,
        "skills_version": ctx.skills_version,
        "image": ctx.image,
        "scanned_files": changed,
        "changed_files": changed,
        "base_sha": ctx.pr.base_sha,
    }
    mounted = current_skills_version()
    if mounted != ctx.skills_version:
        run_meta["skills_version_mounted"] = mounted
    uri = sinks_pkg.get_sink().write_scan(ctx.scan_id, ctx.pr, findings, run_meta)
    if meta["complete"]:
        return {"status": ScanStatus.done, "triage": triage, "sarif_uri": uri}
    return {"status": ScanStatus.failed, "triage": triage, "sarif_uri": uri,
            "error": ("incomplete: " + "; ".join(meta["errors"]))[:4000]}


def _scan(scan_row: dict, scan_id: int, token: str | None, res: _ScanResources) -> dict[str, Any]:
    """The scan itself; returns the queue outcome. Records what it allocates in `res`."""
    repo = scan_row["repo"]
    number = int(scan_row["pr"])
    inst = scan_row.get("installation_id")
    policy = load_policy()
    if not policy.repo_enabled(repo):
        timeline.emit(scan_id, "rules", "repository disabled by policy: skipping")
        return {"status": ScanStatus.skipped, "triage": {"decision": "skip", "source": "policy", "reason": "repo_disabled"}}

    scm = scm_pkg.get_scm(scan_row.get("scm") or "github")
    pr = _current_pr(scm, scan_row, repo, number, inst)
    diff = scm.get_diff(repo, number, inst)
    changed = _changed_files(pr, diff)

    rule, rule_reason = triage_rules.classify(changed, diff)
    rules = {"decision": rule, "reason": rule_reason}
    audited = stages.bucket(scan_id, "skip_audit") < policy.skip_audit_sample
    _rules_event(scan_id, rule, rule_reason, audited, changed)
    if rule == "skip" and not audited:
        return {"status": ScanStatus.skipped, "triage": {"decision": "skip", "source": "rules", "reason": rule_reason, "rules": rules}}
    if queue.is_superseded(scan_id):
        raise Superseded()

    res.root = root = _work_dir(scan_id, token)
    src = _fresh_src(root)
    scm.fetch_source(repo, pr.head_sha, src, inst)

    per_task = gateway.per_task_keys()
    usd, wall, models = stages.scan_budget(policy, repo, policy.max_hypotheses)
    if not per_task:  # dev: one shared (passthrough) key; with a master key every task gets its own
        res.gw_key = gateway.mint_key(scan_id, usd, wall + KEY_GRACE_S, models)
    res.runner = runner = runner_pkg.get_runner(settings().runner)
    network = runner.create_scan_network(scan_id)

    skills_version = scan_row.get("skills_version") or settings().skills_version
    ctx = Ctx(
        scan_id=scan_id, repo=repo, pr=pr, policy=policy, root=root, src=src, runner=runner, network=network,
        gw_key=res.gw_key, image=_workbench_image(policy, repo), skills_version=skills_version,
        lease_token=token, per_task_keys=per_task, scm=scm, installation_id=inst,
        keep=_debug_opts(scan_row).keep_minutes > 0,
    )
    ctx.shared = _shared_files(repo, pr, diff, changed)

    ctx.check()
    triage, decision = _triage(ctx, rules, audited)
    if decision == "skip":
        return {"status": ScanStatus.skipped, "triage": triage}

    meta: dict[str, Any] = {"dropped": [], "complete": True, "errors": []}
    findings = _analyse(ctx, triage, decision, meta)
    ctx.check()
    res.findings = len(findings)
    return _write_results(ctx, triage, changed, meta, findings)


def _rules_event(scan_id: int, rule: str, reason: str | None, audited: bool, changed: list[str]) -> None:
    if rule == "skip":
        msg = f"rules: skip ({reason})" + ("; audit sample, scanning anyway" if audited else "")
    else:
        msg = f"rules: no skip rule matched; the LLM triage decides ({len(changed)} changed file(s))"
    timeline.emit(scan_id, "rules", msg, data={"decision": rule, "reason": reason, "audit_sample": audited,
                                               "changed_files": changed[:100]})


def _keep(scan_id: int, res: _ScanResources, minutes: int, token: str | None) -> bool:
    """Leave the scan's environments and work dir for debugging; True when the keep was recorded."""
    if res.runner is None and res.root is None:
        return False
    try:
        if not queue.keep(scan_id, minutes, str(res.root) if res.root else None, lease_token=token):
            return False
    except Exception:
        log.exception("scan %s: could not record keep-for-debugging; cleaning up now", scan_id)
        return False
    timeline.emit(scan_id, "kept", f"kept for {minutes} min for debugging: work dir {res.root}, scan network and "
                  "environments stay up until the worker reaps them",
                  data={"keep_minutes": minutes, "work_dir": str(res.root) if res.root else None,
                        "runner": getattr(res.runner, "name", None)})
    return True


def _release(scan_id: int, res: _ScanResources, lease_lost: bool, keep_minutes: int = 0,
             token: str | None = None) -> None:
    # Runs BEFORE the lease is released: once finish() clears it, the same scan id may be
    # revived and leased again, and must not lose its containers/network to our cleanup.
    kept = not lease_lost and keep_minutes > 0 and _keep(scan_id, res, keep_minutes, token)
    if res.runner is not None and not lease_lost and not kept:
        try:
            res.runner.destroy_scan(scan_id)
            timeline.emit(scan_id, "env_destroyed", "scan network and containers destroyed")
        except Exception:
            log.exception("scan %s: destroy_scan failed", scan_id)
            timeline.emit(scan_id, "error", "destroy_scan failed (see the worker log)", level="error")
    try:
        gateway.revoke_key(res.gw_key)
    except Exception:
        log.exception("scan %s: revoke_key failed", scan_id)
    if res.root is not None and not kept:
        shutil.rmtree(res.root, ignore_errors=True)


def _debug_opts(scan_row: dict) -> ScanDebug:
    """The scan's debug options (scans.debug); none requested -> info level, nothing kept."""
    raw = scan_row.get("debug")
    if not raw:
        return ScanDebug(log_level="info", keep_minutes=0)
    try:
        return ScanDebug.model_validate(json.loads(raw) if isinstance(raw, str) else raw)
    except (ValueError, ValidationError):
        log.warning("scan %s: ignoring invalid debug options %r", scan_row.get("id"), raw)
        return ScanDebug(log_level="info", keep_minutes=0)


def _scan_started(scan_row: dict, scan_id: int, dbg: ScanDebug) -> None:
    sha = str(scan_row.get("head_sha") or "")
    extra = f"; debug: log level {dbg.log_level}, keep {dbg.keep_minutes} min" if scan_row.get("debug") else ""
    timeline.emit(scan_id, "scan_started",
                  f"scan of {scan_row.get('repo')}#{scan_row.get('pr')} at {sha[:12]} ({scan_row.get('reason') or 'opened'},"
                  f" attempt {scan_row.get('attempts') or 1}){extra}",
                  data={"repo": scan_row.get("repo"), "pr": scan_row.get("pr"), "head_sha": sha,
                        "base_sha": scan_row.get("base_sha"), "reason": scan_row.get("reason"),
                        "attempt": scan_row.get("attempts"), "skills_version": scan_row.get("skills_version"),
                        "debug": dbg.model_dump() if scan_row.get("debug") else None})


def _scan_finished(scan_id: int, outcome: dict[str, Any], res: _ScanResources, started: float, lease_lost: bool) -> None:
    took = time.monotonic() - started
    if lease_lost:
        timeline.emit(scan_id, "scan_finished", f"abandoned after {took:.0f}s: the lease was lost to another worker",
                      level="warning", data={"status": None, "duration_s": round(took, 1)})
        return
    status = ScanStatus(outcome["status"]).value
    msg = f"scan {status} in {took:.0f}s"
    if res.findings is not None:
        msg += f", {res.findings} finding(s)"
    why = outcome.get("error") or outcome.get("reason") or (outcome.get("triage") or {}).get("reason")
    if why:
        msg += f": {str(why)[:500]}"
    level = "error" if status == ScanStatus.failed else "info"
    timeline.emit(scan_id, "scan_finished", msg, level=level, data={
        "status": status, "duration_s": round(took, 1), "findings": res.findings,
        "sarif_uri": outcome.get("sarif_uri"), "error": outcome.get("error")})


def run_scan(scan_row: dict) -> None:
    scan_id = int(scan_row["id"])
    dbg = _debug_opts(scan_row)
    with bind(scan_id=scan_id, debug=True if dbg.log_level == "debug" else None):
        _run_scan(scan_row, scan_id, dbg)


def _run_scan(scan_row: dict, scan_id: int, dbg: ScanDebug) -> None:
    token = scan_row.get("lease_token")
    res = _ScanResources()
    outcome: dict[str, Any] = {"status": ScanStatus.failed}
    lease_lost = False
    started = time.monotonic()
    _scan_started(scan_row, scan_id, dbg)
    _drop_previous_keep(scan_row, scan_id, token)
    try:
        outcome = _scan(scan_row, scan_id, token, res)
    except Superseded as e:
        log.info("scan %s superseded; aborting", scan_id)
        outcome = {"status": ScanStatus.superseded, "reason": str(e) or "superseded"}
    except LeaseLost:
        log.warning("scan %s: lease lost to another worker; abandoning without writing", scan_id)
        lease_lost = True
    except Exception as e:
        log.exception("scan %s failed", scan_id)
        outcome = {"status": ScanStatus.failed, "error": f"{type(e).__name__}: {e}"[:4000]}
        timeline.emit(scan_id, "error", f"scan failed: {type(e).__name__}: {e}"[:500], level="error")
    finally:
        # Clean up BEFORE releasing the lease (see _release).
        _release(scan_id, res, lease_lost, dbg.keep_minutes, token)
        # The last event goes in before the status turns final: followers (dashboard poll,
        # prsec-trace --follow) read the status first and stop once it is final.
        _scan_finished(scan_id, outcome, res, started, lease_lost)
        if not lease_lost:
            queue.finish(scan_id, lease_token=token, **{k: v for k, v in outcome.items() if k != "reason"})


# --------------------------------------------------------- kept scans (debugging)


def reap_kept(limit: int = 10) -> int:
    """Tear down kept scans whose keep_until has passed (destroy_scan + work dir). Returns how many."""
    rows = queue.claim_due_kept(limit)
    for row in rows:
        _reap(int(row["id"]), row.get("kept_dir"))
    return len(rows)


def _drop_previous_keep(scan_row: dict, scan_id: int, token: str | None) -> None:
    """A revived scan still kept from its previous run: tear that keep down first, so its network
    does not collide with this run's and its work dir is not orphaned by a new keep."""
    if scan_row.get("keep_until") is None:
        return
    try:
        row = queue.release_kept(scan_id, lease_token=token)
    except Exception:
        log.exception("scan %s: could not release the previous run's keep-for-debugging", scan_id)
        return
    if row is not None:
        _reap(scan_id, row.get("kept_dir"), "a new run started")


def _reap(scan_id: int, kept_dir: str | None, why: str = "keep-for-debugging expired") -> None:
    with bind(scan_id=scan_id):
        try:
            runner_pkg.get_runner(settings().runner).destroy_scan(scan_id)
            timeline.emit(scan_id, "env_destroyed", f"{why}: kept scan network and environments destroyed")
        except Exception:
            log.exception("scan %s: destroy_scan of a kept scan failed", scan_id)
            timeline.emit(scan_id, "error", f"{why} but destroy_scan of the kept scan failed", level="error")
        root = settings().work_root.resolve()
        path = Path(kept_dir).resolve() if kept_dir else None
        if path is not None and path != root and path.is_relative_to(root):
            shutil.rmtree(path, ignore_errors=True)

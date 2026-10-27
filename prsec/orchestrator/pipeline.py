"""Phase-1 scan pipeline: rules -> triage -> hypothesise -> static_verify (fan-out) -> skeptic -> verdict -> sink.

Ownership: every write about the scan (stage runs, terminal status) carries the worker's lease token,
and the pipeline stops at the next stage boundary once the lease is gone (superseded, or requeued
after a stall and leased by someone else). A scan whose hypothesise stage failed is *incomplete*:
its SARIF says executionSuccessful=false, nothing is marked stale, and it finishes `failed` (retried).
"""
from __future__ import annotations

import fnmatch
import json
import logging
import re
import shutil
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
from prsec.citations import repo_relative
from prsec.config import Policy, current_skills_version, load_policy, settings
from prsec.db import queue
from prsec.models import (
    CodeLoc,
    Finding,
    Label,
    PRInfo,
    ScanRequest,
    ScanStatus,
    Severity,
    Stage,
    StageResult,
    StageStatus,
    StageTask,
)
from prsec.orchestrator import stages, verdict
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

    def check(self) -> None:
        if queue.is_superseded(self.scan_id):
            raise Superseded()
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
        if not f.is_file():
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


def _run(ctx: Ctx, stage: Stage, files: dict[str, str], *, prompt_ctx: dict[str, Any], hyp_id: str | None = None) -> Ran:
    names = list(files)
    task, choice = stages.build_task(
        ctx.policy, stage, ctx.scan_id, ctx.repo, context_files=names, prompt_ctx=prompt_ctx, hyp_id=hyp_id
    )
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
            env=_gateway_env(ctx, task, task_key or ctx.gw_key),
            network=ctx.network,
        )
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
    if result.status == StageStatus.ok and result.output is not None:
        try:
            output = model_for(stage).model_validate(result.output)
        except ValidationError as e:
            log.warning("stage %s output failed validation: %s", task.task_id, e)
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


def _finding(ctx: Ctx, h: Hypothesis, hyp_run: Ran, sv: Ran | None, sk: Ran | None, label: Label, reason: str) -> Finding:
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
        entry_point=h.entry_point,
        source=_loc(ctx, h.source) if h.source else None,
        sink=_loc(ctx, h.sink),
        path=[_loc(ctx, c) for c in h.path],
        guards=[f"{'effective' if g.effective else 'ineffective'}: {g.description}" for g in static.guards] if static else list(h.assumed_guards),
        remediation=static.remediation if static else None,
        evidence_uri=(sv.evidence_uri if sv else None) or hyp_run.evidence_uri,
        provenance=provenance,
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
        return []
    meta["summary"] = hyp_run.output.summary

    kept: list[Hypothesis] = []
    hyps = _relativise(_normalise_ids(hyp_run.output.hypotheses), ctx.src)
    for h in _canonical_bug_classes(hyps, _bug_class_aliases()):
        errs = _verify_all(_hyp_citations(h), ctx.src)
        if errs:
            meta["dropped"].append({"id": h.id, "reason": "hypothesis_citations_unverified", "errors": errs[:5]})
        else:
            kept.append(h)
    for h in kept[limit:]:
        meta["dropped"].append({"id": h.id, "reason": "over_cap"})
    kept = kept[:limit]

    min_rank = _SEV_RANK[Severity(policy.static_verify_min_severity)]
    to_verify = [h for h in kept if _SEV_RANK[h.severity_guess] >= min_rank]
    for h in kept:
        if h not in to_verify:
            meta["dropped"].append({"id": h.id, "reason": "below_static_verify_min_severity"})
    if not to_verify:
        return []

    ctx.check()
    with ThreadPoolExecutor(max_workers=min(VERIFY_CONCURRENCY, len(to_verify))) as pool:
        verified = list(pool.map(lambda h: (h, *_verify_one(ctx, h, hyp_files)), to_verify))

    survivors: list[tuple[Hypothesis, Ran, list[str]]] = []
    for h, sv, errs in verified:
        static = sv.output if isinstance(sv.output, StaticVerifyOutput) else None
        reason = verdict.drop_reason(static, errs)
        if reason:
            meta["dropped"].append({"id": h.id, "reason": reason, "errors": errs[:5]})
        else:
            survivors.append((h, sv, errs))

    ctx.check()
    need = [(h, sv) for h, sv, errs in survivors if verdict.needs_skeptic(sv.output, errs, h)]  # type: ignore[arg-type]
    skeptics: dict[str, Ran] = {}
    if need:
        with ThreadPoolExecutor(max_workers=min(VERIFY_CONCURRENCY, len(need))) as pool:
            for h, ran in zip([h for h, _ in need], pool.map(lambda p: _skeptic_one(ctx, p[0], p[1].output), need)):
                skeptics[h.id] = ran

    findings = []
    for h, sv, errs in survivors:
        static = sv.output if isinstance(sv.output, StaticVerifyOutput) else None
        sk = skeptics.get(h.id)
        skeptic = sk.output if sk and isinstance(sk.output, SkepticOutput) else None
        label, reason = verdict.decide(h, static, skeptic, errs)
        findings.append(_finding(ctx, h, hyp_run, sv, sk, label, reason))
    return _dedupe(findings)


# ------------------------------------------------------------------- entry


def run_scan(scan_row: dict) -> None:
    scan_id = int(scan_row["id"])
    repo = scan_row["repo"]
    number = int(scan_row["pr"])
    inst = scan_row.get("installation_id")
    token = scan_row.get("lease_token")
    gw_key = ""
    runner: Runner | None = None
    root: Path | None = None
    outcome: dict[str, Any] = {"status": ScanStatus.failed}
    lease_lost = False
    try:
        policy = load_policy()
        if not policy.repo_enabled(repo):
            outcome = {"status": ScanStatus.skipped, "triage": {"decision": "skip", "source": "policy", "reason": "repo_disabled"}}
            return

        scm = scm_pkg.get_scm(scan_row.get("scm") or "github")
        pr = scm.get_pr(repo, number, inst)
        if pr.head_sha != scan_row["head_sha"]:
            # The diff, commits and file list from the SCM describe the current head, not the queued
            # one: scanning would mix two commits. The current head gets (or already has) its own scan.
            log.info("scan %s: PR head moved %s -> %s; superseding", scan_id, scan_row["head_sha"], pr.head_sha)
            _enqueue_current_head(scan_row, pr)
            raise Superseded()
        pr = pr.model_copy(update={"base_sha": scan_row.get("base_sha") or pr.base_sha})
        diff = scm.get_diff(repo, number, inst)
        changed = _changed_files(pr, diff)

        rule, rule_reason = triage_rules.classify(changed, diff)
        rules = {"decision": rule, "reason": rule_reason}
        audited = stages.bucket(scan_id, "skip_audit") < policy.skip_audit_sample
        if rule == "skip" and not audited:
            outcome = {"status": ScanStatus.skipped, "triage": {"decision": "skip", "source": "rules", "reason": rule_reason, "rules": rules}}
            return
        if queue.is_superseded(scan_id):
            raise Superseded()

        root = _work_dir(scan_id, token)
        src = root / "src"
        if src.exists():
            shutil.rmtree(src)
        src.mkdir(parents=True)
        scm.fetch_source(repo, pr.head_sha, src, inst)

        per_task = gateway.per_task_keys()
        usd, wall, models = stages.scan_budget(policy, repo, policy.max_hypotheses)
        if not per_task:  # dev: one shared (passthrough) key; with a master key every task gets its own
            gw_key = gateway.mint_key(scan_id, usd, wall + KEY_GRACE_S, models)
        runner = runner_pkg.get_runner(settings().runner)
        network = runner.create_scan_network(scan_id)

        override = next((ov.workbench_image for p, ov in policy.repos.items()
                         if ov.workbench_image and fnmatch.fnmatch(repo, p)), None)
        skills_version = scan_row.get("skills_version") or settings().skills_version
        ctx = Ctx(
            scan_id=scan_id, repo=repo, pr=pr, policy=policy, root=root, src=src, runner=runner, network=network,
            gw_key=gw_key, image=override or policy.workbench_image, skills_version=skills_version,
            lease_token=token, per_task_keys=per_task,
        )
        ctx.shared = {"pr.json": _pr_json(pr), "diff.patch": diff, "changed_files.txt": "\n".join(changed) + "\n"}
        profile = settings().work_root / "profiles" / f"{repo.replace('/', '__')}.json"
        if profile.is_file():
            ctx.shared["repo_profile.json"] = profile.read_text()

        ctx.check()
        triage, decision = _triage(ctx, rules, audited)
        if decision == "skip":
            outcome = {"status": ScanStatus.skipped, "triage": triage}
            return

        meta: dict[str, Any] = {"dropped": [], "complete": True, "errors": []}
        findings = _analyse(ctx, triage, decision, meta)
        ctx.check()

        run_meta = {
            **meta,
            "triage": triage,
            "skills_version": ctx.skills_version,
            "image": ctx.image,
            "scanned_files": changed,
            "changed_files": changed,
            "base_sha": pr.base_sha,
        }
        mounted = current_skills_version()
        if mounted != ctx.skills_version:
            run_meta["skills_version_mounted"] = mounted
        uri = sinks_pkg.get_sink().write_scan(scan_id, pr, findings, run_meta)
        if meta["complete"]:
            outcome = {"status": ScanStatus.done, "triage": triage, "sarif_uri": uri}
        else:
            outcome = {"status": ScanStatus.failed, "triage": triage, "sarif_uri": uri,
                       "error": ("incomplete: " + "; ".join(meta["errors"]))[:4000]}
    except Superseded:
        log.info("scan %s superseded; aborting", scan_id)
        outcome = {"status": ScanStatus.superseded}
    except LeaseLost:
        log.warning("scan %s: lease lost to another worker; abandoning without writing", scan_id)
        lease_lost = True
    except Exception as e:
        log.exception("scan %s failed", scan_id)
        outcome = {"status": ScanStatus.failed, "error": f"{type(e).__name__}: {e}"[:4000]}
    finally:
        # Clean up BEFORE releasing the lease: once finish() clears it, the same scan id may be
        # revived and leased again, and must not lose its containers/network to our cleanup.
        if runner is not None and not lease_lost:
            try:
                runner.destroy_scan(scan_id)
            except Exception:
                log.exception("scan %s: destroy_scan failed", scan_id)
        try:
            gateway.revoke_key(gw_key)
        except Exception:
            log.exception("scan %s: revoke_key failed", scan_id)
        if root is not None:
            shutil.rmtree(root, ignore_errors=True)
        if not lease_lost:
            queue.finish(scan_id, lease_token=token, **outcome)

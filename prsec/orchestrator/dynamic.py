"""Phase 2 in the scan pipeline: env stage -> per hypothesis (dynamic stage -> agent-free replays).

For static survivors (see `_candidates`), the `env` stage writes an EnvSpec once per scan; then,
`policy.dynamic.concurrency` hypotheses at a time, the `dynamic` stage runs in its own environment
(`h<i>`: sink, catalog services, LLM gateway) and returns a PoC. A reproduced PoC is replayed
without an agent in fresh environments: `policy.dynamic.replay_runs` times on head (`h<i>r<n>`,
stopping at the first run that does not fire) and, once head is confirmed, once on base (`h<i>b`).
Only the replays count; they become a `DynamicEvidence` per hypothesis for `verdict.decide`.

Nothing here fails the scan: every failure becomes `DynamicEvidence(outcome="error"|"env_failed")`,
an unsupported runner `outcome="skipped"`. Superseded / LeaseLost from `ctx.check()` propagate.
See docs/design/phase2-dynamic.md.
"""
from __future__ import annotations

import json
import logging
import shutil
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from prsec.adapters.protocols import WorkbenchSpec
from prsec.config import settings
from prsec.dynamic.envspec import EnvSpec
from prsec.dynamic.poc import PoC
from prsec.dynamic.results import (
    APP_DIR,
    ENVSPEC_FILE,
    REPLAY_REQUEST,
    DynamicEvidence,
    EnvRequest,
    ReplayRequest,
    ReplayResult,
    ServiceRequest,
)
from prsec.models import Limits, Severity, Stage, StageTask
from prsec.orchestrator import pipeline, stages
from prsec.stages.outputs import DynamicOutput, EnvOutput, Hypothesis, StaticVerifyOutput

log = logging.getLogger(__name__)

PREVIOUS_ENVSPEC = "previous_envspec.json"
EVIDENCE_FILE = "dynamic_evidence.json"
LOCAL_RUNNER = "local"  # LocalRunner: no containers, so no dynamic environments
_SURVIVING = ("plausible", "confirmed_static")
_REASON_MAX = 500


@dataclass
class _State:
    """Shared by the per-hypothesis workers of one scan."""

    ctx: pipeline.Ctx
    spec: EnvSpec  # the env stage's spec: its services are authoritative
    lock: threading.Lock = field(default_factory=threading.Lock)
    base_fetched: bool = False
    base_src: Path | None = None
    cached: bool = False


# ------------------------------------------------------------------ helpers


def _evidence(h: Hypothesis, outcome: str, reason: str = "", **kw: Any) -> DynamicEvidence:
    return DynamicEvidence(hypothesis_id=h.id, outcome=outcome, reason=reason[:_REASON_MAX], **kw)  # type: ignore[arg-type]


def _error(e: BaseException) -> str:
    return f"{type(e).__name__}: {e}"[:_REASON_MAX]


def _fresh_dir(path: Path) -> Path:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)
    return path


def _profile_path(repo: str) -> Path:
    return settings().work_root / "profiles" / f"{repo.replace('/', '__')}.envspec.json"


def _previous_envspec(repo: str) -> str | None:
    """Spec that last started this repo's app (cached on a healthy replay env), if it still parses."""
    p = _profile_path(repo)
    try:
        return EnvSpec.model_validate_json(p.read_text()).model_dump_json(indent=2) if p.is_file() else None
    except Exception:
        log.warning("ignoring unreadable cached envspec %s", p, exc_info=True)
        return None


def _cache_envspec(st: _State, spec: EnvSpec) -> None:
    with st.lock:
        if st.cached:
            return
        st.cached = True
    p = _profile_path(st.ctx.repo)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(f".{st.ctx.scan_id}.tmp")
        tmp.write_text(spec.model_dump_json(indent=2))
        tmp.replace(p)
    except OSError:
        log.warning("scan %s: could not cache envspec at %s", st.ctx.scan_id, p, exc_info=True)


def _supports_envs(runner: Any) -> bool:
    """Checked before the (paid) env stage, from `Runner.supports_envs`. A runner without the flag
    is treated as supporting envs unless it is the local one; a NotImplementedError from create_env
    is still mapped to runner_unsupported by `_one`."""
    if not callable(getattr(runner, "create_env", None)):
        return False
    return bool(getattr(runner, "supports_envs", getattr(runner, "name", "") != LOCAL_RUNNER))


def _candidates(
    ctx: pipeline.Ctx, survivors: list[tuple[Hypothesis, pipeline.Ran, list[str]]], meta: dict[str, Any]
) -> list[tuple[Hypothesis, StaticVerifyOutput]]:
    """Survivors with a usable static verdict at or above dynamic.min_severity, worst first, capped."""
    pol = ctx.policy.dynamic
    floor = pipeline._SEV_RANK[Severity(pol.min_severity)]
    eligible = []
    for h, sv, errs in survivors:
        static = sv.output
        if (isinstance(static, StaticVerifyOutput) and not errs and static.hypothesis_id == h.id
                and static.verdict in _SURVIVING and pipeline._SEV_RANK[static.severity] >= floor):
            eligible.append((h, static))
    eligible.sort(key=lambda p: pipeline._SEV_RANK[p[1].severity], reverse=True)
    meta["dynamic"]["not_selected"] = [h.id for h, _ in eligible[pol.max_hypotheses:]]
    return eligible[:pol.max_hypotheses]


# ---------------------------------------------------------------- env stage


def _env_stage(ctx: pipeline.Ctx, meta: dict[str, Any]) -> EnvSpec | None:
    """Once per scan, on the static scan network (no services)."""
    files = dict(ctx.shared)
    previous = _previous_envspec(ctx.repo)
    if previous:
        files[PREVIOUS_ENVSPEC] = previous
    from prsec.dynamic.catalog import describe

    ran = pipeline._run(ctx, Stage.env, files, prompt_ctx={
        "pr_number": ctx.pr.number, "catalog": describe(), "has_previous_envspec": previous is not None,
    })
    meta["dynamic"]["env_stage"] = ran.result.status.value
    return ran.output.envspec if isinstance(ran.output, EnvOutput) else None


# ------------------------------------------------------------ environments


def _seed_dir(st: _State, src: Path, env_name: str, name: str, seeds: list[str], kind: str) -> str | None:
    """Copy a service's repo-relative seed files (in order) into a dir under the work root."""
    from prsec.dynamic.catalog import load_catalog

    entry = load_catalog().services.get(kind)
    if not seeds or entry is None or not entry.seed_path:
        return None
    out = _fresh_dir(st.ctx.root / "seeds" / env_name / name)
    root = src.resolve()
    for n, rel in enumerate(seeds):
        f = (root / rel).resolve()
        if not f.is_relative_to(root) or not f.is_file():
            log.warning("scan %s: seed %r of %s is not a repository file; skipped", st.ctx.scan_id, rel, name)
            continue
        shutil.copyfile(f, out / f"{n:02d}-{f.name}")
    return str(out)


def _env_request(st: _State, spec: EnvSpec, src: Path, env_name: str, *, llm: bool) -> EnvRequest:
    services = [
        ServiceRequest(name=s.name, kind=s.kind, seed_dir=_seed_dir(st, src, env_name, s.name, s.seed, s.kind))
        for s in spec.services
    ]
    env_dir = _fresh_dir(st.ctx.root / "envs" / env_name)
    return EnvRequest(services=services, stubs=spec.stubs, llm=llm, packages=True, env_dir=str(env_dir))


def _destroy(st: _State, env_name: str) -> None:
    try:
        st.ctx.runner.destroy_env(st.ctx.scan_id, env_name)
    except Exception:
        log.warning("scan %s: destroy_env %s failed (destroy_scan cleans up)", st.ctx.scan_id, env_name, exc_info=True)


# ------------------------------------------------------------ dynamic stage


def _stage_files(st: _State, h: Hypothesis, static: StaticVerifyOutput) -> dict[str, str]:
    ctx = st.ctx
    return {
        "hypothesis.json": json.dumps(pipeline._strip_quotes(h.model_dump(mode="json")), indent=2),
        "static_verify.json": json.dumps(pipeline._strip_quotes(static.model_dump(mode="json")), indent=2),
        ENVSPEC_FILE: st.spec.model_dump_json(indent=2),
        "code_slices.md": pipeline._code_slices(ctx, pipeline._hyp_citations(h) + pipeline._static_citations(static)),
        "pr.json": ctx.shared["pr.json"],
        "diff.patch": ctx.shared["diff.patch"],
    }


def _agent_result(h: Hypothesis, ran: pipeline.Ran) -> DynamicOutput | DynamicEvidence:
    """The stage output when it claims a reproduced PoC, else the evidence that ends this hypothesis."""
    out = ran.output
    if not isinstance(out, DynamicOutput):
        status = ran.result.status.value
        return _evidence(h, "error", f"dynamic stage {'output_invalid' if status == 'ok' else status}")
    if out.hypothesis_id != h.id:
        return _evidence(h, "error", "dynamic_hypothesis_mismatch")
    if out.outcome == "reproduced":
        return out if out.poc is not None else _evidence(h, "not_reproduced", "reproduced_without_poc")
    if out.outcome == "env_failed":
        return _evidence(h, "env_failed", f"agent: {out.reasoning}")
    # not_reproduced, or blocked (the environment cannot provide what a proof needs): no proof either way
    return _evidence(h, "not_reproduced", f"{out.outcome}: {out.reasoning}")


def _attempt(
    st: _State, i: int, h: Hypothesis, static: StaticVerifyOutput
) -> tuple[DynamicOutput | DynamicEvidence, dict[str, Any]]:
    """The dynamic stage in its own env `h<i>`, and its provenance. NotImplementedError (no envs) propagates."""
    ctx = st.ctx
    env_name = f"h{i}"
    app_dir = _fresh_dir(ctx.root / "app" / env_name)
    try:
        ctx.runner.create_env(ctx.scan_id, env_name, _env_request(st, st.spec, ctx.src, env_name, llm=True))
    except NotImplementedError:
        raise
    except Exception as e:
        log.warning("scan %s: create_env %s failed", ctx.scan_id, env_name, exc_info=True)
        return _evidence(h, "env_failed", f"create_env: {_error(e)}"), {}
    try:
        ran = pipeline._run(
            ctx, Stage.dynamic, _stage_files(st, h, static),
            prompt_ctx={"pr_number": ctx.pr.number, "bug_class": h.bug_class, "app_dir": APP_DIR},
            hyp_id=h.id, env_name=env_name, app_dir=app_dir,
        )
    finally:
        _destroy(st, env_name)
    return _agent_result(h, ran), ran.provenance(ctx)


# ------------------------------------------------------------------ replays


def _replay_task(st: _State, run_id: str) -> StageTask:
    """Replays run no agent; the task only names the run and carries its wall clock."""
    sp = st.ctx.policy.stage(Stage.dynamic.value, st.ctx.repo)
    return StageTask(
        scan_id=st.ctx.scan_id, stage=Stage.dynamic, task_id=run_id, harness=sp.harness, model_alias=sp.model,
        prompt_md="", output_schema={}, context_files=[Path(REPLAY_REQUEST).name],
        limits=Limits(wall_clock_s=st.ctx.policy.dynamic.replay_timeout_s, usd_budget=0.0),
    )


def _run_replay(st: _State, env_name: str, run_id: str, src: Path, spec: EnvSpec, poc: PoC) -> ReplayResult:
    ctx = st.ctx
    task = _replay_task(st, run_id)
    in_dir = _fresh_dir(ctx.root / "in" / run_id)
    out_dir = _fresh_dir(ctx.root / "out" / run_id)
    req = ReplayRequest(run_id=run_id, envspec=spec, poc=poc, timeout_s=ctx.policy.dynamic.replay_timeout_s)
    (in_dir / Path(REPLAY_REQUEST).name).write_text(req.model_dump_json(indent=2, by_alias=True))
    wb = WorkbenchSpec(
        scan_id=ctx.scan_id, task=task, image=ctx.image, harness_volume=None, src_dir=src, in_dir=in_dir,
        out_dir=out_dir, skills_dir=settings().skills_dir, network=None, env_name=env_name,
        app_dir=_fresh_dir(ctx.root / "app" / env_name), mode="replay",
    )
    try:
        return ctx.runner.run_replay(wb)
    except Exception as e:
        log.warning("scan %s: replay %s failed in runner", ctx.scan_id, run_id, exc_info=True)
        return ReplayResult(run_id=run_id, env_ok=False, env_error=f"run_replay: {_error(e)}", entry=poc.kind)


def _replay(st: _State, env_name: str, run_id: str, src: Path, spec: EnvSpec, poc: PoC) -> ReplayResult:
    """One agent-free replay in a fresh env (no gateway) with a fresh app dir."""
    ctx = st.ctx
    ctx.check()
    try:
        ctx.runner.create_env(ctx.scan_id, env_name, _env_request(st, spec, src, env_name, llm=False))
    except NotImplementedError:
        raise
    except Exception as e:
        log.warning("scan %s: create_env %s failed", ctx.scan_id, env_name, exc_info=True)
        return ReplayResult(run_id=run_id, env_ok=False, env_error=f"create_env: {_error(e)}", entry=poc.kind)
    try:
        return _run_replay(st, env_name, run_id, src, spec, poc)
    finally:
        _destroy(st, env_name)


def _base_src(st: _State) -> Path | None:
    """Base source, fetched once per scan (None when it cannot be fetched)."""
    ctx = st.ctx
    with st.lock:
        if not st.base_fetched:
            st.base_fetched = True
            dest = _fresh_dir(ctx.root / "base_src")
            try:
                st.base_src = ctx.scm.fetch_source(ctx.repo, ctx.pr.base_sha, dest, ctx.installation_id)
            except Exception:
                log.warning("scan %s: could not fetch base %s", ctx.scan_id, ctx.pr.base_sha, exc_info=True)
        return st.base_src


def _replay_spec(st: _State, corrected: EnvSpec | None) -> EnvSpec:
    """The agent's corrected commands/env/stubs with the env stage's (authoritative) services."""
    return (corrected or st.spec).model_copy(update={"services": st.spec.services})


def _head_replays(st: _State, i: int, prefix: str, spec: EnvSpec, poc: PoC) -> list[ReplayResult]:
    """Up to replay_runs head replays; stops at the first that does not fire (it cannot confirm)."""
    runs: list[ReplayResult] = []
    for n in range(1, st.ctx.policy.dynamic.replay_runs + 1):
        r = _replay(st, f"h{i}r{n}", f"{prefix}-r{n}", st.ctx.src, spec, poc)
        runs.append(r)
        if r.env_ok:
            _cache_envspec(st, spec)
        if not (r.env_ok and r.fired):
            break
    return runs


def _replayed(st: _State, i: int, h: Hypothesis, out: DynamicOutput) -> DynamicEvidence:
    assert out.poc is not None
    poc = out.poc
    spec = _replay_spec(st, out.envspec)
    prefix = f"{st.ctx.scan_id}-replay-{h.id}"
    head = _head_replays(st, i, prefix, spec, poc)
    fired = sum(1 for r in head if r.env_ok and r.fired)
    ev = _evidence(h, "not_reproduced", f"replay fired {fired}/{len(head)}", entry=poc.kind, head_runs=len(head),
                   head_fired=fired, poc=poc, replays=head)
    if not any(r.env_ok for r in head):
        return ev.model_copy(update={"outcome": "env_failed", "reason": f"replay env: {head[0].env_error}"[:_REASON_MAX]})
    if not ev.replay_confirmed:
        return ev
    ev = ev.model_copy(update={"outcome": "reproduced", "reason": "replay_confirmed"})
    base_src = _base_src(st) if st.ctx.policy.dynamic.base_replay else None
    if base_src is None:
        return ev
    base = _replay(st, f"h{i}b", f"{prefix}-base", base_src, spec, poc)
    return ev.model_copy(update={
        "base_ran": base.env_ok, "base_fired": base.fired if base.env_ok else None, "replays": [*head, base],
    })


# ------------------------------------------------------------------- driver


def _upload(ctx: pipeline.Ctx, ev: DynamicEvidence) -> DynamicEvidence:
    """Store the evidence bundle (PoC, replay results) next to the dynamic stage's transcript."""
    from prsec.adapters.sinks.sarif_store import evidence_key

    task_id = stages.task_id(ctx.scan_id, Stage.dynamic, ev.hypothesis_id)
    key = evidence_key(ctx.repo, ctx.pr.number, ctx.pr.head_sha, task_id, EVIDENCE_FILE)
    try:
        uri = pipeline._put_evidence(key, ev.model_dump_json(indent=2, by_alias=True).encode(), "application/json")
    except Exception:
        log.warning("scan %s: could not store dynamic evidence of %s", ctx.scan_id, ev.hypothesis_id, exc_info=True)
        return ev
    return ev.model_copy(update={"evidence_uri": uri})


def _one(st: _State, i: int, h: Hypothesis, static: StaticVerifyOutput) -> DynamicEvidence:
    """Never raises, except Superseded / LeaseLost (the scan must stop)."""
    try:
        st.ctx.check()
        res, provenance = _attempt(st, i, h, static)
        ev = res if isinstance(res, DynamicEvidence) else _replayed(st, i, h, res)
        ev = ev.model_copy(update={"provenance": provenance})
    except (pipeline.Superseded, pipeline.LeaseLost):
        raise
    except NotImplementedError:
        return _evidence(h, "skipped", "runner_unsupported")
    except Exception as e:
        log.exception("scan %s: dynamic validation of %s failed", st.ctx.scan_id, h.id)
        ev = _evidence(h, "error", _error(e))
    return _upload(st.ctx, ev)


def _skip_all(cands: list[tuple[Hypothesis, StaticVerifyOutput]], outcome: str, reason: str) -> dict[str, DynamicEvidence]:
    return {h.id: _evidence(h, outcome, reason) for h, _ in cands}


def _gate(ctx: pipeline.Ctx) -> str | None:
    """Why dynamic cannot run at all in this scan, or None."""
    missing = [s for s in (Stage.env.value, Stage.dynamic.value) if s not in ctx.policy.defaults]
    if missing:
        return f"stage_not_configured: {', '.join(missing)}"
    if not _supports_envs(ctx.runner):
        return "runner_unsupported"
    return None


def run_dynamic(
    ctx: pipeline.Ctx, survivors: list[tuple[Hypothesis, pipeline.Ran, list[str]]], meta: dict[str, Any]
) -> dict[str, DynamicEvidence]:
    """DynamicEvidence by hypothesis id for the selected survivors ({} when dynamic is off)."""
    if not ctx.policy.dynamic.enabled:
        return {}
    meta["dynamic"] = {}
    cands = _candidates(ctx, survivors, meta)
    meta["dynamic"]["candidates"] = [h.id for h, _ in cands]
    if not cands:
        return {}
    gate = _gate(ctx)
    if gate:
        meta["dynamic"]["skipped"] = gate
        return _skip_all(cands, "skipped", gate)

    ctx.check()
    spec = _env_stage(ctx, meta)
    if spec is None:
        return _skip_all(cands, "env_failed", f"env stage {meta['dynamic']['env_stage']}")
    st = _State(ctx=ctx, spec=spec)
    workers = max(1, min(ctx.policy.dynamic.concurrency, len(cands)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        evidence = list(pool.map(lambda p: _one(st, p[0], *p[1]), enumerate(cands, 1)))
    meta["dynamic"]["outcomes"] = {ev.hypothesis_id: ev.outcome for ev in evidence}
    return {ev.hypothesis_id: ev for ev in evidence}

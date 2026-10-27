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

Timeline: env_created / env_destroyed per environment (with service health), one `replay` event per
replay (fired, which oracles passed) and one `dynamic_outcome` per hypothesis. With ctx.keep
(debug.keep_minutes > 0) used environments and their dirs are left up for inspection; the scan's
destroy_scan, run by the worker's reaper once the keep expires, removes them.
"""
from __future__ import annotations

import hashlib
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
from prsec.obs.logging import bind, submit_with_context
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
    keep_dirs: bool = False  # keep per-env app/env/seed dirs after use (debugging); else freed right away
    keep_envs: bool = False  # leave used envs up (debugging); destroy_scan removes them later
    kept: set[str] = field(default_factory=set)  # envs left up under keep_envs


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
    from prsec.dynamic.catalog import load_catalog, seed_allowed

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
        if not seed_allowed(entry, f.name):  # *.sh / *.js would run as code in the service container
            log.warning("scan %s: seed %r of %s is not a data file (%s); skipped", st.ctx.scan_id, rel, name,
                        ", ".join(entry.seed_suffixes))
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


def _env_name(st: _State, base: str) -> str:
    """`base` plus a short tag of this lease: a stale run and its successor never share (or destroy)
    each other's envs, although both work on the same scan id."""
    token = st.ctx.lease_token
    return f"{base}{hashlib.sha256(token.encode()).hexdigest()[:4]}" if token else base


def _destroy(st: _State, env_name: str) -> None:
    with st.lock:
        st.kept.discard(env_name)
    try:
        st.ctx.runner.destroy_env(st.ctx.scan_id, env_name)
    except Exception:
        log.warning("scan %s: destroy_env %s failed (destroy_scan cleans up)", st.ctx.scan_id, env_name, exc_info=True)
        st.ctx.emit("env_destroyed", f"env {env_name}: destroy failed (destroy_scan cleans up)", level="warning",
                    data={"env": env_name})
        return
    st.ctx.emit("env_destroyed", f"env {env_name} destroyed", data={"env": env_name})


def _done_with(st: _State, env_name: str) -> None:
    """An env is no longer needed: destroy it, or leave it up for debugging."""
    if not st.keep_envs:
        _destroy(st, env_name)
        return
    with st.lock:
        st.kept.add(env_name)
    st.ctx.emit("env_destroyed", f"env {env_name} left up for debugging (keep-for-debugging)",
                data={"env": env_name, "kept": True})


def _cleanup(st: _State, env_name: str) -> None:
    """Free an env's host dirs (full app installs) as soon as it is gone; results live in out/."""
    if st.keep_dirs:
        return
    for sub in ("app", "envs", "seeds"):
        shutil.rmtree(st.ctx.root / sub / env_name, ignore_errors=True)


def _unhealthy(info: Any) -> str | None:
    services = getattr(info, "services", None) or {}
    bad = sorted(f"{name}: {status}" for name, status in services.items() if status != "healthy")
    return "; ".join(bad) or None


def _create(st: _State, env_name: str, req: EnvRequest) -> str | None:
    """Create env `env_name`; None when it is usable, else why not (it is then destroyed again: a
    launcher call that timed out may still be building it). NotImplementedError propagates."""
    ctx = st.ctx
    if env_name in st.kept:  # kept for debugging, now reused (a retry): it must start fresh
        _destroy(st, env_name)
    try:
        info = ctx.runner.create_env(ctx.scan_id, env_name, req)
    except NotImplementedError:
        raise
    except Exception as e:
        log.warning("scan %s: create_env %s failed", ctx.scan_id, env_name, exc_info=True)
        ctx.emit("env_created", f"env {env_name} could not be created: {_error(e)}", level="warning",
                 data={"env": env_name, "ok": False})
        _destroy(st, env_name)
        return f"create_env: {_error(e)}"
    services = getattr(info, "services", None) or {}
    health = ", ".join(f"{n} {v}" for n, v in sorted(services.items())) or "no services"
    bad = _unhealthy(info)
    ctx.emit("env_created", f"env {env_name} {'unusable' if bad else 'up'}: {health}"[:_REASON_MAX],
             level="warning" if bad else "info",
             data={"env": env_name, "ok": not bad, "services": services, "llm": req.llm,
                   "network": getattr(info, "network", None)})
    if bad:  # a dead mock database would read as "the PoC does not fire"
        log.warning("scan %s: env %s has unhealthy services: %s", ctx.scan_id, env_name, bad)
        _destroy(st, env_name)
        return f"services not healthy: {bad}"[:_REASON_MAX]
    return None


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
    env_name = _env_name(st, f"h{i}")
    app_dir = _fresh_dir(ctx.root / "app" / env_name)
    try:
        failed = _create(st, env_name, _env_request(st, st.spec, ctx.src, env_name, llm=True))
        if failed:
            return _evidence(h, "env_failed", failed), {}
        try:
            ran = pipeline._run(
                ctx, Stage.dynamic, _stage_files(st, h, static),
                prompt_ctx={"pr_number": ctx.pr.number, "bug_class": h.bug_class, "app_dir": APP_DIR},
                hyp_id=h.id, env_name=env_name, app_dir=app_dir,
            )
        finally:
            _done_with(st, env_name)
    finally:
        _cleanup(st, env_name)
    return _agent_result(h, ran), ran.provenance(ctx)


# ------------------------------------------------------------------ replays


def replay_wall_clock_s(replay_timeout_s: int, spec: EnvSpec) -> int:
    """A replay installs and starts the app from scratch (each under its own EnvSpec timeout) before
    the PoC gets replay_timeout_s; the container's wall clock covers all three."""
    return spec.install_timeout_s + spec.health.timeout_s + replay_timeout_s


def _replay_task(st: _State, run_id: str, spec: EnvSpec) -> StageTask:
    """Replays run no agent; the task only names the run and carries its wall clock."""
    sp = st.ctx.policy.stage(Stage.dynamic.value, st.ctx.repo)
    wall = replay_wall_clock_s(st.ctx.policy.dynamic.replay_timeout_s, spec)
    return StageTask(
        scan_id=st.ctx.scan_id, stage=Stage.dynamic, task_id=run_id, harness=sp.harness, model_alias=sp.model,
        prompt_md="", output_schema={}, context_files=[Path(REPLAY_REQUEST).name],
        limits=Limits(wall_clock_s=wall, usd_budget=0.0),
    )


def _run_replay(st: _State, env_name: str, run_id: str, src: Path, spec: EnvSpec, poc: PoC) -> ReplayResult:
    ctx = st.ctx
    task = _replay_task(st, run_id, spec)
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
    with bind(env=env_name):
        r = _replay_in_env(st, env_name, run_id, src, spec, poc)
        _replay_event(st, r)
    return r


def _replay_in_env(st: _State, env_name: str, run_id: str, src: Path, spec: EnvSpec, poc: PoC) -> ReplayResult:
    try:
        failed = _create(st, env_name, _env_request(st, spec, src, env_name, llm=False))
        if failed:
            return ReplayResult(run_id=run_id, env_ok=False, env_error=failed, entry=poc.kind)
        try:
            return _run_replay(st, env_name, run_id, src, spec, poc)
        finally:
            _done_with(st, env_name)
    finally:
        _cleanup(st, env_name)


def _replay_event(st: _State, r: ReplayResult) -> None:
    where = "base" if r.run_id.endswith("-base") else "head"
    passed = [f"{o.type}#{o.index}" for o in r.oracle_results if o.passed]
    if not r.env_ok:
        msg, level = f"replay {r.run_id} on {where}: environment failed: {r.env_error}", "warning"
    else:
        msg = (f"replay {r.run_id} on {where}: {'fired' if r.fired else 'did not fire'}; oracles passed "
               f"{len(passed)}/{len(r.oracle_results)}" + (f" ({', '.join(passed)})" if passed else ""))
        if r.aborted:
            msg += f"; aborted: {r.aborted}" + (" (incomplete: no evidence)" if r.incomplete else "")
        level = "info"
    st.ctx.emit("replay", msg[:_REASON_MAX * 2], level=level, data={
        "run_id": r.run_id, "on": where, "env_ok": r.env_ok, "env_error": r.env_error, "fired": r.fired,
        "aborted": r.aborted, "incomplete": r.incomplete, "duration_s": r.duration_s,
        "oracles": [{"index": o.index, "type": o.type, "passed": o.passed, "detail": o.detail[:300]}
                    for o in r.oracle_results],
    })


def _replay_retrying(st: _State, env_name: str, run_id: str, src: Path, spec: EnvSpec, poc: PoC) -> ReplayResult:
    """One replay; an env failure (pull, install, health) is retried once: it is not a verdict on the PoC."""
    r = _replay(st, env_name, run_id, src, spec, poc)
    if r.env_ok:
        return r
    log.info("scan %s: replay %s env failed (%s); retrying once", st.ctx.scan_id, run_id, r.env_error)
    return _replay(st, env_name, f"{run_id}-retry", src, spec, poc)


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
        r = _replay_retrying(st, _env_name(st, f"h{i}r{n}"), f"{prefix}-r{n}", st.ctx.src, spec, poc)
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
    ran = [r for r in head if r.env_ok]  # only runs whose env came up say anything about the PoC
    fired = sum(1 for r in ran if r.fired)
    ev = _evidence(h, "not_reproduced", f"replay fired {fired}/{len(ran)}", entry=poc.kind, head_runs=len(ran),
                   head_fired=fired, poc=poc, replays=head)
    env_failed = [r for r in head if not r.env_ok]
    if env_failed and fired == len(ran):  # no run failed to fire; an environment failed
        return ev.model_copy(update={"outcome": "env_failed",
                                     "reason": f"replay env: {env_failed[-1].env_error}"[:_REASON_MAX]})
    if not ev.replay_confirmed:
        return ev
    ev = ev.model_copy(update={"outcome": "reproduced", "reason": "replay_confirmed"})
    base_src = _base_src(st) if st.ctx.policy.dynamic.base_replay else None
    if base_src is None:
        return ev
    base = _replay(st, _env_name(st, f"h{i}b"), f"{prefix}-base", base_src, spec, poc)
    # A base run that crashed, timed out or hit a transport error did not "not fire": introduced unknown.
    usable = base.env_ok and not base.incomplete
    return ev.model_copy(update={
        "base_ran": usable, "base_fired": base.fired if usable else None, "replays": [*head, base],
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
    with bind(hypothesis_id=h.id):
        ev = _one_bound(st, i, h, static)
        _outcome_event(st.ctx, ev)
    return ev


def _outcome_event(ctx: pipeline.Ctx, ev: DynamicEvidence) -> None:
    detail = f"; head fired {ev.head_fired}/{ev.head_runs}" if ev.head_runs else ""
    if ev.base_ran:
        detail += f"; base {'fired' if ev.base_fired else 'did not fire'}"
    level = "warning" if ev.outcome in ("error", "env_failed") else "info"
    ctx.emit("dynamic_outcome", f"{ev.hypothesis_id}: {ev.outcome} ({ev.reason}){detail}", level=level,
             hypothesis_id=ev.hypothesis_id,
             data={"outcome": ev.outcome, "reason": ev.reason, "entry": ev.entry, "head_runs": ev.head_runs,
                   "head_fired": ev.head_fired, "base_ran": ev.base_ran, "base_fired": ev.base_fired,
                   "evidence_uri": ev.evidence_uri})


def _one_bound(st: _State, i: int, h: Hypothesis, static: StaticVerifyOutput) -> DynamicEvidence:
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


def _skip_all(
    ctx: pipeline.Ctx, cands: list[tuple[Hypothesis, StaticVerifyOutput]], outcome: str, reason: str
) -> dict[str, DynamicEvidence]:
    out = {h.id: _evidence(h, outcome, reason) for h, _ in cands}
    for ev in out.values():
        _outcome_event(ctx, ev)
    return out


def _candidates_event(
    ctx: pipeline.Ctx, cands: list[tuple[Hypothesis, StaticVerifyOutput]], not_selected: list[str]
) -> None:
    if not cands:
        ctx.emit("dynamic_outcome", "dynamic validation: no static survivor qualifies (verdict, severity floor)")
        return
    over = f"; over the cap: {', '.join(not_selected)}" if not_selected else ""
    ctx.emit("dynamic_outcome", f"dynamic validation of {len(cands)} hypothesis(es): "
             f"{', '.join(h.id for h, _ in cands)}{over}",
             data={"candidates": [h.id for h, _ in cands], "not_selected": not_selected})


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
    _candidates_event(ctx, cands, meta["dynamic"]["not_selected"])
    if not cands:
        return {}
    gate = _gate(ctx)
    if gate:
        meta["dynamic"]["skipped"] = gate
        return _skip_all(ctx, cands, "skipped", gate)

    ctx.check()
    spec = _env_stage(ctx, meta)
    if spec is None:
        return _skip_all(ctx, cands, "env_failed", f"env stage {meta['dynamic']['env_stage']}")
    keep = bool(getattr(ctx, "keep", False))
    st = _State(ctx=ctx, spec=spec, keep_dirs=keep, keep_envs=keep)
    workers = max(1, min(ctx.policy.dynamic.concurrency, len(cands)))
    pool = ThreadPoolExecutor(max_workers=workers)
    try:
        futures = [submit_with_context(pool, _one, st, i, h, static) for i, (h, static) in enumerate(cands, 1)]
        evidence = [f.result() for f in futures]
    except BaseException:  # Superseded / LeaseLost: start no further hypothesis
        pool.shutdown(wait=True, cancel_futures=True)
        raise
    pool.shutdown()
    meta["dynamic"]["outcomes"] = {ev.hypothesis_id: ev.outcome for ev in evidence}
    return {ev.hypothesis_id: ev for ev in evidence}

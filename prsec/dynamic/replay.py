"""Agent-free PoC interpreter: `prsec-replay /work/in/replay.json` -> /work/out/replay_result.json.

The same `PocEngine` backs `prsec-poc run` and `prsec-http`, so what the agent sees while authoring
a PoC is exactly what the replay evaluates. The replay itself never raises: an app that does not come
up is reported as env_ok=false with env_error.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel

from prsec.dynamic.app import AppRunner, EnvError, new_canaries
from prsec.dynamic.poc import (
    SCRIPT_STEP, CanaryHit, Command, JsonCompare, Oracle, PoC, ResponseContains, ResponseStatus, Step, User,
)
from prsec.dynamic.results import (
    REPLAY_REQUEST, REPLAY_RESULT, SINK_HTTP, Canaries, OracleResult, ReplayRequest, ReplayResult, StepRecord,
)
from prsec.dynamic.template import TemplateContext, TemplateError, render, render_str

EXCERPT_BYTES = 4096
MAX_REDIRECTS = 5
HTTP_TIMEOUT = httpx.Timeout(30.0, connect=10.0)
COMMAND_TIMEOUT_S = 60
MAX_SINK_HITS = 50
ANON = "_anonymous"


class StepError(RuntimeError):
    """A step could not be sent or its expectations failed: the run is aborted (fired=false)."""


def sink_url_default() -> str:
    return os.environ.get("PRSEC_SINK_URL", SINK_HTTP)


def fetch_sink_hits(contains: str, sink_url: str | None = None) -> list[dict[str, Any]]:
    """Requests the sink recorded whose host/path/headers/body contain `contains`."""
    r = httpx.get(f"{sink_url or sink_url_default()}/__prsec/hits", params={"contains": contains},
                  timeout=10.0, trust_env=False)
    r.raise_for_status()
    hits = r.json().get("hits", [])
    return hits if isinstance(hits, list) else []


# ------------------------------------------------------------------ helpers


def json_path(doc: Any, path: str) -> Any:
    """Dotted path with list indexes ('items.0.id'); '' or '$' is the document itself."""
    node = doc
    for part in [p for p in path.split(".") if p not in ("", "$")]:
        if isinstance(node, list) and re.fullmatch(r"-?\d+", part):
            node = node[int(part)]
        elif isinstance(node, dict) and part in node:
            node = node[part]
        else:
            raise KeyError(f"path {path!r}: no {part!r}")
    return node


def as_text(value: Any) -> str:
    return value if isinstance(value, str) else json.dumps(value)


def resolve_url(path: str, base_url: str) -> str:
    """Relative paths go to the app; absolute URLs only to canary hosts (they land at the sink)."""
    parts = urlsplit(path)
    if not parts.scheme and not parts.netloc:
        return base_url.rstrip("/") + "/" + path.lstrip("/")
    host = (parts.hostname or "").lower()
    if parts.scheme not in ("http", "https") or not host.endswith(".canary.invalid"):
        raise StepError(f"absolute URL {path!r} not allowed: use a path on the app or a canary URL")
    return path


def _number(v: Any) -> float | None:
    if isinstance(v, bool) or v is None:
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


_OPS = {
    "eq": lambda a, b: a == b, "ne": lambda a, b: a != b, "lt": lambda a, b: a < b,
    "le": lambda a, b: a <= b, "gt": lambda a, b: a > b, "ge": lambda a, b: a >= b,
}


def compare(actual: Any, op: str, expected: Any) -> bool:
    """Numbers compare numerically (also when one side is a numeric string); otherwise as-is."""
    a, b = _number(actual), _number(expected)
    if a is not None and b is not None:
        return _OPS[op](a, b)
    try:
        return _OPS[op](actual, expected)
    except TypeError:
        return False


def _excerpt(resp: httpx.Response) -> str:
    return resp.content[:EXCERPT_BYTES].decode(errors="replace")


# ------------------------------------------------------------------ engine


@dataclass
class Session:
    client: httpx.Client
    headers: dict[str, str] = field(default_factory=dict)  # unrendered user headers


class PocEngine:
    """Runs PoC steps/scripts against a running app and evaluates oracles."""

    def __init__(self, users: dict[str, User], base_url: str, canaries: Canaries | None, workdir: Path,
                 env: dict[str, str] | None = None, sink_url: str | None = None,
                 deadline: float | None = None) -> None:
        self.users = users
        self.workdir = workdir
        self.env = env if env is not None else dict(os.environ)
        self.sink_url = sink_url
        self.deadline = deadline
        self.ctx = TemplateContext(base_url=base_url, canaries=canaries)
        self.sessions: dict[str, Session] = {}
        self.responses: dict[str, httpx.Response] = {}
        self.records: list[StepRecord] = []
        for name, user in users.items():
            self.ctx.users[name] = {k: render_str(v, self.ctx) for k, v in user.vars.items()}

    # ---------------------------------------------------------------- sessions

    def session(self, user: str | None) -> Session:
        key = user or ANON
        if key not in self.sessions:
            client = httpx.Client(timeout=HTTP_TIMEOUT, follow_redirects=True, max_redirects=MAX_REDIRECTS,
                                  trust_env=False)
            headers = dict(self.users[user].headers) if user in self.users else {}
            self.sessions[key] = Session(client=client, headers=headers)
        return self.sessions[key]

    def close(self) -> None:
        for s in self.sessions.values():
            s.client.close()

    def _remaining(self, default: float) -> float:
        if self.deadline is None:
            return default
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise StepError("replay timed out")
        return min(default, left)

    # ---------------------------------------------------------------- steps

    @staticmethod
    def _user_headers(session: Session, ctx: TemplateContext, login: bool) -> dict[str, str]:
        """The user's headers; during login, ones that need a var not extracted yet are left out."""
        out = {}
        for k, v in session.headers.items():
            try:
                out[k] = render_str(v, ctx)
            except TemplateError:
                if not login:
                    raise
        return out

    def _request_kwargs(self, step: Step, ctx: TemplateContext, session: Session, login: bool) -> dict[str, Any]:
        headers = {**self._user_headers(session, ctx, login), **render(step.headers, ctx)}
        kwargs: dict[str, Any] = {"headers": headers, "params": render(step.query, ctx) or None}
        if step.json_body is not None:
            kwargs["json"] = render(step.json_body, ctx)
        elif step.form is not None:
            kwargs["data"] = render(step.form, ctx)
        elif step.body is not None:
            kwargs["content"] = render_str(step.body, ctx).encode()
        return kwargs

    def execute(self, step: Step, user: str | None = None, login: bool = False) -> httpx.Response:
        """Send one step as `user` (default: the step's own user). Raises StepError (recorded) on failure."""
        user = user if user is not None else step.as_user
        record = StepRecord(name=step.name, user=user, method=step.method.upper(), url=step.path)
        self.records.append(record)
        try:
            resp = self._send(step, user, record, login)
        except StepError as e:
            record.error = str(e)
            raise
        self.responses[step.name] = resp
        self._check_status(step, resp)
        self._extract(step, user, resp)
        return resp

    def _send(self, step: Step, user: str | None, record: StepRecord, login: bool) -> httpx.Response:
        ctx = self.ctx.for_user(user)
        session = self.session(user)
        try:
            url = resolve_url(render_str(step.path, ctx), self.ctx.base_url)
            record.url = url
            kwargs = self._request_kwargs(step, ctx, session, login)
        except TemplateError as e:
            raise StepError(f"template: {e}") from None
        try:
            resp = session.client.request(step.method.upper(), url, timeout=self._remaining(30.0), **kwargs)
        except httpx.HTTPError as e:
            raise StepError(f"request failed: {type(e).__name__}: {e}") from None
        record.status = resp.status_code
        record.response_excerpt = _excerpt(resp)
        return resp

    def _check_status(self, step: Step, resp: httpx.Response) -> None:
        if step.expect_status is not None and resp.status_code not in step.expect_status:
            msg = f"expected status {step.expect_status}, got {resp.status_code}"
            self.records[-1].error = msg
            raise StepError(msg)

    def _extract(self, step: Step, user: str | None, resp: httpx.Response) -> None:
        for var, ex in step.extract.items():
            try:
                value = self._extract_one(ex, resp)
            except (KeyError, IndexError, ValueError, re.error) as e:
                msg = f"extract {var}: {e}"
                self.records[-1].error = msg
                raise StepError(msg) from None
            self.ctx.vars[var] = value
            if user is not None:
                self.ctx.users.setdefault(user, {})[var] = value

    @staticmethod
    def _extract_one(ex: Any, resp: httpx.Response) -> str:
        if ex.json_path is not None:
            return as_text(json_path(resp.json(), ex.json_path))
        if ex.header is not None:
            if ex.header not in resp.headers:
                raise KeyError(f"no header {ex.header!r}")
            return resp.headers[ex.header]
        m = re.search(ex.regex, resp.text)
        if m is None:
            raise ValueError(f"regex {ex.regex!r} did not match")
        return m.group(1) if m.re.groups else m.group(0)

    def login(self, user: str) -> None:
        for step in self.users[user].login:
            self.execute(step, user, login=True)

    def run_http(self, steps: list[Step]) -> None:
        """Every user's login, then the steps. Raises StepError on the first failure."""
        for user in self.users:
            self.login(user)
        for step in steps:
            self.execute(step)

    def run_script(self, script: str) -> None:
        record = StepRecord(name=SCRIPT_STEP, method="SCRIPT", url=str(self.workdir))
        self.records.append(record)
        try:
            rendered = render_str(script, self.ctx)
        except TemplateError as e:
            record.error = f"template: {e}"
            raise StepError(record.error) from None
        try:
            proc = subprocess.run(["bash", "-c", rendered], cwd=self.workdir, env=self.env, capture_output=True,
                                  stdin=subprocess.DEVNULL, timeout=self._remaining(600.0))
        except subprocess.TimeoutExpired:
            record.error = "script timed out"
            raise StepError(record.error) from None
        record.status = proc.returncode
        record.response_excerpt = (proc.stdout + proc.stderr)[:EXCERPT_BYTES].decode(errors="replace")
        self.responses[SCRIPT_STEP] = httpx.Response(200 if proc.returncode == 0 else 500, content=proc.stdout)

    # ---------------------------------------------------------------- oracles

    def evaluate(self, oracles: list[Oracle]) -> list[OracleResult]:
        results = []
        for i, oracle in enumerate(oracles):
            try:
                passed, detail = self._evaluate_one(oracle)
            except TemplateError as e:
                passed, detail = False, f"template: {e}"
            except Exception as e:  # an oracle that cannot be evaluated simply does not pass
                passed, detail = False, f"{type(e).__name__}: {e}"
            results.append(OracleResult(index=i, type=oracle.type, passed=passed, detail=detail[:1000]))
        return results

    def _evaluate_one(self, oracle: Oracle) -> tuple[bool, str]:
        if isinstance(oracle, ResponseContains):
            return self._response_contains(oracle)
        if isinstance(oracle, ResponseStatus):
            return self._response_status(oracle)
        if isinstance(oracle, JsonCompare):
            return self._json_compare(oracle)
        if isinstance(oracle, CanaryHit):
            return self._canary_hit(oracle)
        return self._command(oracle)

    def _response(self, step: str) -> httpx.Response:
        if step not in self.responses:
            raise LookupError(f"step {step!r} has no response (did not run)")
        return self.responses[step]

    def _response_contains(self, o: ResponseContains) -> tuple[bool, str]:
        value = render_str(o.value, self.ctx)
        found = value in self._response(o.step).text
        verb = "found" if found else "not found"
        return found != o.negate, f"{value!r} {verb} in response of {o.step}"

    def _response_status(self, o: ResponseStatus) -> tuple[bool, str]:
        status = self._response(o.step).status_code
        return status in o.status, f"{o.step} returned {status}"

    def _json_compare(self, o: JsonCompare) -> tuple[bool, str]:
        actual = json_path(self._response(o.step).json(), o.path)
        expected = render_str(o.value, self.ctx) if isinstance(o.value, str) else o.value
        return compare(actual, o.op, expected), f"{o.path} = {actual!r} {o.op} {expected!r}"

    def _canary_hit(self, o: CanaryHit) -> tuple[bool, str]:
        value = render_str(o.value, self.ctx)
        hits = fetch_sink_hits(value, self.sink_url)
        return bool(hits), f"{len(hits)} sink hit(s) containing {value!r}"

    def _command(self, o: Command) -> tuple[bool, str]:
        cmd, expect = render_str(o.run, self.ctx), render_str(o.expect, self.ctx)
        proc = subprocess.run(["bash", "-c", cmd], cwd=self.workdir, env=self.env, capture_output=True,
                              stdin=subprocess.DEVNULL, timeout=COMMAND_TIMEOUT_S)
        out = proc.stdout.decode(errors="replace")
        found = expect in out
        verb = "found" if found else "not found"
        return found != o.negate, f"exit {proc.returncode}; {expect!r} {verb} in stdout"


def fired(poc: PoC, results: list[OracleResult]) -> bool:
    if not results:
        return False
    passed = [r.passed for r in results]
    return all(passed) if poc.fires_when == "all" else any(passed)


@dataclass
class PocRun:
    fired: bool
    oracle_results: list[OracleResult]
    steps: list[StepRecord]
    aborted: str | None = None


def run_poc(poc: PoC, engine: PocEngine) -> PocRun:
    """Steps (or script), then oracles. An aborted run (failed step/expect_status) never fires."""
    aborted = None
    try:
        if poc.kind == "script":
            engine.run_script(poc.script or "")
        else:
            engine.run_http(poc.steps)
    except StepError as e:
        aborted = str(e)
    results = engine.evaluate(poc.oracles)
    return PocRun(fired=aborted is None and fired(poc, results), oracle_results=results,
                  steps=list(engine.records), aborted=aborted)


# ------------------------------------------------------------------ replay


def _sink_hits(token: str, sink_url: str | None) -> list[dict[str, Any]]:
    try:
        return fetch_sink_hits(token, sink_url)[:MAX_SINK_HITS]
    except (httpx.HTTPError, ValueError):
        return []


def run_replay(req: ReplayRequest, app_root: Path | None = None, src: Path | None = None,
               sink_url: str | None = None, proxy: str | None = "auto") -> ReplayResult:
    """Fresh canaries, app up, run the PoC, evaluate oracles. Never raises."""
    started = time.monotonic()
    runner = AppRunner(req.envspec, app_root=app_root, src=src, proxy=proxy)
    canaries = new_canaries(runner.app_root)
    result = ReplayResult(run_id=req.run_id, env_ok=False, entry=req.poc.kind, canaries=canaries)
    try:
        runner.up(canaries)
        result.env_ok = True
        _replay_poc(req, runner, canaries, sink_url, started, result)
    except EnvError as e:
        result.env_error = str(e)[:4000]
    except Exception as e:  # never raise out of a replay
        result.steps.append(StepRecord(name="replay", method="-", url="", error=f"{type(e).__name__}: {e}"))
    finally:
        result.app_log_tail = runner.logs(200)
        _safe_stop(runner)
        result.duration_s = round(time.monotonic() - started, 3)
    return result


def _replay_poc(req: ReplayRequest, runner: AppRunner, canaries: Canaries, sink_url: str | None,
                started: float, result: ReplayResult) -> None:
    engine = PocEngine(req.poc.users, runner.base_url, canaries, runner.workdir, env=runner.app_env(),
                       sink_url=sink_url, deadline=started + req.timeout_s)
    try:
        run = run_poc(req.poc, engine)
    finally:
        engine.close()
    result.fired = run.fired
    result.oracle_results = run.oracle_results
    result.steps = run.steps
    result.sink_hits = _sink_hits(canaries.token, sink_url)


def _safe_stop(runner: AppRunner) -> None:
    try:
        runner.stop()
    except Exception:  # noqa: BLE001 - best effort teardown
        pass


def _load_request(path: Path) -> ReplayRequest:
    return ReplayRequest.model_validate_json(path.read_text())


def _run_id_of(path: Path) -> str:
    try:
        return str(json.loads(path.read_text()).get("run_id") or "unknown")
    except (OSError, ValueError, AttributeError):
        return "unknown"


def _write(out: Path, model: BaseModel) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(model.model_dump_json(indent=2))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="prsec-replay", description="Replay a PoC against a fresh app (agent-free).")
    ap.add_argument("request", nargs="?", type=Path, default=Path(REPLAY_REQUEST))
    ap.add_argument("--out", type=Path, default=Path(os.environ.get("PRSEC_REPLAY_RESULT", REPLAY_RESULT)))
    args = ap.parse_args(argv)
    try:
        req = _load_request(args.request)
    except (OSError, ValueError) as e:
        result = ReplayResult(run_id=_run_id_of(args.request), env_ok=False,
                              env_error=f"invalid replay request: {e}"[:4000])
    else:
        result = run_replay(req, sink_url=sink_url_default())
    try:
        _write(args.out, result)
    except OSError as e:
        print(f"prsec-replay: cannot write {args.out}: {e}", file=sys.stderr)
        return 2
    print(f"prsec-replay: env_ok={result.env_ok} fired={result.fired} -> {args.out}")
    return 0

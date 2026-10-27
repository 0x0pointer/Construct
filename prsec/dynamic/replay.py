"""Agent-free PoC interpreter: `prsec-replay /work/in/replay.json` -> /work/out/replay_result.json.

The same `PocEngine` backs `prsec-poc run` and `prsec-http`, so what the agent sees while authoring
a PoC is exactly what the replay evaluates. The replay itself never raises: an app that does not come
up is reported as env_ok=false with env_error.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote_plus, urlsplit

import httpx
from pydantic import BaseModel

from prsec.dynamic.app import AppRunner, EnvError, new_canaries
from prsec.dynamic.poc import (
    SCRIPT_STEP, CanaryHit, Command, JsonCompare, Oracle, PoC, ResponseContains, ResponseHeader, ResponseRegex,
    ResponseStatus, Step, User,
)
from prsec.dynamic.results import (
    REPLAY_REQUEST, REPLAY_RESULT, SINK_HTTP, Canaries, OracleResult, ReplayRequest, ReplayResult, StepRecord,
)
from prsec.dynamic.template import TemplateContext, TemplateError, render, render_str

EXCERPT_BYTES = 4096
HTTP_TIMEOUT = httpx.Timeout(30.0, connect=10.0)
COMMAND_TIMEOUT_S = 60
MAX_SINK_HITS = 50
ANON = "_anonymous"


class StepError(RuntimeError):
    """A step could not be sent or its expectations failed: the run is aborted (fired=false).

    `clean`: the app answered, just not as the PoC expects (expect_status, extract). Otherwise
    (transport error, timeout, template) the run says nothing about the bug."""

    def __init__(self, msg: str, clean: bool = False) -> None:
        super().__init__(msg)
        self.clean = clean


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


def resolve_url(path: str, base_url: str, services: Iterable[str] = ()) -> str:
    """A relative path goes to the app. An absolute URL may only name one of the EnvSpec's services
    (oauth2 mock, mailpit, ...). Anything else, canary hosts included, is refused: a request the PoC
    client sends itself would land at the sink and satisfy canary_hit."""
    parts = urlsplit(path)
    if not (parts.scheme or parts.netloc):
        return base_url.rstrip("/") + "/" + path.lstrip("/")
    host = (parts.hostname or "").lower()
    if parts.scheme in ("http", "https") and host in set(services) and not (parts.username or parts.password):
        return path
    raise StepError(f"absolute URL {path!r} not allowed: steps take a path on the app or a service URL")


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
    """Numbers compare numerically (also when one side is a numeric string); otherwise as-is.

    A missing (null) actual value never passes, and a numeric expected value needs a finite
    numeric actual value: `ne 5` must not fire on `null`, "invalid" or NaN."""
    if actual is None:
        return False
    a, b = _number(actual), _number(expected)
    if b is not None and (a is None or not math.isfinite(a)):
        return False
    if a is not None and b is not None:
        return _OPS[op](a, b)
    try:
        return _OPS[op](actual, expected)
    except TypeError:
        return False


def header_matches(values: list[str], op: str, value: str) -> bool:
    """`present`/`absent` look at the header itself; the rest pass if one of its values matches."""
    if op == "present":
        return bool(values)
    if op == "absent":
        return not values
    tests: dict[str, Callable[[str], bool]] = {
        "equals": lambda v: v.strip() == value,
        "contains": lambda v: value in v,
        "starts_with": lambda v: v.strip().startswith(value),
        "regex": lambda v: re.search(value, v) is not None,
    }
    return any(tests[op](v) for v in values)


def _sent_text(url: str, kwargs: dict[str, Any]) -> str:
    """Everything a step sends, as text, so an oracle can tell a server-built value from an echo."""
    dump = lambda v: json.dumps(v, ensure_ascii=False)  # noqa: E731
    parts = [unquote_plus(url), dump(kwargs.get("headers") or {}), dump(kwargs.get("params") or {})]
    for key in ("json", "data"):
        if kwargs.get(key) is not None:
            parts.append(dump(kwargs[key]))
    if kwargs.get("content") is not None:
        parts.append(kwargs["content"].decode(errors="replace"))
    return "\n".join(parts)


def _echo_proves_nothing(value: str, sent: str) -> bool:
    """The value is in the step's own request. Markup (`<>&"'`) is exempt: an unescaped reflection of
    it is the proof of a reflected XSS, and escaping would have changed it."""
    return value in sent and not any(c in value for c in "<>&\"'")


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
                 deadline: float | None = None, services: Iterable[str] = ()) -> None:
        self.users = users
        self.services = frozenset(s.lower() for s in services)
        self.workdir = workdir
        self.env = env if env is not None else dict(os.environ)
        self.sink_url = sink_url
        self.deadline = deadline
        self.ctx = TemplateContext(base_url=base_url, canaries=canaries)
        self.sessions: dict[str, Session] = {}
        self.responses: dict[str, httpx.Response] = {}
        self.all_responses: dict[str, list[httpx.Response]] = {}  # every response of a parallel step
        self.sent: dict[str, str] = {}  # step -> its rendered request (url, headers, body): echo check
        self.records: list[StepRecord] = []
        for name, user in users.items():
            self.ctx.users[name] = {k: render_str(v, self.ctx) for k, v in user.vars.items()}

    # ---------------------------------------------------------------- sessions

    def session(self, user: str | None) -> Session:
        key = user or ANON
        if key not in self.sessions:
            # Redirects are not followed: the client must not make the sink request an open redirect
            # points at, and a 302 to /login must not turn into the login page's 200.
            client = httpx.Client(timeout=HTTP_TIMEOUT, follow_redirects=False, trust_env=False)
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
        if step.parallel > 1:
            return self._execute_parallel(step, user, login)
        record = StepRecord(name=step.name, user=user, method=step.method.upper(), url=step.path)
        self.records.append(record)
        try:
            resp = self._send(step, user, record, login)
        except StepError as e:
            record.error = str(e)
            raise
        self.responses[step.name] = resp
        self.all_responses[step.name] = [resp]
        self._check_status(step, resp)
        self._extract(step, user, resp)
        return resp

    def _execute_parallel(self, step: Step, user: str | None, login: bool) -> httpx.Response:
        """`step.parallel` copies released together by a barrier (race conditions). All must get a
        response; expect_status must hold for each."""
        n = step.parallel
        records = [StepRecord(name=f"{step.name}#{i + 1}", user=user, method=step.method.upper(), url=step.path)
                   for i in range(n)]
        self.records.extend(records)
        self.session(user)  # created once here, not concurrently by the threads
        barrier = threading.Barrier(n, timeout=30)

        def one(record: StepRecord) -> httpx.Response:
            return self._send(step, user, record, login, before_send=barrier.wait)

        with ThreadPoolExecutor(max_workers=n) as pool:
            futures = [pool.submit(one, r) for r in records]
        responses, errors = [], []
        for record, fut in zip(records, futures):
            try:
                responses.append(fut.result())
            except (StepError, threading.BrokenBarrierError) as e:
                record.error = record.error or str(e)
                errors.append(str(e))
        if errors:
            raise StepError(f"{len(errors)}/{n} parallel requests failed: {errors[0]}")
        self.responses[step.name] = responses[-1]
        self.all_responses[step.name] = responses
        for resp in responses:
            self._check_status(step, resp)
        return responses[-1]

    def _send(self, step: Step, user: str | None, record: StepRecord, login: bool,
              before_send: Callable[[], object] | None = None) -> httpx.Response:
        ctx = self.ctx.for_user(user)
        session = self.session(user)
        try:
            url = resolve_url(render_str(step.path, ctx), self.ctx.base_url, self.services)
            record.url = url
            kwargs = self._request_kwargs(step, ctx, session, login)
        except TemplateError as e:
            raise StepError(f"template: {e}") from None
        self.sent[step.name] = _sent_text(url, kwargs)
        if before_send is not None:
            before_send()
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
            self._record_error(step.name, msg)
            raise StepError(msg, clean=True)

    def _extract(self, step: Step, user: str | None, resp: httpx.Response) -> None:
        for var, ex in step.extract.items():
            try:
                value = self._extract_one(ex, resp)
            except (KeyError, IndexError, ValueError, re.error) as e:
                msg = f"extract {var}: {e}"
                self._record_error(step.name, msg)
                raise StepError(msg, clean=True) from None
            self.ctx.vars[var] = value
            if user is not None:
                self.ctx.users.setdefault(user, {})[var] = value

    def _record_error(self, step: str, msg: str) -> None:
        for record in reversed(self.records):
            if record.name == step or record.name.startswith(f"{step}#"):
                record.error = record.error or msg
                return

    @staticmethod
    def _extract_one(ex: Any, resp: httpx.Response) -> str:
        """The extracted value; a missing, null or empty one aborts the run (it would match anything)."""
        if ex.json_path is not None:
            raw = json_path(resp.json(), ex.json_path)
            value = None if raw is None else as_text(raw)
        elif ex.header is not None:
            if ex.header not in resp.headers:
                raise KeyError(f"no header {ex.header!r}")
            value = resp.headers[ex.header]
        else:
            m = re.search(ex.regex, resp.text)
            if m is None:
                raise ValueError(f"regex {ex.regex!r} did not match")
            value = m.group(1) if m.re.groups else m.group(0)
        if value is None or not value.strip():
            raise ValueError("extracted value is empty or null")
        return value

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
        self.all_responses[SCRIPT_STEP] = [self.responses[SCRIPT_STEP]]

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
        if isinstance(oracle, ResponseHeader):
            return self._response_header(oracle)
        if isinstance(oracle, ResponseRegex):
            return self._response_regex(oracle)
        if isinstance(oracle, JsonCompare):
            return self._json_compare(oracle)
        if isinstance(oracle, CanaryHit):
            return self._canary_hit(oracle)
        return self._command(oracle)

    def _responses(self, step: str) -> list[httpx.Response]:
        if step not in self.all_responses:
            raise LookupError(f"step {step!r} has no response (did not run)")
        return self.all_responses[step]

    def _over(self, step: str, check: Callable[[httpx.Response], tuple[bool, str]], every: bool = False) -> tuple[bool, str]:
        """Apply `check` to each response of the step (one, or N for a parallel step): passes if any does,
        or if every one does when `every` (negated checks: "none of the responses shows it")."""
        results = [check(r) for r in self._responses(step)]
        passed = [ok for ok, _ in results]
        ok = all(passed) if every else any(passed)
        detail = next((d for p, d in results if p == ok), results[0][1])
        if len(results) > 1:
            detail = f"{sum(passed)}/{len(results)} responses: {detail}"
        return ok, detail

    def _response_contains(self, o: ResponseContains) -> tuple[bool, str]:
        value = render_str(o.value, self.ctx)
        if not value.strip():
            return False, "empty value: every response contains it"
        if not o.negate and _echo_proves_nothing(value, self.sent.get(o.step, "")):
            return False, f"{value!r} is in the request of {o.step} itself (an echo proves nothing)"

        def check(resp: httpx.Response) -> tuple[bool, str]:
            found = value in resp.text
            return found != o.negate, f"{value!r} {'found' if found else 'not found'} in response of {o.step}"

        return self._over(o.step, check, every=o.negate)

    def _response_status(self, o: ResponseStatus) -> tuple[bool, str]:
        return self._over(o.step, lambda r: (r.status_code in o.status, f"{o.step} returned {r.status_code}"))

    def _response_header(self, o: ResponseHeader) -> tuple[bool, str]:
        value = render_str(o.value, self.ctx) if o.value is not None else None
        if o.op not in ("present", "absent") and not (value or "").strip():
            return False, "empty value: every header contains it"

        def check(resp: httpx.Response) -> tuple[bool, str]:
            values = resp.headers.get_list(o.name)
            return header_matches(values, o.op, value or ""), f"{o.name}: {values!r} {o.op} {value!r}"

        return self._over(o.step, check, every=o.op == "absent")

    def _response_regex(self, o: ResponseRegex) -> tuple[bool, str]:
        sent = self.sent.get(o.step, "")

        def check(resp: httpx.Response) -> tuple[bool, str]:
            hit = next((m.group(0) for m in re.finditer(o.pattern, resp.text)
                        if m.group(0).strip() and not _echo_proves_nothing(m.group(0), sent)), None)
            found = hit is not None
            return found != o.negate, f"/{o.pattern}/ {'matched ' + repr(hit[:200]) if found else 'no match'} in {o.step}"

        return self._over(o.step, check, every=o.negate)

    def _json_compare(self, o: JsonCompare) -> tuple[bool, str]:
        expected = render_str(o.value, self.ctx) if isinstance(o.value, str) else o.value

        def check(resp: httpx.Response) -> tuple[bool, str]:
            actual = json_path(resp.json(), o.path)
            return compare(actual, o.op, expected), f"{o.path} = {actual!r} {o.op} {expected!r}"

        return self._over(o.step, check)

    def _canary_hit(self, o: CanaryHit) -> tuple[bool, str]:
        value = render_str(o.value, self.ctx)
        if not value.strip():
            return False, "empty value: every sink record contains it"
        hits = fetch_sink_hits(value, self.sink_url)
        return bool(hits), f"{len(hits)} sink hit(s) containing {value!r}"

    def _command(self, o: Command) -> tuple[bool, str]:
        cmd, expect = render_str(o.run, self.ctx), render_str(o.expect, self.ctx)
        if not expect.strip():
            return False, "empty expect: every output contains it"
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
    incomplete: bool = False  # aborted for a reason that says nothing about the bug (see StepError)


def run_poc(poc: PoC, engine: PocEngine) -> PocRun:
    """Steps (or script), then oracles. An aborted run (failed step/expect_status) never fires."""
    aborted, incomplete = None, False
    try:
        if poc.kind == "script":
            engine.run_script(poc.script or "")
        else:
            engine.run_http(poc.steps)
    except StepError as e:
        aborted, incomplete = str(e), not e.clean
    except Exception as e:  # keep the steps that ran; the run itself is just not evidence
        aborted, incomplete = f"{type(e).__name__}: {e}", True
        if engine.records:
            engine.records[-1].error = engine.records[-1].error or aborted
    results = engine.evaluate(poc.oracles)
    return PocRun(fired=aborted is None and fired(poc, results), oracle_results=results,
                  steps=list(engine.records), aborted=aborted, incomplete=incomplete)


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
        _replay_poc(req, runner, canaries, sink_url, result)
    except EnvError as e:
        result.env_error = str(e)[:4000]
    except Exception as e:  # never raise out of a replay
        result.aborted, result.incomplete = f"{type(e).__name__}: {e}"[:4000], True
        result.steps.append(StepRecord(name="replay", method="-", url="", error=result.aborted))
    finally:
        result.app_log_tail = runner.logs(200)
        _safe_stop(runner)
        result.duration_s = round(time.monotonic() - started, 3)
    return result


def _replay_poc(req: ReplayRequest, runner: AppRunner, canaries: Canaries, sink_url: str | None,
                result: ReplayResult) -> None:
    """The PoC's own deadline starts once the app is up: install and health have their own (EnvSpec)."""
    engine = PocEngine(req.poc.users, runner.base_url, canaries, runner.workdir, env=runner.app_env(),
                       sink_url=sink_url, deadline=time.monotonic() + req.timeout_s,
                       services=[s.name for s in req.envspec.services])
    try:
        run = run_poc(req.poc, engine)
    finally:
        engine.close()
    result.fired = run.fired
    result.aborted, result.incomplete = run.aborted, run.incomplete
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

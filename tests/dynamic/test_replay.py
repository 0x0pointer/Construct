import json
from pathlib import Path
from typing import Any

import pytest

from prsec.dynamic.poc import PoC
from prsec.dynamic.replay import StepError, compare, json_path, main, resolve_url, run_replay
from prsec.dynamic.results import ReplayRequest, ReplayResult

from .fixtures.workbench import SinkStub, Workbench, sink, workbench  # noqa: F401 - pytest fixtures

LOGIN = {"name": "{user}_login", "method": "POST", "path": "/login",
         "form": {"username": "${USER.username}", "password": "${USER.password}"},
         "expect_status": [200], "extract": {"token": {"json": "token"}}}


def user(name: str, **extra: Any) -> dict[str, Any]:
    login = json.loads(json.dumps(LOGIN).replace("{user}", name))
    return {"vars": {"username": name, "password": f"{name}-pw"}, "login": [login], **extra}


def poc(**kw: Any) -> PoC:
    doc: dict[str, Any] = {"kind": "http", "hypothesis_id": "h1", "description": "test"}
    doc.update(kw)
    return PoC.model_validate(doc)


def replay(wb: Workbench, p: PoC, sink_url: str = "http://127.0.0.1:9", **spec: Any) -> ReplayResult:
    req = ReplayRequest(run_id="r1", envspec=wb.spec(**spec), poc=p, timeout_s=60)
    return run_replay(req, app_root=wb.app_root, src=wb.src, sink_url=sink_url, proxy=None)


IDOR = poc(
    users={"alice": user("alice"), "bob": user("bob")},
    steps=[{"name": "read_other", "as": "alice", "path": "/api/notes/${USERS.bob.note}",
            "extract": {"owner": {"json": "owner"}}}],
    oracles=[{"type": "response_contains", "step": "read_other", "value": "bob-secret-note"},
             {"type": "response_status", "step": "read_other", "status": [200]},
             {"type": "json_compare", "step": "read_other", "path": "owner", "op": "eq", "value": "bob"}],
)
IDOR.users["bob"].vars["note"] = "2"


def test_http_poc_fires(workbench: Workbench) -> None:  # noqa: F811
    result = replay(workbench, IDOR)
    assert result.env_ok
    assert result.fired
    assert result.entry == "http"
    assert [r.passed for r in result.oracle_results] == [True, True, True]
    assert [s.name for s in result.steps] == ["alice_login", "bob_login", "read_other"]
    assert "bob-secret-note" in result.steps[-1].response_excerpt
    assert result.canaries is not None
    assert result.duration_s > 0
    assert not (workbench.app_root / ".prsec" / "app.pid").exists()  # app stopped afterwards


def test_http_poc_that_does_not_fire(workbench: Workbench) -> None:  # noqa: F811
    p = poc(users={"alice": user("alice")},
            steps=[{"name": "own", "as": "alice", "path": "/api/notes/1"}],
            oracles=[{"type": "response_contains", "step": "own", "value": "bob-secret-note"}])
    result = replay(workbench, p)
    assert result.env_ok
    assert not result.fired
    assert "not found" in result.oracle_results[0].detail


def test_expect_status_aborts_run(workbench: Workbench) -> None:  # noqa: F811
    p = poc(steps=[{"name": "me", "path": "/api/me", "expect_status": [200]},
                   {"name": "never", "path": "/health"}],
            oracles=[{"type": "response_status", "step": "me", "status": [401]}])
    result = replay(workbench, p)
    assert not result.fired
    assert result.oracle_results[0].passed  # evaluated for diagnostics, but an aborted run never fires
    assert "expected status" in (result.steps[0].error or "")
    assert len(result.steps) == 1


def test_bearer_header_and_json_compare_invariant(workbench: Workbench) -> None:  # noqa: F811
    alice = user("alice", headers={"Authorization": "Bearer ${USER.token}"})
    alice["login"][0]["extract"] = {"token": {"header": "X-Session"}}
    p = poc(users={"alice": alice},
            steps=[{"name": "withdraw", "as": "alice", "method": "POST", "path": "/api/withdraw",
                    "json": {"amount": 150}}],
            oracles=[{"type": "json_compare", "step": "withdraw", "path": "balance", "op": "lt", "value": 0}])
    result = replay(workbench, p)
    assert result.fired


def test_extract_regex_list_index_and_global_vars(workbench: Workbench) -> None:  # noqa: F811
    alice = user("alice")
    alice["login"][0]["extract"] = {"token": {"regex": r'"token": "([^"]+)"'}, "second": {"json": "user.ids.1"}}
    p = poc(users={"alice": alice},
            steps=[{"name": "note", "path": "/api/notes/${VARS.second}",
                    "headers": {"Cookie": "session=${USERS.alice.token}"}}],
            oracles=[{"type": "response_contains", "step": "note", "value": "bob-secret-note"}])
    assert replay(workbench, p).fired


def test_failed_extract_aborts(workbench: Workbench) -> None:  # noqa: F811
    p = poc(steps=[{"name": "h", "path": "/health", "extract": {"x": {"json": "missing.path"}}}],
            oracles=[{"type": "response_status", "step": "h", "status": [200]}])
    result = replay(workbench, p)
    assert not result.fired
    assert "extract x" in (result.steps[0].error or "")


def test_sentinel_file_read_and_fires_when_any(workbench: Workbench) -> None:  # noqa: F811
    p = poc(steps=[{"name": "read", "path": "/file", "query": {"name": "${CANARY.file}"}}],
            oracles=[{"type": "response_contains", "step": "read", "value": "${CANARY.file_content}"},
                     {"type": "response_status", "step": "read", "status": [500]}],
            fires_when="any")
    result = replay(workbench, p)
    assert result.fired
    assert [r.passed for r in result.oracle_results] == [True, False]


def test_reflected_marker_negate(workbench: Workbench) -> None:  # noqa: F811
    p = poc(steps=[{"name": "s", "path": "/search", "query": {"q": "<b>${CANARY.token}</b>"}}],
            oracles=[{"type": "response_contains", "step": "s", "value": "<b>${CANARY.token}</b>"},
                     {"type": "response_contains", "step": "s", "value": "&lt;b&gt;", "negate": True}])
    assert replay(workbench, p).fired


def test_canary_hit_via_sink(workbench: Workbench, sink: SinkStub) -> None:  # noqa: F811
    p = poc(steps=[{"name": "ssrf", "path": "/fetch", "query": {"url": f"{sink.url}/cb/${{CANARY.token}}"}}],
            oracles=[{"type": "canary_hit"}])
    result = replay(workbench, p, sink_url=sink.url)
    assert result.fired
    assert len(result.sink_hits) == 1
    assert result.canaries is not None
    assert result.canaries.token in str(result.sink_hits[0]["path"])


def test_canary_hit_without_hits_does_not_fire(workbench: Workbench, sink: SinkStub) -> None:  # noqa: F811
    p = poc(steps=[{"name": "h", "path": "/health"}], oracles=[{"type": "canary_hit"}])
    result = replay(workbench, p, sink_url=sink.url)
    assert not result.fired
    assert result.oracle_results[0].detail.startswith("0 sink hit(s)")


def test_unreachable_sink_does_not_fire(workbench: Workbench) -> None:  # noqa: F811
    p = poc(steps=[{"name": "h", "path": "/health"}], oracles=[{"type": "canary_hit"}])
    result = replay(workbench, p, sink_url="http://127.0.0.1:9")
    assert not result.oracle_results[0].passed


def test_script_poc_with_command_oracle(workbench: Workbench) -> None:  # noqa: F811
    p = PoC.model_validate({
        "kind": "script", "hypothesis_id": "h1", "description": "direct call",
        "script": "echo ${CANARY.token} > proof.txt; echo ran $APP_MODE",
        "oracles": [{"type": "command", "run": "cat proof.txt", "expect": "${CANARY.token}"},
                    {"type": "command", "run": "ls", "expect": "proof.txt"}]})
    result = replay(workbench, p, env={"APP_MODE": "replay"})
    assert result.fired
    assert result.entry == "script"
    assert result.steps[0].status == 0
    assert "ran replay" in result.steps[0].response_excerpt


def test_script_poc_oracles_read_the_script_step(workbench: Workbench) -> None:  # noqa: F811
    p = PoC.model_validate({
        "kind": "script", "hypothesis_id": "h1", "description": "direct call",
        "script": "echo prsec-${CANARY.token}",
        "oracles": [{"type": "response_contains", "step": "script", "value": "prsec-${CANARY.token}"},
                    {"type": "response_status", "step": "script", "status": [200]}]})
    result = replay(workbench, p)
    assert result.fired


def test_http_poc_oracle_cannot_read_a_script_step() -> None:
    with pytest.raises(ValueError, match="unknown step 'script'"):
        poc(steps=[{"name": "h", "path": "/health"}],
            oracles=[{"type": "response_status", "step": "script", "status": [200]}])


def test_command_oracle_negate(workbench: Workbench) -> None:  # noqa: F811
    p = PoC.model_validate({
        "kind": "script", "hypothesis_id": "h1", "description": "d", "script": "true",
        "oracles": [{"type": "command", "run": "echo clean", "expect": "dirty", "negate": True}]})
    assert replay(workbench, p).fired


def test_template_error_aborts(workbench: Workbench) -> None:  # noqa: F811
    p = poc(steps=[{"name": "h", "path": "/notes/${VARS.never_set}"}],
            oracles=[{"type": "response_status", "step": "h", "status": [404]}])
    result = replay(workbench, p)
    assert not result.fired
    assert "unknown var" in (result.steps[0].error or "")
    assert "did not run" in result.oracle_results[0].detail


def test_absolute_url_to_non_canary_host_is_refused(workbench: Workbench) -> None:  # noqa: F811
    p = poc(steps=[{"name": "out", "path": "http://example.com/x"}],
            oracles=[{"type": "response_status", "step": "out", "status": [200]}])
    result = replay(workbench, p)
    assert not result.fired
    assert "not allowed" in (result.steps[0].error or "")


def test_redirects_are_not_followed(workbench: Workbench) -> None:  # noqa: F811
    p = poc(steps=[{"name": "go", "path": "/go", "query": {"to": "/health"}}],
            oracles=[{"type": "response_status", "step": "go", "status": [200]}])
    result = replay(workbench, p)
    assert not result.fired
    assert result.steps[0].status == 302


def test_canary_url_step_cannot_fire_canary_hit(workbench: Workbench, sink: SinkStub) -> None:  # noqa: F811
    p = poc(steps=[{"name": "self", "path": "${CANARY.url}"}], oracles=[{"type": "canary_hit"}])
    result = replay(workbench, p, sink_url=sink.url)
    assert not result.fired
    assert "not allowed" in (result.steps[0].error or "")


def test_whitespace_needle_never_passes(workbench: Workbench) -> None:  # noqa: F811
    p = poc(steps=[{"name": "h", "path": "/health"}],
            oracles=[{"type": "response_contains", "step": "h", "value": " "}])
    result = replay(workbench, p)
    assert not result.fired
    assert "empty" in result.oracle_results[0].detail


def test_value_echoed_from_the_request_does_not_pass(workbench: Workbench) -> None:  # noqa: F811
    p = poc(steps=[{"name": "s", "path": "/search", "query": {"q": "id-${CANARY.token}"}}],
            oracles=[{"type": "response_contains", "step": "s", "value": "id-${CANARY.token}"}])
    result = replay(workbench, p)
    assert not result.fired
    assert "request" in result.oracle_results[0].detail


def test_empty_extracted_value_aborts(workbench: Workbench) -> None:  # noqa: F811
    p = poc(steps=[{"name": "s", "path": "/search", "extract": {"x": {"regex": "results for (\\w*)<"}}},
                   {"name": "h", "path": "/health"}],
            oracles=[{"type": "response_contains", "step": "h", "value": "${VARS.x}"}])
    result = replay(workbench, p)
    assert not result.fired
    assert "empty" in (result.steps[0].error or "")


def test_unmatched_optional_group_aborts_and_keeps_steps(workbench: Workbench) -> None:  # noqa: F811
    p = poc(steps=[{"name": "h", "path": "/health"},
                   {"name": "s", "path": "/search", "extract": {"x": {"regex": "results for (zzz)?"}}}],
            oracles=[{"type": "response_status", "step": "h", "status": [200]}])
    result = replay(workbench, p)
    assert not result.fired
    assert [s.name for s in result.steps] == ["h", "s"]


@pytest.mark.parametrize("doc", [{"x": None}, {"x": ""}, {"x": "  "}])
def test_null_or_empty_json_extract_is_refused(doc: dict[str, Any]) -> None:
    import httpx

    from prsec.dynamic.poc import Extract
    from prsec.dynamic.replay import PocEngine
    extract, resp = Extract(json="x"), httpx.Response(200, json=doc)
    with pytest.raises(ValueError, match="empty or null"):
        PocEngine._extract_one(extract, resp)


def test_env_failure_is_reported(workbench: Workbench) -> None:  # noqa: F811
    p = poc(steps=[{"name": "h", "path": "/health"}],
            oracles=[{"type": "response_status", "step": "h", "status": [200]}])
    result = replay(workbench, p, start="echo cannot-start >&2; exit 1")
    assert not result.env_ok
    assert "exited before it became healthy" in (result.env_error or "")
    assert "cannot-start" in result.app_log_tail
    assert not result.fired


def test_main_writes_result(workbench: Workbench, tmp_path: Path,  # noqa: F811
                            monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PRSEC_APP_DIR", str(workbench.app_root))
    monkeypatch.setenv("PRSEC_SRC_DIR", str(workbench.src))
    monkeypatch.setenv("PRSEC_SINK_URL", "http://127.0.0.1:9")
    monkeypatch.setattr("prsec.dynamic.app.detect_proxy", lambda: None)
    req = ReplayRequest(run_id="run-7", envspec=workbench.spec(), poc=IDOR)
    (tmp_path / "replay.json").write_text(req.model_dump_json(by_alias=True))
    out = tmp_path / "out" / "replay_result.json"
    assert main([str(tmp_path / "replay.json"), "--out", str(out)]) == 0
    result = ReplayResult.model_validate_json(out.read_text())
    assert result.run_id == "run-7"
    assert result.fired


def test_main_never_raises_on_bad_request(tmp_path: Path) -> None:
    (tmp_path / "replay.json").write_text(json.dumps({"run_id": "bad-1", "poc": {}}))
    out = tmp_path / "result.json"
    assert main([str(tmp_path / "replay.json"), "--out", str(out)]) == 0
    result = ReplayResult.model_validate_json(out.read_text())
    assert result.run_id == "bad-1"
    assert not result.env_ok
    assert "invalid replay request" in (result.env_error or "")


def test_main_missing_request_file(tmp_path: Path) -> None:
    out = tmp_path / "result.json"
    assert main([str(tmp_path / "missing.json"), "--out", str(out)]) == 0
    assert ReplayResult.model_validate_json(out.read_text()).run_id == "unknown"


# ------------------------------------------------------------------ units


@pytest.mark.parametrize(("path", "expected"), [
    ("a.b", 1), ("items.1.id", "y"), ("items.-1.id", "y"), ("", {"a": {"b": 1}, "items": [{"id": "x"}, {"id": "y"}]}),
])
def test_json_path(path: str, expected: Any) -> None:
    doc = {"a": {"b": 1}, "items": [{"id": "x"}, {"id": "y"}]}
    assert json_path(doc, path) == expected


def test_json_path_missing() -> None:
    with pytest.raises(KeyError):
        json_path({"a": [1]}, "a.x")


@pytest.mark.parametrize(("actual", "op", "expected", "result"), [
    (-5, "lt", 0, True), ("10", "gt", 9, True), (3, "eq", "3", True), ("abc", "eq", "abc", True),
    ("abc", "ne", "abd", True), (True, "eq", True, True), ("x", "lt", 3, False), (None, "eq", None, False),
    (None, "ne", 5, False), ("invalid", "ne", 5, False), ("nan", "ne", 5, False), ("inf", "gt", 5, False),
    (2, "ge", 2.0, True), (2, "le", 1, False),
])
def test_compare(actual: Any, op: str, expected: Any, result: bool) -> None:
    assert compare(actual, op, expected) is result


def test_resolve_url() -> None:
    assert resolve_url("api/x?y=1", "http://127.0.0.1:8000") == "http://127.0.0.1:8000/api/x?y=1"


@pytest.mark.parametrize("url", ["http://127.0.0.1:22/", "file:///etc/hosts", "//evil.example/x",
                                 "http://canary.invalid.example.com/", "http://abc.canary.invalid/abc",
                                 "https://abc.canary.invalid/"])
def test_resolve_url_refuses_other_hosts(url: str) -> None:
    with pytest.raises(StepError):
        resolve_url(url, "http://127.0.0.1:8000")


# ------------------------------------------------------------------ PoC validation


def test_login_step_names_must_be_unique_across_users() -> None:
    users = {"alice": user("x"), "bob": user("x")}
    with pytest.raises(ValueError, match="unique"):
        poc(users=users, steps=[{"name": "s", "path": "/"}],
            oracles=[{"type": "response_status", "step": "s", "status": [200]}])


def test_main_step_may_not_reuse_a_login_step_name() -> None:
    users = {"alice": user("alice")}
    with pytest.raises(ValueError, match="unique"):
        poc(users=users, steps=[{"name": "alice_login", "path": "/"}],
            oracles=[{"type": "response_status", "step": "alice_login", "status": [200]}])


def test_script_step_name_is_reserved() -> None:
    with pytest.raises(ValueError, match="reserved"):
        poc(steps=[{"name": "script", "path": "/"}],
            oracles=[{"type": "response_status", "step": "script", "status": [200]}])


@pytest.mark.parametrize("oracle", [
    {"type": "response_contains", "step": "s", "value": ""},
    {"type": "canary_hit", "value": ""},
    {"type": "command", "run": "true", "expect": ""},
])
def test_empty_oracle_values_are_invalid(oracle: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        poc(steps=[{"name": "s", "path": "/"}], oracles=[oracle])

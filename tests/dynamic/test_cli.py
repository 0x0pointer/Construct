import json
from pathlib import Path

import pytest
import yaml

from prsec.sandbox.cli import canary, env, http
from prsec.sandbox.cli import poc as poccli

from .fixtures.workbench import SinkStub, Workbench, sink, workbench  # noqa: F401 - pytest fixtures

POC = {
    "kind": "http", "hypothesis_id": "h1", "description": "alice reads bob's note",
    "users": {"alice": {"vars": {"username": "alice", "password": "alice-pw"},
                        "login": [{"name": "login", "method": "POST", "path": "/login",
                                   "form": {"username": "${USER.username}", "password": "${USER.password}"},
                                   "expect_status": [200]}]}},
    "steps": [{"name": "idor", "as": "alice", "path": "/api/notes/2"}],
    "oracles": [{"type": "response_contains", "step": "idor", "value": "bob-secret-note"}],
}


@pytest.fixture
def cli(workbench: Workbench, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Workbench:  # noqa: F811
    """Points the CLIs at the fixture app (spec file, app/src dirs, no proxy, unreachable sink)."""
    spec = tmp_path / "envspec.json"
    spec.write_text(workbench.spec().model_dump_json())
    monkeypatch.setenv("PRSEC_ENVSPEC", str(spec))
    monkeypatch.setenv("PRSEC_APP_DIR", str(workbench.app_root))
    monkeypatch.setenv("PRSEC_SRC_DIR", str(workbench.src))
    monkeypatch.setenv("PRSEC_SINK_URL", "http://127.0.0.1:9")
    monkeypatch.setattr("prsec.dynamic.app.detect_proxy", lambda: None)
    return workbench


@pytest.fixture
def running(cli: Workbench) -> Workbench:
    assert env.main(["up"]) == 0
    return cli


def write(path: Path, doc: object) -> Path:
    path.write_text(yaml.safe_dump(doc))
    return path


# ------------------------------------------------------------------ prsec-env


def test_env_up_status_logs_down(running: Workbench, capsys: pytest.CaptureFixture[str]) -> None:
    capsys.readouterr()
    assert env.main(["status"]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["healthy"]
    assert env.main(["logs", "-n", "5"]) == 0
    assert "GET /health" in capsys.readouterr().out
    assert env.main(["down"]) == 0
    env.main(["status"])
    assert not json.loads(capsys.readouterr().out.splitlines()[-1])["running"]


def test_env_reset(running: Workbench) -> None:
    marker = running.app_root / "src" / "dirty.txt"
    marker.write_text("x")
    assert env.main(["reset"]) == 0
    assert not marker.exists()


def test_env_up_failure_exit_1(cli: Workbench, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(cli.spec(start="exit 4").model_dump_json())
    assert env.main(["up", "--spec", str(bad)]) == 1
    assert "exited before it became healthy" in capsys.readouterr().err


def test_env_invalid_spec(cli: Workbench, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bad = write(tmp_path / "bad.yaml", {"stack": "cobol", "start": "x"})
    assert env.main(["status", "--spec", str(bad)]) == 2
    err = capsys.readouterr().err
    assert "stack:" in err
    assert "port:" in err


def test_env_missing_spec(cli: Workbench, tmp_path: Path) -> None:
    assert env.main(["status", "--spec", str(tmp_path / "nope.json")]) == 2


def test_load_envspec_accepts_env_output(tmp_path: Path) -> None:
    f = write(tmp_path / "out.yaml", {"envspec": {"stack": "node", "start": "npm start", "port": 3000}, "notes": ""})
    assert env.load_envspec(f).port == 3000


# ------------------------------------------------------------------ prsec-http


def test_http_as_user_logs_in_once_and_keeps_cookies(running: Workbench, tmp_path: Path,
                                                     capsys: pytest.CaptureFixture[str]) -> None:
    pocfile = write(tmp_path / "poc.yaml", POC)
    capsys.readouterr()
    assert http.main(["--user", "alice", "--poc", str(pocfile), "GET", "/api/me"]) == 0
    first = capsys.readouterr()
    assert first.out.startswith("HTTP 200")
    assert '"user": "alice"' in first.out
    assert "logged in as alice" in first.err
    assert http.main(["--user", "alice", "GET", "/api/notes/2"]) == 0
    second = capsys.readouterr()
    assert "bob-secret-note" in second.out
    assert "logged in" not in second.err
    assert (running.app_root / ".prsec" / "users" / "alice.json").exists()


def test_http_anonymous_with_json_and_headers(running: Workbench, capsys: pytest.CaptureFixture[str]) -> None:
    capsys.readouterr()
    assert http.main(["POST", "/login", "--json", '{"username": "bob", "password": "bob-pw"}',
                      "-H", "X-Test: 1"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("HTTP 200")
    assert "set-cookie: session=tok-bob" in out.lower()


def test_http_form_and_placeholders(running: Workbench, capsys: pytest.CaptureFixture[str]) -> None:
    capsys.readouterr()
    assert http.main(["GET", "/search?q=${CANARY.token}"]) == 0
    out = capsys.readouterr().out
    canaries = json.loads((running.app_root / ".prsec" / "canaries.json").read_text())
    assert canaries["token"] in out
    assert http.main(["POST", "/login", "--form", "username=bob", "--form", "password=wrong"]) == 0
    assert capsys.readouterr().out.startswith("HTTP 403")


def test_http_connection_failure(cli: Workbench, capsys: pytest.CaptureFixture[str]) -> None:
    assert http.main(["GET", "/health"]) == 1
    assert "request failed" in capsys.readouterr().err


def test_http_bad_arguments(cli: Workbench) -> None:
    assert http.main(["POST", "/x", "--json", "{not json"]) == 2
    assert http.main(["GET", "/x", "-H", "no-colon"]) == 2


# ------------------------------------------------------------------ prsec-poc


def test_poc_validate_ok(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert poccli.main(["validate", str(write(tmp_path / "poc.yaml", POC))]) == 0
    assert capsys.readouterr().out.startswith("ok: http PoC")


def test_poc_validate_json_file(tmp_path: Path) -> None:
    f = tmp_path / "poc.json"
    f.write_text(json.dumps(POC))
    assert poccli.main(["validate", str(f)]) == 0


def test_poc_validate_errors_are_readable(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bad = dict(POC, oracles=[{"type": "response_contains", "step": "nope", "value": "x"}], kind="ftp")
    assert poccli.main(["validate", str(write(tmp_path / "poc.yaml", bad))]) == 1
    assert "kind:" in capsys.readouterr().out


def test_poc_validate_unparsable(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    f = tmp_path / "poc.yaml"
    f.write_text("kind: [unclosed")
    assert poccli.main(["validate", str(f)]) == 1
    assert "cannot parse" in capsys.readouterr().out


def test_poc_run_fired(running: Workbench, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    capsys.readouterr()
    assert poccli.main(["run", str(write(tmp_path / "poc.yaml", POC))]) == 0
    out = capsys.readouterr().out
    assert "oracle 0 response_contains: PASS" in out
    assert out.rstrip().endswith("FIRED")


def test_poc_run_not_fired_json(running: Workbench, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    doc = dict(POC, oracles=[{"type": "response_contains", "step": "idor", "value": "alice-secret-note"}])
    capsys.readouterr()
    assert poccli.main(["run", "--json", str(write(tmp_path / "poc.yaml", doc))]) == 1
    assert json.loads(capsys.readouterr().out)["fired"] is False


def test_poc_run_invalid(cli: Workbench, tmp_path: Path) -> None:
    assert poccli.main(["run", str(write(tmp_path / "poc.yaml", {"kind": "http"}))]) == 2


# ------------------------------------------------------------------ prsec-canary


def test_canary_new_rotates(cli: Workbench, capsys: pytest.CaptureFixture[str]) -> None:
    assert canary.main(["show"]) == 0
    first = json.loads(capsys.readouterr().out)
    assert canary.main(["new"]) == 0
    second = json.loads(capsys.readouterr().out)
    assert second["token"] != first["token"]
    assert Path(second["file"]).read_text().strip() == second["file_content"]


def test_canary_hits(cli: Workbench, sink: SinkStub, monkeypatch: pytest.MonkeyPatch,  # noqa: F811
                     capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setenv("PRSEC_SINK_URL", sink.url)
    canary.main(["show"])
    token = json.loads(capsys.readouterr().out)["token"]
    sink.records.append({"host": f"{token}.canary.invalid", "path": "/x"})
    sink.records.append({"host": "other", "path": "/marker-42"})
    assert canary.main(["hits"]) == 0
    assert json.loads(capsys.readouterr().out)["count"] == 1
    assert canary.main(["hits", "--contains", "marker-42"]) == 0
    assert json.loads(capsys.readouterr().out)["hits"][0]["host"] == "other"


def test_canary_hits_sink_down(cli: Workbench, capsys: pytest.CaptureFixture[str]) -> None:
    assert canary.main(["hits"]) == 1
    assert "sink query failed" in capsys.readouterr().err

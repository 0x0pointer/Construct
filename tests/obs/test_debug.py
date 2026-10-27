import json
import sys
from pathlib import Path

import httpx
import pytest

SANDBOX_TESTS = Path(__file__).parent.parent / "sandbox"
sys.path.insert(0, str(SANDBOX_TESTS))

from fakeharness import make_task  # noqa: E402  (registers the fake adapters)

from prsec.obs import debug  # noqa: E402


@pytest.fixture
def work(tmp_path, monkeypatch):
    """A scan work dir as the pipeline leaves it: <root>/src, <root>/in/<task_id>/task.json (container paths)."""
    make_task(tmp_path)  # src/, in/diff.patch, skills/ on the host
    task = make_task(tmp_path, container_paths=True)
    in_dir = tmp_path / "in" / task.task_id
    in_dir.mkdir(parents=True)
    (in_dir / "diff.patch").write_text((tmp_path / "in" / "diff.patch").read_text())
    (in_dir / "task.json").write_text(task.model_dump_json(indent=2))
    monkeypatch.setenv("FAKE_MODE", "valid")
    monkeypatch.setenv("PRSEC_ADAPTER_MODULES", "fakeharness")
    monkeypatch.setenv("PYTHONPATH", str(SANDBOX_TESTS))
    monkeypatch.setenv("PRSEC_GATEWAY_URL", "http://gw.invalid:4000")
    monkeypatch.setenv("PRSEC_GATEWAY_KEY", "sk-x")
    return tmp_path, in_dir / "task.json"


def test_parse_rerun_stage():
    a = debug.build_parser().parse_args(["rerun-stage", "t/task.json", "--src", "s", "--in", "i",
                                         "--harness", "codex", "--model", "agent-small", "--out", "o"])
    assert (a.cmd, a.task, a.src, a.in_dir, a.harness, a.model, a.out) == (
        "rerun-stage", "t/task.json", "s", "i", "codex", "agent-small", "o")
    assert a.gateway is False


def test_parse_scan():
    a = debug.build_parser().parse_args(["scan", "acme/shop", "7", "a" * 40, "--keep", "30", "--token", "t"])
    assert (a.repo, a.pr, a.head_sha, a.keep, a.token) == ("acme/shop", 7, "a" * 40, 30, "t")
    assert a.api == debug.DEFAULT_API


def test_parse_requires_subcommand():
    with pytest.raises(SystemExit):
        debug.build_parser().parse_args([])


def test_rerun_stage_with_fake_harness(work, capsys):
    root, task_json = work
    out = root / "dbg"
    code = debug.main(["rerun-stage", str(task_json), "--skills", str(root / "skills"), "--out", str(out)])
    printed = capsys.readouterr().out
    assert code == 0, printed
    assert "status:     ok" in printed
    assert "dev mode" in printed
    assert json.loads((out / "out" / "triage.json").read_text())["decision"] == "light"
    assert (out / "in" / "diff.patch").exists()
    assert f"result:     {out / 'out' / 'result.json'}" in printed
    # the original task.json is untouched (still container paths)
    assert json.loads(task_json.read_text())["workdir"] == "/work/src"


def test_rerun_stage_defaults_src_to_work_dir(work):
    root, task_json = work
    args = debug.build_parser().parse_args(["rerun-stage", str(task_json), "--harness", "fake2", "--model", "m"])
    spec = debug.prepare_spec(args)
    assert spec.src_dir == root / "src"
    assert spec.out_dir.parent.parent == root / "debug"
    assert spec.task.harness == "fake2"
    assert spec.task.model_alias == "m"


def test_dev_runner_drops_gateway_env(work):
    root, task_json = work
    spec = debug.prepare_spec(debug.build_parser().parse_args(["rerun-stage", str(task_json), "--out", str(root / "d")]))
    assert "PRSEC_GATEWAY_URL" not in debug.DevRunner()._env(spec)
    assert debug.DevRunner(keep_gateway=True)._env(spec)["PRSEC_GATEWAY_URL"] == "http://gw.invalid:4000"


def test_rerun_stage_missing_task(tmp_path, capsys):
    assert debug.main(["rerun-stage", str(tmp_path / "nope" / "task.json")]) == 2


def _mock(seen, status=202, body=None):
    def handler(request):
        seen.append(request)
        return httpx.Response(status, json=body if body is not None else {"scan_id": 77})

    return httpx.MockTransport(handler)


def test_scan_posts_debug_request(capsys):
    seen = []
    args = debug.build_parser().parse_args(["scan", "acme/shop", "7", "a" * 40, "--keep", "15",
                                            "--api", "http://api:8080/", "--token", "tok"])
    assert debug.trigger_scan(args, transport=_mock(seen)) == 0
    req = seen[0]
    assert str(req.url) == "http://api:8080/scans"
    assert req.headers["x-prsec-admin"] == "tok"
    assert json.loads(req.content) == {"repo": "acme/shop", "pr": 7, "head_sha": "a" * 40,
                                       "debug": {"log_level": "debug", "keep_minutes": 15}}
    assert "prsec-trace 77 --follow" in capsys.readouterr().out


def test_scan_reports_api_errors(capsys):
    args = debug.build_parser().parse_args(["scan", "acme/shop", "7", "a" * 40, "--token", "bad"])
    assert debug.trigger_scan(args, transport=_mock([], status=403, body={"detail": "forbidden"})) == 1
    assert "403" in capsys.readouterr().err


def test_scan_duplicate_is_not_queued():
    args = debug.build_parser().parse_args(["scan", "acme/shop", "7", "a" * 40, "--token", "t"])
    assert debug.trigger_scan(args, transport=_mock([], status=200, body={"ignored": "duplicate"})) == 1


def test_scan_needs_token(monkeypatch):
    monkeypatch.delenv("PRSEC_ADMIN_TOKEN", raising=False)
    assert debug.main(["scan", "acme/shop", "7", "a" * 40]) == 2


def test_scan_keep_bounds():
    assert debug.main(["scan", "acme/shop", "7", "a" * 40, "--keep", "5000", "--token", "t"]) == 2

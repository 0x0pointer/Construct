import json
import subprocess
import sys
from pathlib import Path

from fakeharness import make_task

from prsec.models import Event, StageResult, StageStatus
from prsec.sandbox.entrypoint import main as entry


def _write_task(task, tmp_path) -> Path:
    p = tmp_path / "task.json"
    p.write_text(task.model_dump_json())
    return p


def test_main_writes_result_and_transcript(tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_MODE", "valid")
    monkeypatch.setenv("PRSEC_GATEWAY_URL", "http://gw:4000")
    monkeypatch.setenv("PRSEC_GATEWAY_KEY", "sk-1")
    monkeypatch.delenv("PRSEC_GATEWAY_MODEL", raising=False)
    task = make_task(tmp_path)
    assert entry.main([str(_write_task(task, tmp_path))]) == 0

    res = StageResult.model_validate_json((Path(task.out_dir) / "result.json").read_text())
    assert res.status == StageStatus.ok
    assert res.model == "agent-small"
    lines = (Path(task.out_dir) / "transcript.jsonl").read_text().splitlines()
    assert len(lines) == len(res.transcript) > 0
    Event.model_validate_json(lines[0])


def test_gateway_from_env(monkeypatch, tmp_path):
    task = make_task(tmp_path)
    monkeypatch.delenv("PRSEC_GATEWAY_URL", raising=False)
    assert entry.gateway_from_env(task) is None
    monkeypatch.setenv("PRSEC_GATEWAY_URL", "http://gw:4000")
    monkeypatch.setenv("PRSEC_GATEWAY_KEY", "sk-1")
    monkeypatch.setenv("PRSEC_GATEWAY_MODEL", "judge")
    gw = entry.gateway_from_env(task)
    assert (gw.base_url, gw.api_key, gw.model) == ("http://gw:4000", "sk-1", "judge")


def test_unknown_harness_gives_harness_error_result(tmp_path):
    task = make_task(tmp_path, harness="does-not-exist")
    assert entry.main([str(_write_task(task, tmp_path))]) == 0
    res = json.loads((Path(task.out_dir) / "result.json").read_text())
    assert res["status"] == "harness_error"
    assert "does-not-exist" in res["errors"][0]


def test_bad_task_file(tmp_path):
    p = tmp_path / "task.json"
    p.write_text("{}")
    assert entry.main([str(p)]) == 2
    assert entry.main([]) == 2


def test_module_entrypoint_with_extra_adapter_module(tmp_path):
    task = make_task(tmp_path)
    env = {"FAKE_MODE": "valid", "PRSEC_ADAPTER_MODULES": "fakeharness",
           "PYTHONPATH": str(Path(__file__).parent), "PATH": "/usr/bin:/bin"}
    proc = subprocess.run([sys.executable, "-m", "prsec.sandbox.entrypoint.main", str(_write_task(task, tmp_path))],
                          env=env, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert json.loads((Path(task.out_dir) / "result.json").read_text())["status"] == "ok"


def test_task_file_must_be_an_existing_task_json(tmp_path):
    other = tmp_path / "secrets.json"
    other.write_text("{}")
    assert entry.main([str(other)]) == 2
    assert entry.main([str(tmp_path / "task.json")]) == 2  # missing
    (tmp_path / "dir").mkdir()
    (tmp_path / "dir" / "task.json").mkdir()
    assert entry.main([str(tmp_path / "dir" / "task.json")]) == 2  # not a regular file
    p = tmp_path / "task.json"
    p.write_text("{}")
    assert entry.task_file(str(tmp_path / "dir" / ".." / "task.json")) == p.resolve()

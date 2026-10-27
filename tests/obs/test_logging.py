"""prsec.obs.logging: JSON/text shape, bound context, thread propagation, per-scan debug gate."""
from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor

import pytest

from prsec.obs import logging as obslog

log = logging.getLogger("prsec.test.obs")


@pytest.fixture(autouse=True)
def _restore_root():
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    yield
    for h in list(root.handlers):
        if h not in handlers:
            root.removeHandler(h)
    root.setLevel(level)


def _setup(monkeypatch, fmt: str = "json", level: str = "INFO", service: str = "worker") -> None:
    monkeypatch.setenv("PRSEC_LOG_FORMAT", fmt)
    monkeypatch.setenv("PRSEC_LOG_LEVEL", level)
    obslog.setup_logging(service)


def _lines(capsys) -> list[str]:
    return [line for line in capsys.readouterr().err.splitlines() if line.strip()]


def _json_lines(capsys) -> list[dict]:
    return [json.loads(line) for line in _lines(capsys)]


def test_json_shape(monkeypatch, capsys) -> None:
    _setup(monkeypatch)
    log.info("hello %s", "world")
    (rec,) = _json_lines(capsys)
    assert list(rec)[:5] == ["ts", "level", "service", "logger", "msg"]
    assert rec["msg"] == "hello world"
    assert rec["level"] == "INFO"
    assert rec["service"] == "worker"
    assert rec["logger"] == "prsec.test.obs"
    assert rec["ts"].endswith("Z")
    assert "exc" not in rec


def test_json_exception(monkeypatch, capsys) -> None:
    _setup(monkeypatch)
    try:
        raise ValueError("boom")
    except ValueError:
        log.exception("failed")
    (rec,) = _json_lines(capsys)
    assert rec["level"] == "ERROR"
    assert "ValueError: boom" in rec["exc"]


def test_bound_fields_appear(monkeypatch, capsys) -> None:
    _setup(monkeypatch)
    with obslog.bind(scan_id=12, task_id="t-1", stage="triage", hypothesis_id="h1", env="e1"):
        log.info("inside")
    rec = _json_lines(capsys)[0]
    assert rec["scan_id"] == 12
    assert rec["task_id"] == "t-1"
    assert rec["stage"] == "triage"
    assert rec["hypothesis_id"] == "h1"
    assert rec["env"] == "e1"


def test_bound_field_cannot_override_core_keys(monkeypatch, capsys) -> None:
    _setup(monkeypatch)
    with obslog.bind(msg="spoof", level="spoof"):
        log.info("real")
    rec = _json_lines(capsys)[0]
    assert rec["msg"] == "real"
    assert rec["level"] == "INFO"


def test_nested_bind_restores() -> None:
    with obslog.bind(scan_id=1, stage="triage"):
        with obslog.bind(stage="hunt", task_id="t"):
            inner = obslog.get_context()
        outer = obslog.get_context()
    after = obslog.get_context()
    assert inner == {"scan_id": 1, "stage": "hunt", "task_id": "t"}
    assert outer == {"scan_id": 1, "stage": "triage"}
    assert after == {}


def test_bind_none_removes_field() -> None:
    with obslog.bind(scan_id=1, stage="triage"):
        with obslog.bind(stage=None):
            ctx = obslog.get_context()
    assert ctx == {"scan_id": 1}


def test_bind_restores_after_exception() -> None:
    with pytest.raises(RuntimeError):
        with obslog.bind(scan_id=5):
            raise RuntimeError
    assert obslog.get_context() == {}


def test_get_context_returns_copy() -> None:
    with obslog.bind(scan_id=1):
        obslog.get_context()["scan_id"] = 99
        ctx = obslog.get_context()
    assert ctx == {"scan_id": 1}


def test_submit_with_context_propagates_to_thread(monkeypatch, capsys) -> None:
    _setup(monkeypatch)

    def work(x: int) -> dict:
        log.info("in thread %s", x)
        return obslog.get_context()

    with ThreadPoolExecutor(max_workers=1) as pool:
        with obslog.bind(scan_id=7, stage="validate"):
            fut = obslog.submit_with_context(pool, work, 3)
        ctx = fut.result(timeout=5)
        plain = pool.submit(obslog.get_context).result(timeout=5)
    assert ctx == {"scan_id": 7, "stage": "validate"}
    assert plain == {}
    rec = _json_lines(capsys)[0]
    assert rec["scan_id"] == 7
    assert rec["msg"] == "in thread 3"


def test_debug_dropped_at_info_level(monkeypatch, capsys) -> None:
    _setup(monkeypatch, level="INFO")
    log.debug("hidden")
    assert _lines(capsys) == []


def test_debug_context_passes_debug_at_info_level(monkeypatch, capsys) -> None:
    _setup(monkeypatch, level="INFO")
    with obslog.bind(scan_id=3, debug=True):
        log.debug("visible")
    log.debug("hidden again")
    recs = _json_lines(capsys)
    assert len(recs) == 1
    assert recs[0]["msg"] == "visible"
    assert recs[0]["level"] == "DEBUG"
    assert recs[0]["debug"] is True


def test_debug_false_does_not_pass(monkeypatch, capsys) -> None:
    _setup(monkeypatch, level="INFO")
    with obslog.bind(debug=False):
        log.debug("hidden")
    assert _lines(capsys) == []


def test_global_debug_level(monkeypatch, capsys) -> None:
    _setup(monkeypatch, level="debug")
    log.debug("shown")
    assert len(_lines(capsys)) == 1


def test_warning_level_drops_info(monkeypatch, capsys) -> None:
    _setup(monkeypatch, level="WARNING")
    log.info("hidden")
    log.warning("shown")
    recs = _json_lines(capsys)
    assert [r["msg"] for r in recs] == ["shown"]


def test_invalid_level_defaults_to_info(monkeypatch, capsys) -> None:
    _setup(monkeypatch, level="bogus")
    log.debug("hidden")
    log.info("shown")
    assert len(_lines(capsys)) == 1


def test_quiet_third_party_stays_at_info_in_debug_scan(monkeypatch, capsys) -> None:
    _setup(monkeypatch, level="INFO")
    with obslog.bind(debug=True):
        logging.getLogger("urllib3.connectionpool").debug("wire noise")
    assert _lines(capsys) == []


def test_text_format_readable(monkeypatch, capsys) -> None:
    _setup(monkeypatch, fmt="text", service="launcher")
    with obslog.bind(scan_id=4, stage="hunt"):
        log.warning("something %d", 1)
    (line,) = _lines(capsys)
    assert " WARNING launcher " in line
    assert "prsec.test.obs [scan_id=4 stage=hunt] something 1" in line
    assert not line.startswith("{")


def test_text_format_without_context(monkeypatch, capsys) -> None:
    _setup(monkeypatch, fmt="text")
    log.info("plain")
    (line,) = _lines(capsys)
    assert line.endswith("prsec.test.obs plain")


def test_default_format_is_text(monkeypatch, capsys) -> None:
    monkeypatch.delenv("PRSEC_LOG_FORMAT", raising=False)
    monkeypatch.delenv("PRSEC_LOG_LEVEL", raising=False)
    obslog.setup_logging("api")
    log.info("x")
    (line,) = _lines(capsys)
    assert not line.startswith("{")
    assert " INFO api " in line


def test_setup_is_idempotent(monkeypatch, capsys) -> None:
    _setup(monkeypatch)
    _setup(monkeypatch, service="worker2")
    log.info("once")
    recs = _json_lines(capsys)
    assert len(recs) == 1
    assert recs[0]["service"] == "worker2"


def test_uvicorn_loggers_use_root_handler(monkeypatch, capsys) -> None:
    logging.getLogger("uvicorn.error").addHandler(logging.NullHandler())
    logging.getLogger("uvicorn.access").propagate = False
    _setup(monkeypatch, service="launcher")
    logging.getLogger("uvicorn.access").info("GET /healthz 200")
    logging.getLogger("uvicorn.error").info("started")
    recs = _json_lines(capsys)
    assert [r["logger"] for r in recs] == ["uvicorn.access", "uvicorn.error"]
    assert logging.getLogger("uvicorn.error").handlers == []


def test_child_log_env_is_debug_in_a_debug_scan(monkeypatch) -> None:
    monkeypatch.setenv("PRSEC_LOG_LEVEL", "INFO")
    with obslog.bind(scan_id=1, debug=True):
        assert obslog.child_log_env() == {"PRSEC_LOG_LEVEL": "DEBUG"}


def test_child_log_env_passes_the_process_level(monkeypatch) -> None:
    monkeypatch.setenv("PRSEC_LOG_LEVEL", "WARNING")
    assert obslog.child_log_env() == {"PRSEC_LOG_LEVEL": "WARNING"}


def test_child_log_env_empty_without_a_level(monkeypatch) -> None:
    monkeypatch.delenv("PRSEC_LOG_LEVEL", raising=False)
    assert obslog.child_log_env() == {}

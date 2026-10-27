"""prsec.obs.events: emit never raises, list_events in order (db), backoff when the database is down."""
import logging

import pytest

from db_queue.conftest import dsn, sql  # noqa: F401  (fixtures: a fresh migrated schema per test)
from prsec.obs import events
from prsec.obs.logging import bind


@pytest.fixture(autouse=True)
def fresh_backoff():
    events.reset_backoff()
    yield
    events.reset_backoff()


# ------------------------------------------------------------------ no database


@pytest.fixture
def rows(monkeypatch):
    out: list[dict] = []
    monkeypatch.setattr(events, "_insert", out.append)
    return out


def test_emit_builds_the_row(rows):
    events.emit(3, "triage", "triage: full", stage="triage", data={"decision": "full"})
    assert rows == [{"scan_id": 3, "kind": "triage", "level": "info", "stage": "triage", "task_id": None,
                     "hypothesis_id": None, "message": "triage: full", "data": {"decision": "full"}}]


def test_emit_takes_unset_fields_from_the_bound_context(rows):
    with bind(scan_id=3, stage="static_verify", task_id="3-static_verify-H1", hypothesis_id="H1"):
        events.emit(3, "static_verdict", "H1: plausible", stage="skeptic")
    assert rows[0]["stage"] == "skeptic"
    assert rows[0]["task_id"] == "3-static_verify-H1"
    assert rows[0]["hypothesis_id"] == "H1"


def test_emit_truncates_and_sanitises(rows):
    class Odd:
        def __str__(self):
            return "odd"

    events.emit(3, "agent", "x" * 5000, data={"obj": Odd()})
    assert len(rows[0]["message"]) == events.MESSAGE_MAX
    assert rows[0]["data"] == {"obj": "odd"}


def test_oversized_data_is_previewed(rows):
    events.emit(3, "agent", "big", data={"blob": "y" * (events.DATA_MAX + 10)})
    assert rows[0]["data"]["truncated"] is True
    assert len(rows[0]["data"]["preview"]) == 4000


def test_unknown_kind_and_level_are_coerced(rows):
    events.emit(3, "nonsense", "hello", level="loud")
    assert rows[0]["kind"] == "error"
    assert rows[0]["level"] == "info"
    assert rows[0]["message"] == "[unknown kind 'nonsense'] hello"


def test_emit_logs_the_line(rows, caplog):
    with caplog.at_level(logging.INFO, logger="prsec.events"):
        events.emit(3, "label", "H1 labelled likely: reason", level="warning")
    assert caplog.records[0].getMessage() == "[label] H1 labelled likely: reason"
    assert caplog.records[0].levelno == logging.WARNING


def test_emit_never_raises_and_backs_off(monkeypatch):
    calls = []

    def broken(row):
        calls.append(row)
        raise RuntimeError("db down")

    monkeypatch.setattr(events, "_insert", broken)
    events.emit(3, "scan_started", "one")
    events.emit(3, "scan_finished", "two")  # inside the backoff: not attempted
    assert len(calls) == 1
    events.reset_backoff()
    events.emit(3, "scan_finished", "three")
    assert len(calls) == 2


def test_emit_survives_unserialisable_scan_id(rows):
    events.emit("not-an-int", "error", "x")  # type: ignore[arg-type]
    assert rows == []


# ------------------------------------------------------------------ database


@pytest.mark.db
def test_emit_and_list_events(sql):
    events.emit(7, "scan_started", "scan of acme/api#1", data={"repo": "acme/api"})
    events.emit(7, "stage_started", "triage started", stage="triage", task_id="7-triage")
    events.emit(8, "scan_started", "another scan")
    events.emit(7, "scan_finished", "scan done", level="info")
    got = events.list_events(7)
    assert [e["kind"] for e in got] == ["scan_started", "stage_started", "scan_finished"]
    assert got[0]["data"] == {"repo": "acme/api"}
    assert got[1]["task_id"] == "7-triage"
    assert got[1]["stage"] == "triage"
    assert got[0]["ts"] is not None
    assert got[2]["data"] is None


@pytest.mark.db
def test_list_events_after_id_and_limit(sql):
    for i in range(5):
        events.emit(7, "agent", f"m{i}")
    first = events.list_events(7, limit=2)
    assert [e["message"] for e in first] == ["m0", "m1"]
    rest = events.list_events(7, after_id=first[-1]["id"])
    assert [e["message"] for e in rest] == ["m2", "m3", "m4"]
    assert events.list_events(7, after_id=rest[-1]["id"]) == []


@pytest.mark.db
def test_list_events_of_unknown_scan_is_empty(sql):
    assert events.list_events(12345) == []

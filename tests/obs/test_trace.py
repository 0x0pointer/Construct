import io
import json
from datetime import UTC, datetime

from prsec.obs import trace

TS = datetime(2026, 10, 27, 12, 3, 4, tzinfo=UTC)


def ev(i, kind="stage_started", **kw):
    return {"id": i, "scan_id": 42, "ts": TS, "kind": kind, "level": "info", "stage": None, "task_id": None,
            "hypothesis_id": None, "message": f"event {i}", "data": None, **kw}


class FakeDb:
    """Scan events appear over time; status flips to done after `finish_after` status reads."""

    def __init__(self, batches, finish_after):
        self.batches = list(batches)
        self.finish_after = finish_after
        self.status_reads = 0
        self.fetches = []

    def status(self, scan_id):
        self.status_reads += 1
        return "done" if self.status_reads > self.finish_after else "running"

    def fetch(self, scan_id, after_id):
        self.fetches.append(after_id)
        return self.batches.pop(0) if self.batches else []


def test_format_event_columns():
    line = trace.format_event(ev(1, stage="static_verify", hypothesis_id="H3", message="started  verify\nnow"))
    assert "stage_started" in line
    assert "static_verify/H3" in line
    assert line.endswith("started verify now")
    assert line.split()[1] == "INFO"


def test_format_event_data_and_agent():
    line = trace.format_event(ev(1, kind="triage", data={"decision": "full", "tags": ["sqli"]}))
    assert line.endswith('[decision=full tags=["sqli"]]')
    agent = trace.format_event(ev(2, kind="agent", stage="hypothesise", message="tool_call: grep"))
    assert "> hypothesise: tool_call: grep" in agent


def test_format_data_truncates():
    text = trace.format_data({"blob": "x" * 500})
    assert len(text) == trace.DATA_MAX
    assert text.endswith("...")


def test_format_event_colour_by_level():
    assert trace.format_event(ev(1, level="error"), colour=True).startswith("\033[31m")
    assert not trace.format_event(ev(1), colour=True).startswith("\033")


def test_clock_accepts_iso_strings():
    assert trace._clock("2026-10-27T12:03:04Z") == trace._clock(TS)


def test_filter_kinds_and_no_agent():
    keep = trace.make_filter(["triage", "agent"], no_agent=True)
    assert keep(ev(1, kind="triage"))
    assert not keep(ev(2, kind="agent"))
    assert not keep(ev(3, kind="rules"))
    assert trace.make_filter([""], no_agent=False)(ev(4, kind="rules"))


def test_follow_polls_until_finished():
    db = FakeDb([[ev(1), ev(2)], [], [ev(3, kind="scan_finished")]], finish_after=2)
    seen, sleeps = [], []
    code = trace.follow(42, db.fetch, db.status, seen.append, sleep=sleeps.append)
    assert code == 0
    assert [e["id"] for e in seen] == [1, 2, 3]
    assert db.fetches == [0, 2, 2]
    assert sleeps == [trace.POLL_S, trace.POLL_S]


def test_follow_reads_full_pages_without_sleeping():
    db = FakeDb([[ev(1), ev(2)], [ev(3)]], finish_after=0)
    seen, sleeps = [], []
    assert trace.follow(42, db.fetch, db.status, seen.append, sleep=sleeps.append, page=2) == 0
    assert [e["id"] for e in seen] == [1, 2, 3]
    assert sleeps == []


def test_no_follow_stops_after_backlog():
    db = FakeDb([[ev(1)]], finish_after=99)
    seen = []
    assert trace.follow(42, db.fetch, db.status, seen.append, keep_following=False, sleep=None) == 0
    assert len(seen) == 1


def test_unknown_scan():
    out = io.StringIO()
    code = trace.main(["9"], fetch=lambda s, a: [], status=lambda s: None, out=out)
    assert code == 1
    assert out.getvalue() == ""


def test_main_json_and_filters():
    db = FakeDb([[ev(1), ev(2, kind="agent"), ev(3, kind="triage")]], finish_after=0)
    out = io.StringIO()
    code = trace.main(["42", "--json", "--no-agent", "--kinds", "triage,stage_started"],
                      fetch=db.fetch, status=db.status, out=out)
    rows = [json.loads(line) for line in out.getvalue().splitlines()]
    assert code == 0
    assert [r["id"] for r in rows] == [1, 3]
    assert rows[0]["ts"].startswith("2026-10-27 12:03:04")


def test_main_follow_text():
    db = FakeDb([[ev(1)], [ev(2, kind="scan_finished", message="done")]], finish_after=1)
    out = io.StringIO()
    code = trace.main(["42", "-f"], fetch=db.fetch, status=db.status, out=out, sleep=lambda s: None)
    lines = out.getvalue().splitlines()
    assert code == 0
    assert len(lines) == 2
    assert "scan_finished" in lines[1]

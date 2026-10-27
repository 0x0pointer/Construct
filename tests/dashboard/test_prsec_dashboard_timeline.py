import re
from datetime import UTC, datetime
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

from prsec.dashboard import main as dashboard
from prsec.db import findings as db
from prsec.obs import events as obs_events

HOSTILE = "<script>alert(1)</script>"
TS = datetime(2026, 10, 27, 12, 3, 4, tzinfo=UTC)


def ev(i, kind="stage_started", **kw):
    return {"id": i, "scan_id": 5, "ts": TS, "kind": kind, "level": "info", "stage": None, "task_id": None,
            "hypothesis_id": None, "message": f"event {i}", "data": None, **kw}


def scan(status="running"):
    return {"id": 5, "repo": "acme/shop", "pr": 7, "head_sha": "a" * 40, "base_sha": None, "status": status,
            "skills_version": "dev", "reason": "manual", "attempts": 1, "supersede_count": 0, "cost_usd": 0.1,
            "duration_s": 3, "sarif_uri": None, "triage": None, "error": None, "findings": [],
            "debug": {"log_level": "debug", "keep_minutes": 30},
            "stage_runs": [{"id": 31, "task_id": "5-hypothesise", "stage": "hypothesise", "harness": "codex",
                            "harness_version": None, "model": "agent-large", "status": "ok", "attempts": 1,
                            "usage": {"usd": 0.1}, "errors": [], "transcript_uri": "file:///t", "duration_s": 9}]}


class Store:
    def __init__(self, status="running", events=()):
        self.status = status
        self.events = list(events)
        self.calls = []

    def get_scan(self, scan_id):
        return scan(self.status) if scan_id == 5 else None

    def list_events(self, scan_id, after_id=0, limit=500):
        self.calls.append((scan_id, after_id, limit))
        return [e for e in self.events if e["id"] > after_id][:limit]


@pytest.fixture
def store(monkeypatch):
    s = Store()
    monkeypatch.setattr(db, "get_scan", s.get_scan)
    monkeypatch.setattr(obs_events, "list_events", s.list_events)
    return s


@pytest.fixture
def tclient(store):
    return TestClient(dashboard.app)


def _poll_url(html):
    return re.search(r'hx-get="([^"]+)"', html).group(1).replace("&amp;", "&")


def test_timeline_groups_agent_events_under_their_stage():
    events = [ev(1, kind="scan_started"),
              ev(2, kind="stage_started", stage="hypothesise", task_id="5-hypothesise"),
              ev(3, kind="agent", stage="hypothesise", task_id="5-hypothesise", message="reading diff"),
              ev(4, kind="agent", stage="static_verify", task_id="5-sv-H1"),
              ev(5, kind="agent", stage="hypothesise", task_id="5-hypothesise")]
    items, appended = dashboard._timeline(events, set(), {"5-hypothesise": 31})
    assert [i["type"] for i in items] == ["event", "event", "group", "group"]
    assert [e["id"] for e in items[2]["events"]] == [3, 5]
    assert items[2]["transcript_id"] == 31
    assert appended == {}


def test_timeline_appends_to_known_groups():
    items, appended = dashboard._timeline([ev(9, kind="agent", task_id="5-sv-H1")], {"5-sv-H1"}, {})
    assert items == []
    assert [e["id"] for e in appended[dashboard._group_dom_id("5-sv-H1")]] == [9]


def test_kv_truncates_and_serialises():
    pairs = dict(dashboard._kv({"n": 3, "long": "x" * 1000, "obj": {"a": [1]}}))
    assert pairs["n"] == "3"
    assert len(pairs["long"]) == dashboard.DATA_VALUE_MAX
    assert pairs["obj"] == '{"a": [1]}'
    assert dashboard._kv(None) == []


def test_scan_page_renders_timeline_escaped(tclient, store):
    store.events = [ev(1, kind="triage", level="warning", message=HOSTILE, data={"why": HOSTILE}),
                    ev(2, kind="agent", stage="hypothesise", task_id="5-hypothesise", message=HOSTILE)]
    r = tclient.get("/scans/5")
    assert r.status_code == 200
    assert HOSTILE not in r.text
    assert r.text.count("&lt;script&gt;alert(1)&lt;/script&gt;") == 3
    assert 'class="tl-ev lv-warning"' in r.text
    assert "<details open>" in r.text  # agent groups start open while the scan runs
    assert 'href="/stage-runs/31/transcript"' in r.text
    assert "log level <code>debug</code>, keep 30 min" in r.text
    assert store.calls == [(5, 0, dashboard.TIMELINE_INITIAL)]


def test_scan_page_polls_while_running(tclient, store):
    store.events = [ev(1), ev(2, kind="agent", task_id="5-hypothesise")]
    url = _poll_url(tclient.get("/scans/5").text)
    q = parse_qs(urlsplit(url).query)
    assert urlsplit(url).path == "/scans/5/events"
    assert q["after_id"] == ["2"]
    assert q["g"] == ["5-hypothesise"]
    assert 'hx-trigger="every 2s"' in tclient.get("/scans/5").text


def test_finished_scan_does_not_poll(tclient, store):
    store.status = "done"
    store.events = [ev(1, kind="scan_finished")]
    text = tclient.get("/scans/5").text
    assert "hx-get" not in text
    assert "timeline complete" in text


def test_agent_groups_start_closed_once_the_scan_finished(tclient, store):
    store.status = "done"
    store.events = [ev(1, kind="agent", stage="hypothesise", task_id="5-hypothesise")]
    text = tclient.get("/scans/5").text
    assert "<details>" in text


def test_label_row_links_the_finding_of_its_hypothesis():
    sc = {**scan("done"), "findings": [{"id": 44, "hypothesis_id": "H1"}, {"id": 45, "hypothesis_id": None}]}
    tl = dashboard._timeline_ctx(sc, [ev(1, kind="label", hypothesis_id="H1"), ev(2, kind="label")], 0, set(), 500)
    assert [i["ev"]["finding_id"] for i in tl["items"]] == [44, None]


def test_explicit_finding_id_wins_over_the_hypothesis_match():
    view = dashboard._event_view(ev(1, kind="replay", hypothesis_id="H1", data={"finding_id": 9}), {}, {"H1": 44})
    assert view["finding_id"] == 9


def test_poll_returns_only_new_events_out_of_band(tclient, store):
    store.events = [ev(1), ev(2, kind="agent", task_id="5-hypothesise", message="old"),
                    ev(3, kind="agent", task_id="5-hypothesise", message="tool_call grep"),
                    ev(4, kind="agent", task_id="5-sv-H1", stage="static_verify", message="new group"),
                    ev(5, kind="dynamic_outcome", hypothesis_id="H1", data={"finding_id": 12})]
    r = tclient.get("/scans/5/events", params={"after_id": 2, "g": ["5-hypothesise"]})
    assert r.status_code == 200
    assert "<html" not in r.text
    assert "old" not in r.text
    assert f'hx-swap-oob="beforeend:#{dashboard._group_dom_id("5-hypothesise")}"' in r.text
    assert 'hx-swap-oob="beforeend:#timeline-events"' in r.text
    assert f'id="{dashboard._group_dom_id("5-sv-H1")}"' in r.text
    assert 'href="/findings/12/dynamic-evidence"' in r.text
    q = parse_qs(urlsplit(_poll_url(r.text)).query)
    assert q["after_id"] == ["5"]
    assert q["g"] == ["5-hypothesise", "5-sv-H1"]


def test_poll_without_new_events_keeps_cursor(tclient, store):
    r = tclient.get("/scans/5/events", params={"after_id": 7})
    assert "hx-swap-oob" not in r.text
    assert parse_qs(urlsplit(_poll_url(r.text)).query)["after_id"] == ["7"]


def test_poll_stops_when_scan_finished(tclient, store):
    store.status = "failed"
    store.events = [ev(8, kind="scan_finished", level="error", message="boom")]
    r = tclient.get("/scans/5/events", params={"after_id": 7})
    assert "boom" in r.text
    assert "hx-get" not in r.text
    assert 'href="/scans/5"' in r.text


def test_poll_continues_while_backlog_is_full(tclient, store, monkeypatch):
    monkeypatch.setattr(dashboard, "TIMELINE_PAGE", 2)
    store.status = "done"
    store.events = [ev(1), ev(2), ev(3)]
    r = tclient.get("/scans/5/events")
    assert parse_qs(urlsplit(_poll_url(r.text)).query)["after_id"] == ["2"]


def test_poll_unknown_scan(tclient, store):
    assert tclient.get("/scans/6/events").status_code == 404


def test_run_sets_up_logging(monkeypatch):
    import uvicorn

    seen = {}
    monkeypatch.setattr(dashboard, "setup_logging", lambda service: seen.setdefault("service", service))
    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: seen.setdefault("kw", kw))
    dashboard.run()
    assert seen["service"] == "dashboard"
    assert seen["kw"]["log_config"] is None


@pytest.mark.db
def test_scan_page_reads_scan_events_table(client, seeded, pg_pool):
    from psycopg.types.json import Jsonb

    s1, _ = seeded["scans"]
    with pg_pool.connection() as c:
        c.execute("INSERT INTO scan_events (scan_id, kind, level, stage, message, data) VALUES"
                  " (%s, 'triage', 'info', 'triage', %s, %s)", (s1, HOSTILE, Jsonb({"decision": "full"})))
    text = client.get(f"/scans/{s1}").text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text
    assert "<dt>decision</dt>" in text
    assert "hx-get" not in text  # scan 1 is done

from __future__ import annotations

import copy
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from prsec.dashboard import main as dashboard

HOSTILE = "<script>alert(1)</script>"
NOW = datetime(2026, 10, 27, 12, 3, 4, tzinfo=UTC)


class FakeDashboardData:
    def __init__(self):
        self.findings = {
            1: {
                "id": 1,
                "title": f"SQLi {HOSTILE}",
                "severity": "high",
                "label": "likely",
                "status": "open",
                "triage_state": "new",
                "triage_note": f"operator note {HOSTILE}",
                "bug_class": "sqli",
                "vuln_class": "injection",
                "repo": "acme/shop",
                "last_pr": 7,
                "sink_file": "app/orders.py",
                "sink_line": 42,
                "fingerprint": "fp-1",
                "introduced": True,
                "first_scan_id": 9,
                "last_scan_id": 9,
                "updated_at": NOW,
                "occurrences": [
                    {
                        "scan_id": 9,
                        "pr": 7,
                        "head_sha": "a" * 40,
                        "label": "likely",
                        "scan_status": "running",
                        "created_at": NOW,
                    }
                ],
                "data": {
                    "description": f"desc {HOSTILE}",
                    "label_reason": "taint reaches query builder",
                    "remediation": "parameterize the statement",
                    "entry_point": "orders.show",
                    "source": {"file": "app/api.py", "line": 10, "snippet": HOSTILE},
                    "path": [
                        {"file": "app/orders.py", "line": 42, "end_line": 43, "snippet": f"query = {HOSTILE}"}
                    ],
                    "sink": {"file": "app/db.py", "line": 98, "snippet": "cursor.execute(query)"},
                    "guards": ["authz: admin"],
                    "hypothesis_id": "H1",
                    "provenance": {"agent": HOSTILE, "tool": "claude-code"},
                    "evidence_uri": "memory://evidence-1",
                    "dynamic": {
                        "outcome": "reproduced",
                        "reason": f"confirmed {HOSTILE}",
                        "entry": "http",
                        "head_runs": 1,
                        "head_fired": 1,
                        "base_fired": False,
                        "evidence_uri": "memory://dynamic-1",
                        "replays": [
                            {
                                "run_id": "9-replay-H1-r1",
                                "target": "head",
                                "env_ok": True,
                                "fired": True,
                                "duration_s": 12,
                                "oracle_results": [{"index": 0, "type": "response_contains", "passed": True, "detail": HOSTILE}],
                            }
                        ],
                        "poc_yaml": f"kind: http\ndescription: {HOSTILE}\n",
                    },
                },
            },
            2: {
                "id": 2,
                "title": "IDOR in order lookup",
                "severity": "critical",
                "label": "reproduced",
                "status": "open",
                "triage_state": "tp",
                "triage_note": "confirmed by AppSec",
                "bug_class": "idor",
                "vuln_class": "authz_bypass",
                "repo": "acme/shop",
                "last_pr": 7,
                "sink_file": "app/lookup.py",
                "sink_line": 17,
                "fingerprint": "fp-2",
                "introduced": False,
                "first_scan_id": 9,
                "last_scan_id": 9,
                "updated_at": NOW,
                "occurrences": [],
                "data": {
                    "description": "customer ids are guessable",
                    "label_reason": "reproduced with another account",
                    "path": [],
                    "guards": [],
                    "provenance": {"agent": "codex"},
                },
            },
        }
        self.scans = {
            9: {
                "id": 9,
                "repo": "acme/shop",
                "pr": 7,
                "head_sha": "a" * 40,
                "base_sha": "b" * 40,
                "status": "running",
                "skills_version": "dev",
                "reason": "manual",
                "attempts": 1,
                "supersede_count": 0,
                "cost_usd": 1.25,
                "duration_s": 125,
                "sarif_uri": "memory://sarif-9",
                "triage": {"decision": "full", "rationale": HOSTILE, "risk_tags": ["sqli"]},
                "error": None,
                "debug": {"log_level": "debug", "keep_minutes": 30},
                "keep_until": None,
                "stage_runs": [
                    {
                        "id": 31,
                        "task_id": "scan-9-hypothesise",
                        "stage": "hypothesise",
                        "role": "Hypothesise",
                        "harness": "codex",
                        "harness_version": "0.50.0",
                        "model": "agent-large",
                        "status": "ok",
                        "summary": "1 hypothesis(es): H1",
                        "attempts": 1,
                        "usage": {"tokens_in": 10, "tokens_out": 20, "usd": 0.1},
                        "turns": 2,
                        "errors": [],
                        "transcript_uri": "memory://transcript-31",
                        "duration_s": 9,
                    }
                ],
                "findings": [],
            }
        }
        self.scans[9]["findings"] = [self._scan_finding(1), self._scan_finding(2)]
        self.scan_rows = [
            {
                "id": 9,
                "repo": "acme/shop",
                "pr": 7,
                "head_sha": "a" * 40,
                "status": "running",
                "triage_decision": "full",
                "findings_total": 2,
                "findings_reproduced": 1,
                "findings_likely": 1,
                "findings_inconclusive": 0,
                "cost_usd": 1.25,
                "duration_s": 125,
                "created_at": NOW,
            }
        ]
        self.events = [
            {
                "id": 11,
                "scan_id": 9,
                "ts": NOW,
                "kind": "triage",
                "level": "warning",
                "stage": "triage",
                "task_id": None,
                "hypothesis_id": None,
                "message": HOSTILE,
                "data": {"note": HOSTILE},
            },
            {
                "id": 12,
                "scan_id": 9,
                "ts": NOW,
                "kind": "agent",
                "level": "info",
                "stage": "hypothesise",
                "task_id": "scan-9-hypothesise",
                "hypothesis_id": None,
                "message": "reading diff",
                "data": {"tool": "grep"},
            },
            {
                "id": 13,
                "scan_id": 9,
                "ts": NOW,
                "kind": "dynamic_outcome",
                "level": "info",
                "stage": "dynamic",
                "task_id": None,
                "hypothesis_id": "H1",
                "message": f"proof {HOSTILE}",
                "data": {"finding_id": 1, "detail": HOSTILE},
            },
        ]
        self.metrics_payload = {
            "scans_by_status": {"7d": {"running": 1}, "30d": {"running": 1}},
            "skip_rate": 0.0,
            "finished_scans": 1,
            "avg_cost_usd": 1.25,
            "total_cost_usd": 1.25,
            "avg_duration_s": 125,
            "precision_by_label": [{"key": "likely", "total": 1, "tp": 0, "fp": 0, "accepted": 0, "untriaged": 1, "precision": 0.0}],
            "precision_by_bug_class": [{"key": "sqli", "total": 1, "tp": 0, "fp": 0, "accepted": 0, "untriaged": 1, "precision": 0.0}],
            "per_stage": [{"stage": "hypothesise", "runs": 1, "ok_rate": 1.0, "failed": 0, "avg_duration_s": 9, "avg_cost": 0.1, "total_cost": 0.1, "avg_tokens": 30, "avg_turns": 2.0}],
            "per_harness": [{"harness": "codex", "runs": 1, "ok_rate": 1.0, "avg_duration_s": 9, "avg_cost": 0.1, "total_cost": 0.1, "avg_tokens": 30}],
            "per_stage_harness": [{"stage": "hypothesise", "harness": "codex", "model": "agent-large", "runs": 1, "ok_rate": 1.0, "avg_duration_s": 9, "avg_cost": 0.1, "total_cost": 0.1, "avg_tokens": 30}],
        }
        self.artifacts = {
            "memory://transcript-31": b'{"kind":"message"}\n',
            "memory://evidence-1": b'evidence\n',
            "memory://dynamic-1": b'dynamic evidence\n',
            "memory://sarif-9": b'{"runs": []}',
        }

    def _scan_finding(self, finding_id: int) -> dict:
        finding = self.findings[finding_id]
        return {
            "id": finding["id"],
            "severity": finding["severity"],
            "label": finding["label"],
            "bug_class": finding["bug_class"],
            "title": finding["title"],
            "sink_file": finding["sink_file"],
            "sink_line": finding["sink_line"],
            "status": finding["status"],
            "triage_state": finding["triage_state"],
        }

    def list_findings(self, filters=None, limit=None, offset=0):
        filters = filters or {}
        rows = []
        for finding in self.findings.values():
            if filters.get("repo") and finding["repo"] != filters["repo"]:
                continue
            if filters.get("label") and finding["label"] != filters["label"]:
                continue
            if filters.get("bug_class") and finding["bug_class"] != filters["bug_class"]:
                continue
            if filters.get("triage_state") and finding["triage_state"] != filters["triage_state"]:
                continue
            if filters.get("status") and finding["status"] != filters["status"]:
                continue
            if filters.get("severity") and finding["severity"] != filters["severity"]:
                continue
            rows.append(copy.deepcopy(finding))
        rows.sort(key=lambda row: row["id"])
        stop = None if limit is None else offset + limit
        return rows[offset:stop]

    def distinct_values(self):
        return {"repo": ["acme/shop"], "bug_class": ["sqli", "idor"]}

    def get_finding(self, finding_id):
        finding = self.findings.get(finding_id)
        return copy.deepcopy(finding) if finding else None

    def set_triage(self, finding_id, state, note, actor=None):
        finding = self.findings.get(finding_id)
        if finding is None:
            return None
        finding["triage_state"] = state
        suffix = f"{actor} -> {state}" if actor else state
        finding["triage_note"] = f"{suffix}\n{note}" if note else suffix
        self.scans[9]["findings"] = [self._scan_finding(1), self._scan_finding(2)]
        return copy.deepcopy(finding)

    def list_scans(self, filters=None, limit=None, offset=0):
        filters = filters or {}
        rows = []
        for scan in self.scan_rows:
            if filters.get("repo") and scan["repo"] != filters["repo"]:
                continue
            if filters.get("status") and scan["status"] != filters["status"]:
                continue
            if filters.get("pr") and scan["pr"] != filters["pr"]:
                continue
            rows.append(copy.deepcopy(scan))
        stop = None if limit is None else offset + limit
        return rows[offset:stop]

    def get_scan(self, scan_id):
        scan = self.scans.get(scan_id)
        return copy.deepcopy(scan) if scan else None

    def list_events(self, scan_id, after_id=0, limit=500):
        return [copy.deepcopy(event) for event in self.events if event["scan_id"] == scan_id and event["id"] > after_id][:limit]

    def metrics(self):
        return copy.deepcopy(self.metrics_payload)

    def stage_run_transcript_uri(self, stage_run_id):
        return "memory://transcript-31" if stage_run_id == 31 else None


@pytest.fixture
def dashboard_client(monkeypatch):
    data = FakeDashboardData()
    monkeypatch.setattr(dashboard.db, "list_findings", data.list_findings)
    monkeypatch.setattr(dashboard.db, "distinct_values", data.distinct_values)
    monkeypatch.setattr(dashboard.db, "get_finding", data.get_finding)
    monkeypatch.setattr(dashboard.db, "set_triage", data.set_triage)
    monkeypatch.setattr(dashboard.db, "list_scans", data.list_scans)
    monkeypatch.setattr(dashboard.db, "get_scan", data.get_scan)
    monkeypatch.setattr(dashboard.db, "metrics", data.metrics)
    monkeypatch.setattr(dashboard.db, "stage_run_transcript_uri", data.stage_run_transcript_uri)
    monkeypatch.setattr(dashboard.obs_events, "list_events", data.list_events)
    monkeypatch.setattr(dashboard.sarif_store, "read_uri", lambda uri: data.artifacts[uri])
    return TestClient(dashboard.app), data


def test_dashboard_assets_are_first_party_and_packaged(dashboard_client):
    client, _ = dashboard_client
    response = client.get("/findings")
    assert response.status_code == 200
    assert 'href="http://testserver/static/dashboard.css"' in response.text
    assert 'src="http://testserver/static/dashboard.js"' in response.text
    assert "https://" not in response.text
    assert "unpkg" not in response.text
    assert "htmx" not in response.text.lower()
    assert client.get("/static/dashboard.css").status_code == 200
    assert client.get("/static/dashboard.js").status_code == 200
    pyproject = Path("/workspace/Construct/pyproject.toml").read_text()
    assert "dashboard/static/*.css" in pyproject
    assert "dashboard/static/*.js" in pyproject


def test_findings_page_responsive_filters_table_empty_and_partial(dashboard_client):
    client, _ = dashboard_client
    response = client.get("/findings", params={"label": "likely"})
    assert response.status_code == 200
    assert 'data-dashboard-filters' in response.text
    assert 'id="findings-table"' in response.text
    assert 'class="table-wrap"' in response.text
    assert 'option selected>likely<' in response.text
    assert "SQLi" in response.text
    assert "IDOR in order lookup" not in response.text

    partial = client.get(
        "/findings",
        params={"label": "reproduced"},
        headers={"X-Partial-Request": "true", "X-Partial-Target": "findings-table"},
    )
    assert partial.status_code == 200
    assert "<html" not in partial.text
    assert "IDOR in order lookup" in partial.text
    assert "SQLi" not in partial.text
    assert 'class="pager"' in partial.text

    empty = client.get("/findings", params={"repo": "unknown/repo"})
    assert empty.status_code == 200
    assert "No findings match." in empty.text
    assert 'class="empty-state"' in empty.text


def test_finding_detail_prioritizes_content_and_escapes_untrusted_text(dashboard_client):
    client, _ = dashboard_client
    response = client.get("/findings/1")
    assert response.status_code == 200
    assert "Description" in response.text
    assert "Code flow" in response.text
    assert "Dynamic validation" in response.text
    assert "Provenance" in response.text
    assert "Occurrences" in response.text
    assert 'class="layout-two-col"' in response.text
    assert 'id="triage-panel"' in response.text
    assert 'action="/findings/1/triage"' in response.text
    assert HOSTILE not in response.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in response.text


def test_scans_scan_metrics_keep_existing_visible_behaviour(dashboard_client, monkeypatch):
    client, data = dashboard_client
    scans = client.get("/")
    assert scans.status_code == 200
    assert "Scans" in scans.text
    assert 'href="/scans/9"' in scans.text
    assert "Findings column: total (reproduced/likely/inconclusive)." in scans.text

    empty_scans = client.get("/", params={"status": "done"})
    assert empty_scans.status_code == 200
    assert "No scans." in empty_scans.text

    detail = client.get("/scans/9")
    assert detail.status_code == 200
    assert "Timeline" in detail.text
    assert 'data-dashboard-timeline-poller' in detail.text
    assert 'data-poll-url="/scans/9/events?' in detail.text
    assert 'href="/sarif/9"' in detail.text
    assert "Hypothesise" in detail.text

    metrics = client.get("/metrics")
    assert metrics.status_code == 200
    assert "Metrics" in metrics.text
    assert "Harness comparison (30 days)" in metrics.text
    assert "hypothesise" in metrics.text

    monkeypatch.setattr(dashboard.db, "metrics", lambda: {
        **data.metrics_payload,
        "per_stage": [],
        "per_harness": [],
        "per_stage_harness": [],
        "precision_by_label": [],
        "precision_by_bug_class": [],
    })
    empty_metrics = client.get("/metrics")
    assert "No findings." in empty_metrics.text
    assert "No stage runs." in empty_metrics.text


def test_triage_progressive_enhancement_and_validation(dashboard_client):
    client, _ = dashboard_client
    redirect = client.post("/findings/1/triage", data={"state": "tp", "note": "confirmed"}, follow_redirects=False)
    assert redirect.status_code == 303
    assert redirect.headers["location"] == "/findings/1"

    partial = client.post(
        "/findings/1/triage",
        data={"state": "fp", "note": "closed out"},
        headers={"X-Partial-Request": "true", "X-Partial-Target": "triage-panel", "X-Forwarded-Email": "appsec@example.com"},
    )
    assert partial.status_code == 200
    assert "saved" in partial.text
    assert "appsec@example.com -&gt; fp" in partial.text
    assert "closed out" in partial.text

    assert client.post("/findings/1/triage", data={"state": "bogus"}).status_code == 422
    assert client.post("/findings/404/triage", data={"state": "tp"}).status_code == 404


def test_artifact_security_headers_unchanged(dashboard_client):
    client, _ = dashboard_client
    for path in ("/stage-runs/31/transcript", "/findings/1/evidence", "/findings/1/dynamic-evidence"):
        response = client.get(path)
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/plain")
        assert response.headers["x-content-type-options"] == "nosniff"


def test_timeline_poll_fragment_is_safe_and_deduplicatable(dashboard_client):
    client, _ = dashboard_client
    response = client.get("/scans/9/events", params={"after_id": 11, "g": ["scan-9-hypothesise"]})
    assert response.status_code == 200
    assert 'data-replace-target="#timeline-poller"' in response.text
    assert 'data-append-target="#timeline-events"' in response.text
    assert f'data-append-target="#{dashboard._group_dom_id("scan-9-hypothesise")}"' in response.text
    assert 'data-id="12"' in response.text
    assert 'data-id="13"' in response.text
    assert HOSTILE not in response.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in response.text

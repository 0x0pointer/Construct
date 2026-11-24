import json

import pytest
from psycopg.types.json import Jsonb

from prsec.dashboard import main as dashboard
from prsec.db import findings as db

pytestmark = pytest.mark.db


def _fid(fingerprint):
    return next(r["id"] for r in db.list_findings() if r["fingerprint"] == fingerprint)


def _assert_no_remote_assets(text):
    lowered = text.lower()
    for needle in ("https://", "http://", "unpkg.com", "htmx.org"):
        assert needle not in lowered


def test_scans_list(client, seeded):
    s1, s2 = seeded["scans"]
    r = client.get("/")
    assert r.status_code == 200
    assert 'class="topnav"' in r.text
    assert 'class="app-main"' in r.text
    assert 'class="page-header"' in r.text
    assert '<form class="filters" method="get" action="/">' in r.text
    assert "Apply filters" in r.text
    assert 'class="card"' in r.text
    assert f'href="/scans/{s1}"' in r.text
    assert f'href="/scans/{s2}"' in r.text
    assert "acme/web" in r.text
    assert "$1.25" in r.text
    assert "2m00s" in r.text or "1m59s" in r.text
    _assert_no_remote_assets(r.text)
    r = client.get("/", params={"status": "skipped"})
    assert "acme/web" in r.text
    assert "acme/shop" not in r.text


def test_scan_detail(client, seeded):
    s1, _ = seeded["scans"]
    r = client.get(f"/scans/{s1}")
    assert r.status_code == 200
    assert "New &lt;b&gt;SQL&lt;/b&gt; endpoint" in r.text  # escaped
    assert "codex" in r.text
    assert "0.50.0" in r.text
    assert "output_invalid" in r.text
    assert "schema: citations missing" in r.text
    assert f'href="/sarif/{s1}"' in r.text
    assert client.get("/scans/999999").status_code == 404


def test_scan_detail_agent_observability(client, seeded):
    s1, _ = seeded["scans"]
    r = client.get(f"/scans/{s1}")
    assert r.status_code == 200
    # Agents panel: friendly role names and the decision summary derived from each agent's output.
    assert "Agents" in r.text
    assert "Hypothesise" in r.text
    assert "Static verify" in r.text
    assert "2 hypothesis(es): H1, H2" in r.text  # hypothesise decision from its output
    assert "Turns" in r.text  # per-agent effort column


def test_metrics_per_agent_rollup(client, seeded):
    r = client.get("/metrics")
    assert r.status_code == 200
    assert "By agent" in r.text
    assert "Avg turns" in r.text
    assert "hypothesise" in r.text  # a per-stage row
    assert "static_verify" in r.text


def test_findings_filters(client, seeded):
    r = client.get("/findings")
    assert r.status_code == 200
    assert '<form class="filters" method="get" action="/findings"' in r.text
    assert "Apply filters" in r.text
    assert "<noscript>" not in r.text
    assert r.text.count('href="/findings/') >= 6
    _assert_no_remote_assets(r.text)

    r = client.get("/findings")
    r = client.get("/findings", params={"label": "reproduced"})
    assert "idor in get" in r.text
    assert "sqli in find" not in r.text

    r = client.get("/findings", params={"repo": "nope/repo"})
    assert 'id="findings-empty-state"' in r.text
    assert "No findings match the current filters." in r.text

    r = client.get("/findings", params={"bug_class": "sqli", "repo": "acme/shop"},
                   headers={"HX-Request": "true", "HX-Target": "findings-table"})
    assert "<html" not in r.text
    assert "Matching findings" in r.text
    assert "sqli in find" in r.text
    assert "idor in get" not in r.text


def test_findings_filters_remain_plain_get_and_partial_compatible(client, seeded, monkeypatch):
    monkeypatch.setattr(dashboard, "PAGE_SIZE", 2)
    r = client.get("/findings", params={"repo": "acme/shop", "severity": "high"})
    assert r.status_code == 200
    assert '<form class="filters" method="get" action="/findings"' in r.text
    assert 'data-dashboard-partial="true"' in r.text
    assert "Apply filters" in r.text
    assert 'href="/findings?repo=acme%2Fshop&amp;severity=high&amp;page=2"' in r.text

    partial = client.get(
        "/findings",
        params={"repo": "acme/shop", "severity": "high"},
        headers={"HX-Request": "true", "HX-Target": "findings-table"},
    )
    assert partial.status_code == 200
    assert "<html" not in partial.text
    assert '<section class="card">' in partial.text
    assert "Matching findings" in partial.text


def test_finding_detail_and_triage(client, seeded):
    f = seeded["findings"][0]
    fid = _fid(f.fingerprint)
    r = client.get(f"/findings/{fid}")
    assert r.status_code == 200
    assert 'class="page-header hero"' in r.text
    assert 'id="triage-panel"' in r.text
    assert 'method="post" action="/findings/' in r.text
    assert "app/api.py:10" in r.text
    assert "app/orders.py:42-43" in r.text
    assert "oid = request.args[&#39;id&#39;]" in r.text
    assert "claude-code" in r.text
    assert f.fingerprint in r.text

    r = client.post(f"/findings/{fid}/triage", data={"state": "fp", "note": "sanitised upstream"},
                    headers={"HX-Request": "true", "X-Forwarded-Email": "appsec@example.com"})
    assert r.status_code == 200
    assert "<html" not in r.text
    assert "saved" in r.text
    assert "appsec@example.com" in r.text
    assert "sanitised upstream" in r.text
    got = db.get_finding(fid)
    assert got["triage_state"] == "fp"
    assert "appsec@example.com -> fp" in got["triage_note"]

    r = client.post(f"/findings/{fid}/triage", data={"state": "tp"}, follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == f"/findings/{fid}"
    assert client.post(f"/findings/{fid}/triage", data={"state": "bogus"}).status_code == 422
    assert client.post("/findings/999999/triage", data={"state": "tp"}).status_code == 404
    assert client.get("/findings/999999").status_code == 404


def test_dashboard_pages_share_restyled_shell(client, seeded):
    s1, _ = seeded["scans"]
    pages = [
        ("/", "Scans"),
        ("/findings", "Findings"),
        ("/metrics", "Metrics"),
        (f"/scans/{s1}", "Agents"),
    ]
    for path, marker in pages:
        r = client.get(path)
        assert r.status_code == 200
        assert 'class="topnav"' in r.text
        assert 'class="app-main"' in r.text
        assert 'class="page-header"' in r.text
        assert marker in r.text
        _assert_no_remote_assets(r.text)


def test_finding_detail_restyled_layout_preserves_sections(client, seeded, pg_pool):
    fid = _fid(seeded["findings"][0].fingerprint)
    dynamic = {
        "outcome": "reproduced",
        "reason": "replay_confirmed",
        "entry": "http",
        "head_runs": 2,
        "head_fired": 2,
        "base_fired": False,
        "evidence_uri": "file:///tmp/replay.json",
        "replays": [
            {
                "run_id": "1-replay-H1-r1",
                "env_ok": True,
                "fired": True,
                "duration_s": 11,
                "oracle_results": [{"index": 0, "type": "response_contains", "passed": True, "detail": "canary"}],
                "sink_hits": [{"path": "/sink"}],
            }
        ],
        "poc": {"kind": "http", "steps": [{"path": "/orders"}]},
    }
    with pg_pool.connection() as c:
        c.execute(
            "UPDATE findings SET data = jsonb_set(jsonb_set(data, '{evidence_uri}', to_jsonb(%s::text)), '{dynamic}', %s) WHERE id = %s",
            ("file:///tmp/evidence.txt", Jsonb(dynamic), fid),
        )
    r = client.get(f"/findings/{fid}")
    assert r.status_code == 200
    assert 'class="page-header hero"' in r.text
    assert 'class="grid2"' in r.text
    for heading in ("Description", "Label reasoning", "Remediation", "Code flow", "Guards",
                    "Dynamic validation", "Triage", "Metadata", "Provenance", "Occurrences"):
        assert heading in r.text
    for text in ("sqli in find", "high", "likely", "open", "acme/shop", "User input reaches a query.",
                 "static path confirmed", "Use bound parameters.", "app/api.py:10", "app/orders.py:42-43",
                 "none", "replay bundle", "Replay runs", "PoC", "Fingerprint", "stage transcript"):
        assert text in r.text
    assert f'href="/findings/{fid}/dynamic-evidence"' in r.text
    assert f'href="/findings/{fid}/evidence"' in r.text
    assert 'href="/scans/' in r.text


def test_dashboard_restyle_escapes_untrusted_finding_and_scan_content(client, seeded, pg_pool):
    from psycopg.types.json import Jsonb

    s1, _ = seeded["scans"]
    fid = _fid(seeded["findings"][0].fingerprint)
    hostile = '<script>alert(1)</script>" onclick="alert(2)'
    forwarded = '<img src=x onerror=alert(1)>'
    note = f"{hostile} javascript:alert(9)"
    with pg_pool.connection() as c:
        c.execute(
            """
            UPDATE findings
               SET title = %s,
                   data = jsonb_set(
                       jsonb_set(
                           jsonb_set(data, '{description}', to_jsonb(%s::text)),
                           '{source,snippet}', to_jsonb(%s::text)
                       ),
                       '{label_reason}', to_jsonb(%s::text)
                   )
             WHERE id = %s
            """,
            (hostile, hostile, hostile, note, fid),
        )
        c.execute(
            "INSERT INTO scan_events (scan_id, kind, level, stage, message, data) VALUES (%s, 'triage', 'warning', 'triage', %s, %s)",
            (s1, hostile, Jsonb({"note": note})),
        )
    db.set_triage(fid, "accepted", note)

    finding_page = client.get(f"/findings/{fid}", headers={"X-Forwarded-User": forwarded})
    scan_page = client.get(f"/scans/{s1}", headers={"X-Forwarded-User": forwarded})
    for page in (finding_page, scan_page):
        assert page.status_code == 200
        assert hostile not in page.text
        assert forwarded not in page.text
        assert "<img" not in page.text
        assert 'href="javascript:' not in page.text
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page.text
        assert "&lt;img src=x onerror=alert(1)&gt;" in page.text
        assert "javascript:alert(9)" in page.text


def test_finding_detail_handles_missing_optional_sections(client, seeded, pg_pool):
    fid = _fid(seeded["findings"][0].fingerprint)
    minimal = {
        "hypothesis_id": "H1",
        "provenance": {"static_verify": {"harness": "claude-code"}},
        "sink": {"file": "app/orders.py", "line": 42},
    }
    with pg_pool.connection() as c:
        c.execute("UPDATE findings SET data = %s WHERE id = %s", (Jsonb(minimal), fid))
    r = client.get(f"/findings/{fid}")
    assert r.status_code == 200
    assert "No remediation recorded." in r.text
    assert "No guards recorded." in r.text
    assert "No dynamic validation recorded." in r.text
    assert "No stage transcript artifact." in r.text
    assert "/dynamic-evidence" not in r.text
    assert f'href="/findings/{fid}/evidence"' not in r.text


def test_long_dashboard_values_use_wrapping_layout(client, seeded, pg_pool):
    s1, _ = seeded["scans"]
    fid = _fid(seeded["findings"][0].fingerprint)
    long_title = "very-long-title-" * 12
    long_repo = "owner/" + ("nested-service-" * 8)
    long_path = "src/" + ("deep/" * 14) + "module.py"
    long_fingerprint = "fp-" + ("abcdef123456" * 8)
    long_snippet = "sink(" + ("x" * 420) + ")"
    long_note = "triage-note-" + ("n" * 260)
    long_provenance = {"trace": "line-" + ("p" * 320)}
    dynamic = {
        "outcome": "reproduced",
        "head_runs": 1,
        "head_fired": 1,
        "base_fired": None,
        "replays": [{"run_id": "r1", "env_ok": True, "fired": True, "duration_s": 7, "app_log_tail": "log-" + ("z" * 320)}],
    }
    with pg_pool.connection() as c:
        c.execute(
            """
            UPDATE findings
               SET repo = %s,
                   title = %s,
                   fingerprint = %s,
                   data = jsonb_set(
                       jsonb_set(
                           jsonb_set(data, '{sink,file}', to_jsonb(%s::text)),
                           '{sink,snippet}', to_jsonb(%s::text)
                       ),
                       '{provenance}', %s
                   )
             WHERE id = %s
            """,
            (long_repo, long_title, long_fingerprint, long_path, long_snippet, Jsonb(long_provenance), fid),
        )
        c.execute("UPDATE findings SET data = jsonb_set(data, '{dynamic}', %s) WHERE id = %s", (Jsonb(dynamic), fid))
    db.set_triage(fid, "tp", long_note)

    finding_page = client.get(f"/findings/{fid}")
    scan_page = client.get(f"/scans/{s1}")
    assert finding_page.status_code == 200
    assert long_title in finding_page.text
    assert long_repo in finding_page.text
    assert long_path in finding_page.text
    assert long_fingerprint in finding_page.text
    assert long_snippet in finding_page.text
    assert long_note in finding_page.text
    assert "line-" in finding_page.text
    assert 'class="page-header__title wrap-anywhere"' in finding_page.text
    assert 'class="table-wrap"' in finding_page.text
    assert "<pre>" in finding_page.text
    assert scan_page.status_code == 200
    assert "log-" in scan_page.text or "log-" in finding_page.text
    assert 'class="table-wrap"' in scan_page.text


def test_metrics_page(client, seeded):
    db.set_triage(_fid(seeded["findings"][0].fingerprint), "tp", None)
    r = client.get("/metrics")
    assert r.status_code == 200
    assert "Harness comparison" in r.text
    assert "claude-code" in r.text
    assert "codex" in r.text
    assert "50%" in r.text  # skip rate: 1 skipped / (1 done + 1 skipped)
    assert "100%" in r.text  # sqli precision


def test_sarif_download(client, seeded):
    s1, s2 = seeded["scans"]
    r = client.get(f"/sarif/{s1}")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/sarif+json")
    assert "attachment" in r.headers["content-disposition"]
    assert len(json.loads(r.content)["runs"][0]["results"]) == 3
    assert client.get(f"/sarif/{s2}").status_code == 404


def test_healthz(client):
    assert client.get("/healthz").text == "ok"


def test_transcript_and_evidence_routes(client, seeded, pg_pool):
    from prsec.adapters.sinks.sarif_store import evidence_key, put_bytes

    s1, _ = seeded["scans"]
    uri = put_bytes(evidence_key("acme/shop", 7, "a" * 40, "t1", "transcript.jsonl"), b'{"kind": "message"}\n', "application/x-ndjson")
    with pg_pool.connection() as c:
        run_id = c.execute("UPDATE stage_runs SET transcript_uri = %s WHERE task_id = 't1' RETURNING id", (uri,)).fetchone()[0]
        no_tr = c.execute("SELECT id FROM stage_runs WHERE task_id = 't2'").fetchone()[0]
        fid = c.execute("SELECT id FROM findings ORDER BY id LIMIT 1").fetchone()[0]
        c.execute("UPDATE findings SET data = jsonb_set(data, '{evidence_uri}', to_jsonb(%s::text)) WHERE id = %s", (uri, fid))
    assert f'href="/stage-runs/{run_id}/transcript"' in client.get(f"/scans/{s1}").text
    r = client.get(f"/stage-runs/{run_id}/transcript")
    assert r.status_code == 200
    assert '"kind": "message"' in r.text
    assert client.get(f"/stage-runs/{no_tr}/transcript").status_code == 404
    assert f'href="/findings/{fid}/evidence"' in client.get(f"/findings/{fid}").text
    assert client.get(f"/findings/{fid}/evidence").text == r.text
    with pg_pool.connection() as c:
        c.execute("UPDATE stage_runs SET transcript_uri = 'file:///etc/passwd' WHERE id = %s", (run_id,))
    assert client.get(f"/stage-runs/{run_id}/transcript").status_code == 404


@pytest.mark.parametrize("path", ["/findings/7", "/findings", "/", "/findings/7?x=1#t"])
def test_local_path_keeps_same_site_paths(path):
    assert dashboard._local_path(path) == path


@pytest.mark.parametrize(
    "path",
    [
        "https://evil.example/x",
        "javascript:alert(1)",
        "//evil.example/x",
        "/\\evil.example/x",
        "\\\\evil.example/x",
        "/\t/evil.example",
        "/\n/evil.example",
        "findings/7",
        "",
        "http:/evil.example",
    ],
)
def test_local_path_refuses_off_site_redirects(path):
    assert dashboard._local_path(path) == "/findings"
    assert dashboard._local_path(path, fallback="/") == "/"


def test_run_binds_loopback_unless_configured(monkeypatch):
    import uvicorn

    calls = []
    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: calls.append(kw))
    monkeypatch.delenv("PRSEC_DASHBOARD_HOST", raising=False)
    monkeypatch.delenv("PRSEC_DASHBOARD_PORT", raising=False)
    dashboard.run()
    monkeypatch.setenv("PRSEC_DASHBOARD_HOST", "0.0.0.0")
    monkeypatch.setenv("PRSEC_DASHBOARD_PORT", "9000")
    dashboard.run()
    assert [(c["host"], c["port"]) for c in calls] == [("127.0.0.1", 8081), ("0.0.0.0", 9000)]

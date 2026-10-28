import json

import pytest

from prsec.dashboard import main as dashboard
from prsec.db import findings as db

pytestmark = pytest.mark.db


def _fid(fingerprint):
    return next(r["id"] for r in db.list_findings() if r["fingerprint"] == fingerprint)


def test_scans_list(client, seeded):
    s1, s2 = seeded["scans"]
    r = client.get("/")
    assert r.status_code == 200
    assert f'href="/scans/{s1}"' in r.text
    assert "acme/web" in r.text
    assert "$1.25" in r.text
    assert "2m00s" in r.text or "1m59s" in r.text
    assert "htmx.org@2.0.4" in r.text
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
    assert r.text.count('href="/findings/') >= 6
    r = client.get("/findings", params={"label": "reproduced"})
    assert "idor in get" in r.text
    assert "sqli in find" not in r.text
    r = client.get("/findings", params={"bug_class": "sqli", "repo": "acme/shop"},
                   headers={"HX-Request": "true", "HX-Target": "findings-table"})
    assert "<html" not in r.text
    assert "sqli in find" in r.text
    assert "idor in get" not in r.text


def test_finding_detail_and_triage(client, seeded):
    f = seeded["findings"][0]
    fid = _fid(f.fingerprint)
    r = client.get(f"/findings/{fid}")
    assert r.status_code == 200
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

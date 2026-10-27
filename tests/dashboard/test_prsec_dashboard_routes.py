import json

import pytest

from prsec.db import findings as db

pytestmark = pytest.mark.db


def _fid(fingerprint):
    return next(r["id"] for r in db.list_findings() if r["fingerprint"] == fingerprint)


def test_scans_list(client, seeded):
    s1, s2 = seeded["scans"]
    r = client.get("/")
    assert r.status_code == 200
    assert f'href="/scans/{s1}"' in r.text and "acme/web" in r.text
    assert "$1.25" in r.text and ("2m00s" in r.text or "1m59s" in r.text)
    assert "htmx.org@2.0.4" in r.text
    r = client.get("/", params={"status": "skipped"})
    assert "acme/web" in r.text and "acme/shop" not in r.text


def test_scan_detail(client, seeded):
    s1, _ = seeded["scans"]
    r = client.get(f"/scans/{s1}")
    assert r.status_code == 200
    assert "New &lt;b&gt;SQL&lt;/b&gt; endpoint" in r.text  # escaped
    assert "codex" in r.text and "0.50.0" in r.text and "output_invalid" in r.text
    assert "schema: citations missing" in r.text
    assert f'href="/sarif/{s1}"' in r.text
    assert client.get("/scans/999999").status_code == 404


def test_findings_filters(client, seeded):
    r = client.get("/findings")
    assert r.status_code == 200 and r.text.count('href="/findings/') >= 6
    r = client.get("/findings", params={"label": "reproduced"})
    assert "idor in get" in r.text and "sqli in find" not in r.text
    r = client.get("/findings", params={"bug_class": "sqli", "repo": "acme/shop"},
                   headers={"HX-Request": "true", "HX-Target": "findings-table"})
    assert "<html" not in r.text and "sqli in find" in r.text and "idor in get" not in r.text


def test_finding_detail_and_triage(client, seeded):
    f = seeded["findings"][0]
    fid = _fid(f.fingerprint)
    r = client.get(f"/findings/{fid}")
    assert r.status_code == 200
    assert "app/api.py:10" in r.text and "app/orders.py:42-43" in r.text
    assert "oid = request.args[&#39;id&#39;]" in r.text
    assert "claude-code" in r.text and f.fingerprint in r.text

    r = client.post(f"/findings/{fid}/triage", data={"state": "fp", "note": "sanitised upstream"},
                    headers={"HX-Request": "true", "X-Forwarded-Email": "appsec@example.com"})
    assert r.status_code == 200 and "<html" not in r.text
    assert "saved" in r.text and "appsec@example.com" in r.text and "sanitised upstream" in r.text
    got = db.get_finding(fid)
    assert got["triage_state"] == "fp" and "appsec@example.com -> fp" in got["triage_note"]

    r = client.post(f"/findings/{fid}/triage", data={"state": "tp"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == f"/findings/{fid}"
    assert client.post(f"/findings/{fid}/triage", data={"state": "bogus"}).status_code == 422
    assert client.post("/findings/999999/triage", data={"state": "tp"}).status_code == 404
    assert client.get("/findings/999999").status_code == 404


def test_metrics_page(client, seeded):
    db.set_triage(_fid(seeded["findings"][0].fingerprint), "tp", None)
    r = client.get("/metrics")
    assert r.status_code == 200
    assert "Harness comparison" in r.text and "claude-code" in r.text and "codex" in r.text
    assert "50%" in r.text  # skip rate: 1 skipped / (1 done + 1 skipped)
    assert "100%" in r.text  # sqli precision


def test_sarif_download(client, seeded):
    s1, s2 = seeded["scans"]
    r = client.get(f"/sarif/{s1}")
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/sarif+json")
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
    assert r.status_code == 200 and '"kind": "message"' in r.text
    assert client.get(f"/stage-runs/{no_tr}/transcript").status_code == 404
    assert f'href="/findings/{fid}/evidence"' in client.get(f"/findings/{fid}").text
    assert client.get(f"/findings/{fid}/evidence").text == r.text
    with pg_pool.connection() as c:
        c.execute("UPDATE stage_runs SET transcript_uri = 'file:///etc/passwd' WHERE id = %s", (run_id,))
    assert client.get(f"/stage-runs/{run_id}/transcript").status_code == 404

import pytest

from prsec.dashboard import main as dashboard
from prsec.db import findings as db
from prsec.dynamic.poc import PoC
from prsec.dynamic.results import DynamicEvidence, OracleResult, ReplayResult

HOSTILE = "<script>alert(1)</script>"
POC = PoC(kind="http", hypothesis_id="H1", description=f"reflected {HOSTILE}",
          steps=[{"name": "probe", "path": "/search?q=${CANARY.token}"}],
          oracles=[{"type": "response_contains", "step": "probe", "value": "${CANARY.token}"}])


def _evidence(uri=None) -> dict:
    replays = [
        ReplayResult(run_id="1-replay-H1-r1", env_ok=True, fired=True, duration_s=75,
                     oracle_results=[OracleResult(index=0, type="response_contains", passed=True, detail=HOSTILE)],
                     sink_hits=[{"host": "tok.canary.invalid", "path": "/tok"}]),
        ReplayResult(run_id="1-replay-H1-r2", env_ok=True, fired=True),
        ReplayResult(run_id="1-replay-H1-base", env_ok=False, env_error="base app never healthy"),
    ]
    return DynamicEvidence(hypothesis_id="H1", outcome="reproduced", reason="replay_confirmed", entry="http",
                           head_runs=2, head_fired=2, poc=POC, replays=replays,
                           evidence_uri=uri).model_dump(mode="json", by_alias=True)


def test_dynamic_view_tags_replays_and_renders_yaml():
    view = dashboard._dynamic_view(_evidence())
    assert [r["target"] for r in view["replays"]] == ["head", "head", "base"]
    assert "kind: http" in view["poc_yaml"]
    assert "${CANARY.token}" in view["poc_yaml"]


def test_dynamic_view_without_evidence():
    assert dashboard._dynamic_view(None) is None


@pytest.mark.db
def test_finding_page_dynamic_section_is_escaped(client, seeded, pg_pool):
    from psycopg.types.json import Jsonb

    fid = next(r["id"] for r in db.list_findings() if r["fingerprint"] == seeded["findings"][0].fingerprint)
    with pg_pool.connection() as c:
        c.execute("UPDATE findings SET data = jsonb_set(data, '{dynamic}', %s) WHERE id = %s", (Jsonb(_evidence()), fid))
    text = client.get(f"/findings/{fid}").text
    assert 'id="dynamic"' in text
    assert "2/2 fired" in text
    assert "1-replay-H1-base" in text
    assert "base app never healthy" in text
    assert "tok.canary.invalid" in text
    assert "1m15s" in text
    assert HOSTILE not in text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text


@pytest.mark.db
def test_dynamic_evidence_route(client, seeded, pg_pool):
    from psycopg.types.json import Jsonb

    from prsec.adapters.sinks.sarif_store import evidence_key, put_bytes

    fid = next(r["id"] for r in db.list_findings() if r["fingerprint"] == seeded["findings"][0].fingerprint)
    assert client.get(f"/findings/{fid}/dynamic-evidence").status_code == 404
    uri = put_bytes(evidence_key("acme/shop", 7, "a" * 40, "1-dynamic-H1", "dynamic_evidence.json"), b'{"outcome": "reproduced"}',
                    "application/json")
    with pg_pool.connection() as c:
        c.execute("UPDATE findings SET data = jsonb_set(data, '{dynamic}', %s) WHERE id = %s", (Jsonb(_evidence(uri)), fid))
    assert f'href="/findings/{fid}/dynamic-evidence"' in client.get(f"/findings/{fid}").text
    r = client.get(f"/findings/{fid}/dynamic-evidence")
    assert r.status_code == 200
    assert r.text == '{"outcome": "reproduced"}'
    assert r.headers["content-type"].startswith("text/plain")
    assert client.get("/findings/999999/dynamic-evidence").status_code == 404

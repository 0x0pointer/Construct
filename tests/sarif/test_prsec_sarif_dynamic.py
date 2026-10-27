import json
import sys
from pathlib import Path

import jsonschema

sys.path.insert(0, str(Path(__file__).parent))
from _factories import finding, pr  # noqa: E402

from prsec.dynamic.poc import PoC  # noqa: E402
from prsec.dynamic.results import DynamicEvidence, ReplayResult  # noqa: E402
from prsec.sarif.builder import build_sarif  # noqa: E402

SCHEMA = json.loads((Path(__file__).parent / "sarif-schema-2.1.0.json").read_text())
POC = PoC(kind="http", hypothesis_id="H1", description="d", steps=[{"name": "s1", "path": "/x"}],
          oracles=[{"type": "canary_hit"}])


def _evidence(**kw) -> dict:
    ev = DynamicEvidence(
        hypothesis_id="H1", outcome="reproduced", reason="replay_confirmed", entry="http", head_runs=2, head_fired=2,
        base_ran=True, base_fired=False, poc=POC, evidence_uri="s3://prsec/evidence/acme/shop/7/x/dynamic_evidence.json",
        replays=[ReplayResult(run_id="r1", env_ok=True, fired=True)], **kw,
    )
    return ev.model_dump(mode="json", by_alias=True)


def _result(f):
    doc = build_sarif(pr(), 1, [f], {})
    jsonschema.Draft4Validator(SCHEMA).validate(json.loads(json.dumps(doc)))
    return doc["runs"][0]["results"][0]


def test_reproduced_finding_has_dynamic_summary():
    props = _result(finding(label="reproduced", introduced=True, dynamic=_evidence()))["properties"]
    assert props["label"] == "reproduced"
    assert props["introduced"] is True
    assert props["dynamic"] == {
        "outcome": "reproduced", "reason": "replay_confirmed", "entry": "http", "head_runs": 2, "head_fired": 2,
        "base_fired": False, "evidenceUri": "s3://prsec/evidence/acme/shop/7/x/dynamic_evidence.json",
    }


def test_summary_leaves_out_poc_and_replays():
    dyn = _result(finding(dynamic=_evidence()))["properties"]["dynamic"]
    assert "poc" not in dyn
    assert "replays" not in dyn


def test_no_dynamic_property_without_evidence():
    props = _result(finding())["properties"]
    assert "dynamic" not in props


def test_skipped_dynamic_is_summarised():
    skipped = DynamicEvidence(hypothesis_id="H1", outcome="skipped", reason="runner_unsupported").model_dump(mode="json")
    dyn = _result(finding(introduced=None, dynamic=skipped))["properties"]["dynamic"]
    assert dyn["outcome"] == "skipped"
    assert dyn["reason"] == "runner_unsupported"
    assert dyn["base_fired"] is None

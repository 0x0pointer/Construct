import json
import sys
from pathlib import Path

import jsonschema
import pytest

sys.path.insert(0, str(Path(__file__).parent))
from _factories import finding, pr  # noqa: E402

from prsec.models import CodeLoc  # noqa: E402
from prsec.sarif.builder import build_sarif  # noqa: E402

SCHEMA = json.loads((Path(__file__).parent / "sarif-schema-2.1.0.json").read_text())
META = {"skills_version": "2026.10.1", "harnesses": {"hypothesise": "codex", "static_verify": "claude-code"}}


def validate(doc):
    jsonschema.Draft4Validator(SCHEMA).validate(json.loads(json.dumps(doc)))


def test_full_document_validates():
    fs = [
        finding(),
        finding(bug_class="idor", severity="critical", label="reproduced", symbol="get_order",
                vuln_class="business_logic", evidence_uri="s3://prsec/evidence/1"),
        finding(severity="medium", symbol="list", label="inconclusive", source=None, path=[], remediation=None,
                sink=CodeLoc(file="app/orders.py", line=5)),
        finding(bug_class="info-leak", severity="info", symbol="debug", introduced=None, entry_point=None),
    ]
    doc = build_sarif(pr(), 99, fs, META)
    validate(doc)
    run = doc["runs"][0]
    assert doc["version"] == "2.1.0"
    assert run["tool"]["driver"]["name"] == "prsec"
    assert [r["id"] for r in run["tool"]["driver"]["rules"]] == ["idor", "info-leak", "sqli"]
    assert run["tool"]["driver"]["rules"][0]["properties"]["vuln_class"] == "business_logic"
    assert [r["level"] for r in run["results"]] == ["error", "error", "warning", "note"]
    for r in run["results"]:
        assert run["tool"]["driver"]["rules"][r["ruleIndex"]]["id"] == r["ruleId"]
    assert run["properties"] == {
        "scan_id": 99, "repo": "acme/shop", "pr": 7, "head_sha": "a" * 40, "base_sha": "b" * 40,
        "skills_version": "2026.10.1", "harnesses": META["harnesses"],
    }
    assert run["versionControlProvenance"][0] == {
        "repositoryUri": "https://github.com/acme/shop", "revisionId": "a" * 40, "branch": "feat/orders",
        "mappedTo": {"uriBaseId": "SRCROOT"},
    }


def test_result_mapping():
    f = finding()
    res = build_sarif(pr(), 1, [f], META)["runs"][0]["results"][0]
    assert res["ruleId"] == "sqli"
    assert res["partialFingerprints"] == {"prsec/v1": f.fingerprint}
    region = res["locations"][0]["physicalLocation"]["region"]
    assert region == {"startLine": 42, "endLine": 43, "snippet": {"text": "cur.execute(f'... {oid}')"}}
    flow = res["codeFlows"][0]["threadFlows"][0]["locations"]
    assert [l["location"]["physicalLocation"]["artifactLocation"]["uri"] for l in flow] == [
        "app/api.py", "app/svc.py", "app/orders.py"]
    assert [l["kinds"] for l in flow] == [["source"], ["taint"], ["sink"]]
    p = res["properties"]
    assert p["label"] == "likely" and p["severity"] == "high" and p["introduced"] is True
    assert p["entry_point"] == "GET /orders/{id}" and p["hypothesis_id"] == "H1"
    assert p["provenance"]["static_verify"]["harness"] == "claude-code"
    assert "evidenceUri" in p and "label_reason" in p


def test_no_flow_without_source_or_path():
    res = build_sarif(pr(), 1, [finding(source=None, path=[])], META)["runs"][0]["results"][0]
    assert "codeFlows" not in res


def test_empty_scan_validates():
    doc = build_sarif(pr(scm="gitlab", url="https://gitlab.example.com/g/p/-/merge_requests/3"), 1, [], {})
    validate(doc)
    assert doc["runs"][0]["results"] == [] and doc["runs"][0]["tool"]["driver"]["rules"] == []


@pytest.mark.parametrize("sev,level", [("critical", "error"), ("high", "error"), ("medium", "warning"),
                                       ("low", "note"), ("info", "note")])
def test_levels(sev, level):
    assert build_sarif(pr(), 1, [finding(severity=sev)], {})["runs"][0]["results"][0]["level"] == level


def test_artifact_uris_are_percent_encoded():
    f = finding(sink=CodeLoc(file="src/my dir/a#b%c?d.py", line=3), source=CodeLoc(file="/src/ü.py", line=1), path=[])
    doc = build_sarif(pr(), 1, [f], {})
    validate(doc)
    res = doc["runs"][0]["results"][0]
    assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/my%20dir/a%23b%25c%3Fd.py"
    flow = res["codeFlows"][0]["threadFlows"][0]["locations"]
    assert flow[0]["location"]["physicalLocation"]["artifactLocation"]["uri"] == "src/%C3%BC.py"


def test_incomplete_scan_is_marked_unsuccessful():
    doc = build_sarif(pr(), 1, [], {"complete": False, "errors": ["hypothesise stage timeout"]})
    validate(doc)
    [inv] = doc["runs"][0]["invocations"]
    assert inv["executionSuccessful"] is False
    assert inv["toolExecutionNotifications"][0]["message"]["text"] == "hypothesise stage timeout"
    assert build_sarif(pr(), 1, [], {})["runs"][0]["invocations"] == [{"executionSuccessful": True}]

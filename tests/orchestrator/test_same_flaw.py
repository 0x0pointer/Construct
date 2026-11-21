"""One flaw, several framings: hypotheses at the same sink line and entry point (an SQL injection and the
tenancy bypass it allows, filed as idor) get one dynamic attempt and end up as one finding."""
from prsec.dynamic.results import DynamicEvidence
from prsec.models import CodeLoc, Finding, Label, ScanStatus, Severity
from prsec.orchestrator import pipeline

from .test_dynamic import dyn, dyn_out, dyn_script, finding  # noqa: F401  (dyn is a fixture)
from .test_pipeline import ROW, hyp, only, static
from .test_pipeline import env  # noqa: F401  (fixture)


def f(hid, bug_class, label=Label.likely, severity=Severity.high, line=10, entry="GET /orders/1"):
    return Finding(fingerprint=f"fp-{bug_class}-{line}-{entry}", scan_id=1, repo="a/b", pr=1, head_sha="h",
                   hypothesis_id=hid, vuln_class="technical", bug_class=bug_class, title=f"{bug_class} title",
                   description="d", label=label, label_reason="r", severity=severity,
                   sink=CodeLoc(file="./app.py", line=line), entry_point=entry)


def test_same_sink_and_entry_point_merge_across_classes():
    [kept] = pipeline._dedupe([f("H1", "sqli", Label.reproduced), f("H2", "idor", Label.reproduced, entry="get /orders/2")])
    assert (kept.hypothesis_id, kept.bug_class) == ("H1", "sqli")  # tie: the earlier hypothesis
    assert kept.provenance["merged"] == [{"hypothesis_id": "H2", "bug_class": "idor", "title": "idor title",
                                          "label": "reproduced"}]


def test_stronger_evidence_wins_the_merge():
    [kept] = pipeline._dedupe([f("H1", "sqli", Label.likely), f("H2", "idor", Label.reproduced)])
    assert kept.hypothesis_id == "H2"
    assert [m["hypothesis_id"] for m in kept.provenance["merged"]] == ["H1"]


def test_other_line_or_entry_point_stays_separate():
    out = pipeline._dedupe([f("H1", "sqli"), f("H2", "idor", line=11), f("H3", "xss", entry="POST /orders")])
    assert sorted(x.hypothesis_id for x in out) == ["H1", "H2", "H3"]
    assert all("merged" not in x.provenance for x in out)


def test_one_dynamic_attempt_per_flaw_and_one_finding(dyn):  # noqa: F811
    tenancy = {**hyp("H2"), "bug_class": "idor", "title": "injection bypasses the user_id filter"}
    s = dyn(script=dyn_script(out=dyn_out()), replay=lambda req, spec: not req.run_id.endswith("-base"))
    s["runner"].script["hypothesise"] = lambda t: {"summary": "s", "hypotheses": [hyp("H1"), tenancy]}
    s["runner"].script["static_verify"] = lambda t: static(t.task_id.rsplit("-", 1)[1])
    pipeline.run_scan(ROW)
    assert only(s["q"])["status"] == ScanStatus.done
    dynamic_tasks = [sp.task.task_id for sp in s["runner"].specs if sp.task.stage.value == "dynamic" and sp.mode == "stage"]
    assert dynamic_tasks == ["101-dynamic-H1"]  # H2 is the same flaw: no second attempt
    fd = finding(s)
    assert (fd.hypothesis_id, fd.bug_class, fd.label) == ("H1", "sqli", Label.reproduced)
    assert fd.provenance["merged"][0]["bug_class"] == "idor"
    assert DynamicEvidence.model_validate(fd.dynamic).outcome == "reproduced"

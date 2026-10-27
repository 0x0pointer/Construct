import itertools

import pytest

from prsec.models import Label
from prsec.orchestrator.verdict import decide, drop_reason, needs_skeptic
from prsec.stages.outputs import Citation, Hypothesis, SkepticOutput, StaticVerifyOutput

CIT = Citation(file="a.py", line=1, quote="x = 1")
HYP = Hypothesis(
    id="H1", vuln_class="technical", bug_class="sqli", title="t", description="d", entry_point="GET /x",
    sink=CIT, impact="i", severity_guess="high", introduced_by_diff=True,
)


def static(verdict: str, reachable: str, hid: str = "H1") -> StaticVerifyOutput:
    return StaticVerifyOutput(hypothesis_id=hid, verdict=verdict, reachable=reachable, reasoning="r", citations=[CIT], severity="high")


def skeptic(refuted: bool) -> SkepticOutput:
    return SkepticOutput(hypothesis_id="H1", refuted=refuted, confidence="medium", reasoning="r")


def expected(v, reach, sk, cit_err):
    if cit_err:
        return Label.inconclusive, "citations_unverified"
    if v == "refuted":
        return Label.inconclusive, "static_refuted"
    if sk is True:
        return Label.inconclusive, "skeptic_refuted"
    if v == "plausible":
        return Label.inconclusive, "plausible_static_only"
    if reach == "no":
        return Label.inconclusive, "unreachable"
    if reach == "unknown":
        return Label.inconclusive, "reachability_unknown"
    if sk is None:
        return Label.inconclusive, "skeptic_unavailable"
    return Label.likely, "confirmed_static_reachable_skeptic_upheld"


CASES = list(itertools.product(["refuted", "plausible", "confirmed_static"], ["yes", "no", "unknown"], [None, False, True], [False, True]))


@pytest.mark.parametrize("v,reach,sk,cit_err", CASES)
def test_truth_table(v, reach, sk, cit_err):
    got = decide(HYP, static(v, reach), None if sk is None else skeptic(sk), ["bad"] if cit_err else [])
    assert got == expected(v, reach, sk, cit_err)
    assert got[0] != Label.reproduced


def test_exactly_one_likely_row():
    likely = [c for c in CASES if expected(*c)[0] == Label.likely]
    assert likely == [("confirmed_static", "yes", False, False)]


def test_no_static():
    assert decide(HYP, None, skeptic(False), []) == (Label.inconclusive, "static_verify_unavailable")


def test_hypothesis_mismatch():
    assert decide(HYP, static("confirmed_static", "yes", hid="H9"), skeptic(False), [])[1] == "static_hypothesis_mismatch"


def test_drop_and_skeptic_gating():
    assert drop_reason(static("refuted", "yes"), []) == "static_refuted"
    assert drop_reason(static("plausible", "yes"), ["e"]) == "static_citations_unverified"
    assert drop_reason(None, []) is None
    assert drop_reason(static("plausible", "unknown"), []) is None
    assert not needs_skeptic(static("plausible", "unknown"), [])
    assert not needs_skeptic(static("confirmed_static", "no"), [])
    assert not needs_skeptic(static("confirmed_static", "yes", hid="H9"), [], HYP)
    assert needs_skeptic(static("confirmed_static", "yes"), [], HYP)
    assert needs_skeptic(static("confirmed_static", "yes"), [])
    assert not needs_skeptic(static("refuted", "yes"), [])
    assert not needs_skeptic(None, [])


@pytest.mark.parametrize("v,reach,hid", list(itertools.product(
    ["confirmed_static", "plausible", "refuted"], ["yes", "no", "unknown"], ["H1", "H2"])))
def test_skeptic_skipped_only_when_it_cannot_change_the_label(v, reach, hid):
    st = static(v, reach, hid)
    labels = {decide(HYP, st, sk, [])[0] for sk in (None, skeptic(True), skeptic(False))}
    if not needs_skeptic(st, [], HYP):
        assert labels == {Label.inconclusive}
    else:
        assert labels == {Label.inconclusive, Label.likely}

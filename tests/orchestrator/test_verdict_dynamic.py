"""Phase-2 label table (docs/design/phase2-dynamic.md, "Labels") as an exhaustive truth table."""
import itertools

import pytest

from prsec.dynamic.results import DynamicEvidence
from prsec.models import Label
from prsec.orchestrator.verdict import decide, introduced
from prsec.stages.outputs import Citation, Hypothesis, SkepticOutput, StaticVerifyOutput

CIT = Citation(file="a.py", line=1, quote="x = 1")
HYP = Hypothesis(
    id="H1", vuln_class="technical", bug_class="sqli", title="t", description="d", entry_point="GET /x",
    sink=CIT, impact="i", severity_guess="high", introduced_by_diff=True,
)

# name -> DynamicEvidence (None = dynamic did not run for this hypothesis)
DYN = {
    "none": None,
    "confirmed_http": DynamicEvidence(hypothesis_id="H1", outcome="reproduced", entry="http", head_runs=2, head_fired=2),
    "confirmed_script": DynamicEvidence(hypothesis_id="H1", outcome="reproduced", entry="script", head_runs=2, head_fired=2),
    "one_run_only": DynamicEvidence(hypothesis_id="H1", outcome="not_reproduced", entry="http", head_runs=1, head_fired=1),
    "flaky": DynamicEvidence(hypothesis_id="H1", outcome="not_reproduced", entry="http", head_runs=2, head_fired=1),
    "not_reproduced": DynamicEvidence(hypothesis_id="H1", outcome="not_reproduced"),
    "env_failed": DynamicEvidence(hypothesis_id="H1", outcome="env_failed"),
    "error": DynamicEvidence(hypothesis_id="H1", outcome="error"),
    "skipped": DynamicEvidence(hypothesis_id="H1", outcome="skipped", reason="runner_unsupported"),
}
CONFIRMED = {"confirmed_http", "confirmed_script"}


def static(verdict: str, reachable: str) -> StaticVerifyOutput:
    return StaticVerifyOutput(hypothesis_id="H1", verdict=verdict, reachable=reachable, reasoning="r",
                              citations=[CIT], severity="high")


def skeptic(refuted: bool) -> SkepticOutput:
    return SkepticOutput(hypothesis_id="H1", refuted=refuted, confidence="medium", reasoning="r")


def phase1(v, reach, sk, cit_err):
    if cit_err:
        return Label.inconclusive, "citations_unverified"
    if v == "refuted":
        return Label.inconclusive, "static_refuted"
    if sk is True:
        return Label.inconclusive, "skeptic_refuted"
    if v == "plausible":
        return Label.inconclusive, "plausible_static_only"
    if reach != "yes":
        return Label.inconclusive, {"no": "unreachable", "unknown": "reachability_unknown"}[reach]
    if sk is None:
        return Label.inconclusive, "skeptic_unavailable"
    return Label.likely, "confirmed_static_reachable_skeptic_upheld"


def suffix(reason, dyn):
    ev = DYN[dyn]
    return reason if ev is None or ev.outcome == "skipped" else f"{reason}; dynamic={ev.outcome}"


def expected(v, reach, sk, cit_err, dyn):
    blocked = cit_err or v == "refuted"
    if dyn in CONFIRMED and not blocked:
        if dyn == "confirmed_script":
            return Label.likely, "replay_confirmed_direct_call"
        if reach != "yes":
            return Label.likely, f"replay_confirmed_reachability_{reach}"
        return Label.reproduced, "replay_confirmed"
    label, reason = phase1(v, reach, sk, cit_err)
    return (label, suffix(reason, dyn)) if label == Label.inconclusive else (label, reason)


CASES = list(itertools.product(
    ["refuted", "plausible", "confirmed_static"], ["yes", "no", "unknown"], [None, False, True], [False, True], list(DYN),
))


@pytest.mark.parametrize("v,reach,sk,cit_err,dyn", CASES)
def test_truth_table(v, reach, sk, cit_err, dyn):
    got = decide(HYP, static(v, reach), None if sk is None else skeptic(sk), ["bad"] if cit_err else [], DYN[dyn])
    assert got == expected(v, reach, sk, cit_err, dyn)


def test_reproduced_rows():
    rows = {(v, reach, cit) for v, reach, _, cit, dyn in CASES if expected(v, reach, None, cit, dyn)[0] == Label.reproduced}
    assert rows == {("plausible", "yes", False), ("confirmed_static", "yes", False)}


def test_skeptic_does_not_block_reproduced():
    got = decide(HYP, static("confirmed_static", "yes"), skeptic(True), [], DYN["confirmed_http"])
    assert got == (Label.reproduced, "replay_confirmed")


@pytest.mark.parametrize("dyn", [d for d in DYN if d not in CONFIRMED])
def test_unconfirmed_dynamic_never_downgrades_likely(dyn):
    got = decide(HYP, static("confirmed_static", "yes"), skeptic(False), [], DYN[dyn])
    assert got == (Label.likely, "confirmed_static_reachable_skeptic_upheld")


def test_no_static_records_dynamic_outcome():
    got = decide(HYP, None, None, [], DYN["confirmed_http"])
    assert got == (Label.inconclusive, "static_verify_unavailable; dynamic=reproduced")


def test_hypothesis_mismatch_blocks_replay():
    other = static("confirmed_static", "yes").model_copy(update={"hypothesis_id": "H9"})
    got = decide(HYP, other, skeptic(False), [], DYN["confirmed_http"])
    assert got == (Label.inconclusive, "static_hypothesis_mismatch; dynamic=reproduced")


def _ev(**kw) -> DynamicEvidence:
    return DynamicEvidence(hypothesis_id="H1", outcome="reproduced", entry="http", head_runs=2, head_fired=2, **kw)


@pytest.mark.parametrize("ev,want", [
    (None, None),
    (_ev(), None),  # no base replay
    (_ev(base_ran=False, base_fired=None), None),  # base env failed
    (_ev(base_ran=True, base_fired=True), False),  # fires on base: pre-existing
    (_ev(base_ran=True, base_fired=False), True),  # only head: introduced by the PR
    (_ev(base_ran=True, base_fired=None), None),
])
def test_introduced(ev, want):
    assert introduced(ev) is want

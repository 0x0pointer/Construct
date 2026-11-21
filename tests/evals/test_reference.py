"""prsec.evals.reference: judging a reference replay's evidence (the replay itself needs a runner: -m docker / -m k8s)."""
from prsec.dynamic.results import DynamicEvidence
from prsec.evals.cases import list_cases
from prsec.evals.reference import hypothesis, problems


def ev(**kw) -> DynamicEvidence:
    base = dict(hypothesis_id="H1", outcome="reproduced", entry="http", head_runs=2, head_fired=2, base_ran=True,
                base_fired=False)
    return DynamicEvidence(**{**base, **kw})


def test_clean_reference_has_no_problems():
    assert problems(ev(), 2) == []


def test_problems_are_named():
    assert problems(ev(base_fired=True), 2) == ["fired on base"]
    assert problems(ev(base_ran=False, base_fired=None), 2) == ["base replay did not run"]
    assert problems(ev(outcome="not_reproduced", reason="replay fired 1/2", head_fired=1), 2) == [
        "outcome not_reproduced (replay fired 1/2)", "head fired 1/2 of 2"]
    assert problems(ev(entry="script"), 2) == ["entry script"]


def test_hypothesis_cites_the_expected_sink():
    case = next(c for c in list_cases() if c.id == "ssrf-webhook-test")
    h = hypothesis(case)
    assert (h.id, h.bug_class, h.sink.file, h.sink.line) == ("H1", "ssrf", "app.py", 70)
    assert h.sink.quote.strip() == "try:"

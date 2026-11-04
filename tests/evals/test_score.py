"""prsec.evals.score (pure scoring) and the SARIF -> Reported mapping of prsec.evals.run."""
import pytest

from prsec.evals.cases import list_cases
from prsec.evals.run import _reported, aliases, select
from prsec.evals.score import Observed, Reported, render_markdown, score_case, summarize
from prsec.models import CodeLoc, Finding, Label, PRInfo, Severity
from prsec.sarif.builder import build_sarif

CASES = {c.id: c for c in list_cases()}
ALIASES = aliases()


def ssrf(**kw) -> Reported:
    base = dict(bug_class="ssrf", file="app.py", line=71, label="reproduced", severity="high", hypothesis_id="H1",
                introduced=True, static_verdict="confirmed_static", dynamic="reproduced")
    return Reported(**{**base, **kw})


def obs(*findings, triage="full", status="done", **kw) -> Observed:
    return Observed(scan_id=1, status=status, triage=triage, findings=list(findings), **kw)


def failed(score) -> dict[str, str]:
    return {c.name: c.detail for c in score.checks if not c.ok}


def test_perfect_reproduced_finding_passes():
    s = score_case(CASES["ssrf-webhook-test"], obs(ssrf()), ALIASES)
    assert s.passed, failed(s)
    assert (s.tp, s.fp, s.fn, s.reproduced, s.expected_reproducible) == (1, 0, 0, 1, 1)


def test_likely_is_acceptable_but_not_counted_as_reproduced():
    s = score_case(CASES["ssrf-webhook-test"], obs(ssrf(label="likely", introduced=None, dynamic="not_reproduced")),
                   ALIASES)
    assert s.passed, failed(s)
    assert s.reproduced == 0


def test_missing_finding_is_a_false_negative():
    s = score_case(CASES["ssrf-webhook-test"], obs(), ALIASES)
    assert not s.passed
    assert s.fn == 1
    assert "not reported at app.py:70-72" in failed(s)["finding[0] ssrf"]


def test_sink_outside_the_expected_lines_does_not_match():
    s = score_case(CASES["ssrf-webhook-test"], obs(ssrf(line=40)), ALIASES)
    assert (s.tp, s.fp, s.fn) == (0, 1, 1)


def test_false_positive_names_the_must_not_find_entry():
    s = score_case(CASES["ssrf-webhook-test"], obs(ssrf(), ssrf(bug_class="sqli", line=30, hypothesis_id="H2")),
                   ALIASES)
    assert not s.passed
    assert s.fp == 1
    assert "every query binds its values" in failed(s)["false positive sqli"]


def test_alias_matches_canonical_class():
    s = score_case(CASES["ssrf-webhook-test"], obs(ssrf(bug_class="server-side-request-forgery")), ALIASES)
    assert s.passed, failed(s)


def test_wrong_label_verdict_severity_and_introduced_fail():
    s = score_case(CASES["ssrf-webhook-test"],
                   obs(ssrf(label="inconclusive", static_verdict="refuted", severity="low", introduced=False)), ALIASES)
    assert set(failed(s)) == {"finding[0] ssrf label", "finding[0] ssrf static verdict", "finding[0] ssrf severity",
                              "finding[0] ssrf introduced"}


def test_triage_and_scan_status():
    s = score_case(CASES["css-only"], obs(triage="skip", status="skipped"), ALIASES)
    assert s.passed, failed(s)
    s = score_case(CASES["css-only"], obs(triage="full", status="failed", error="boom"), ALIASES)
    assert set(failed(s)) == {"scan", "triage"}
    assert "boom" in failed(s)["scan"]


def test_refutation_must_drop_every_raised_hypothesis_of_the_class():
    case = CASES["sqli-parameterised"]
    ok = score_case(case, obs(hypotheses={"H1": "sqli", "H2": "idor"}, dropped={"H1": "static_refuted"}), ALIASES)
    assert ok.passed, failed(ok)
    bad = score_case(case, obs(hypotheses={"H1": "sql-injection"}), ALIASES)
    assert "refutation sqli" in failed(bad)
    quiet = score_case(case, obs(), ALIASES)
    assert quiet.passed, failed(quiet)


def test_summary_and_markdown():
    a = score_case(CASES["ssrf-webhook-test"], obs(ssrf()), ALIASES)
    b = score_case(CASES["idor-two-users"], obs(), ALIASES)
    summary = summarize([a, b])
    assert (summary["passed"], summary["tp"], summary["fn"], summary["precision"], summary["recall"]) == (1, 1, 1, 1.0, 0.5)
    assert summary["by_class"] == {"idor": {"tp": 0, "fp": 0, "fn": 1}, "ssrf": {"tp": 1, "fp": 0, "fn": 0}}
    md = render_markdown([a, b], summary, {"run": "r1", "policy": "policy-spark.yaml"})
    assert "**1/2 cases passed**" in md
    assert "| idor-two-users | 1 | FAIL |" in md
    assert "## Failed checks" in md


def test_sarif_result_round_trips_to_reported():
    pr = PRInfo(repo="evals/ssrf-webhook-test", number=5, title="t", base_ref="main", base_sha="b" * 40,
                head_ref="f", head_sha="a" * 40)
    f = Finding(fingerprint="fp", scan_id=1, repo=pr.repo, pr=5, head_sha=pr.head_sha, hypothesis_id="H1",
                vuln_class="technical", bug_class="ssrf", title="SSRF", description="d", label=Label.reproduced,
                label_reason="replay_confirmed", severity=Severity.high, introduced=True,
                sink=CodeLoc(file="src/web hooks.py", line=71), dynamic={"outcome": "reproduced"})
    [res] = build_sarif(pr, 1, [f], {})["runs"][0]["results"]
    r = _reported(res, {"H1": "confirmed_static"})
    assert (r.bug_class, r.file, r.line, r.label, r.severity) == ("ssrf", "src/web hooks.py", 71, "reproduced", "high")
    assert (r.introduced, r.static_verdict, r.dynamic) == (True, "confirmed_static", "reproduced")


def test_select_filters_by_id_and_tag():
    cases = list_cases()
    assert {c.id for c in select(cases, [], "dynamic")} == {"idor-two-users", "negative-quantity", "ssrf-webhook-test"}
    assert [c.id for c in select(cases, ["css-only"], None)] == ["css-only"]
    with pytest.raises(SystemExit):
        select(cases, ["nope"], None)


def test_rules_arms_scored_but_not_part_of_pass_fail():
    from prsec.evals.score import rules_expected

    assert rules_expected(CASES["css-only"].expected) == "skip"
    assert rules_expected(CASES["ssrf-webhook-test"].expected) == "scan"
    assert rules_expected({"triage": {"acceptable": ["skip", "light"]}}) is None
    css = score_case(CASES["css-only"], obs(triage="skip", status="skipped", rules={"primary": "skip", "jev": "scan"}),
                     ALIASES)
    assert css.passed  # the shadow's wrong call does not fail the case
    assert css.rules == {"primary": True, "jev": False}
    ssrf_ok = score_case(CASES["ssrf-webhook-test"], obs(ssrf(), rules={"primary": "scan", "jev": None}), ALIASES)
    assert ssrf_ok.rules == {"primary": True, "jev": None}
    summary = summarize([css, ssrf_ok])
    assert summary["rules"] == {"primary": {"right": 2, "wrong": 0, "none": 0},
                                "jev": {"right": 0, "wrong": 1, "none": 1}}
    md = render_markdown([css, ssrf_ok], summary, {})
    assert "| jev | 0 | 1 | 1 |" in md
    assert "Wrong calls: jev on css-only" in md


def test_rules_arms_read_from_scanned_and_skipped_records():
    from prsec.evals.run import _rules_arms

    shadows = [{"name": "jev", "decision": "skip"}]
    scanned = {"triage": {"decision": "full", "rules": {"decision": "scan", "shadows": shadows}}}
    skipped = {"triage": {"decision": "skip", "source": "rules", "rules": {"decision": "skip"}}}
    assert _rules_arms(scanned) == {"primary": "scan", "jev": "skip"}
    assert _rules_arms(skipped) == {"primary": "skip"}
    assert _rules_arms({"triage": None}) == {}

"""Score one scan of an eval case against its expected.json (see prsec-skills/evals/README.md).

Matching rule: a reported finding matches an expectation when the bug class (after alias
normalisation via bug-classes.yaml) and the sink file are equal and, if the expectation gives
`sink_lines`, the reported sink line is inside them. Every reported finding that matches no
expected finding is a false positive (named after the `must_not_find` entry it hits, if any).

Pure functions over `Observed` (what the scan produced); `prsec.evals.run` gathers it from the
database and the scan's SARIF.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from prsec.evals.cases import Case

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
FINAL_STATUSES = ("done", "skipped", "failed", "superseded")
REPRODUCED = "reproduced"


@dataclass
class Reported:
    """One finding of the scan (a SARIF result plus its timeline facts)."""

    bug_class: str
    file: str
    line: int
    label: str
    severity: str
    hypothesis_id: str = ""
    introduced: bool | None = None
    static_verdict: str | None = None
    dynamic: str | None = None  # DynamicEvidence.outcome when the dynamic phase ran


@dataclass
class Observed:
    """What one eval scan produced."""

    scan_id: int
    status: str
    triage: str | None = None
    findings: list[Reported] = field(default_factory=list)
    hypotheses: dict[str, str] = field(default_factory=dict)  # id -> bug_class, everything hypothesise raised
    dropped: dict[str, str] = field(default_factory=dict)  # id -> drop reason
    dynamic: dict[str, str] = field(default_factory=dict)  # hypothesis id -> dynamic outcome
    rules: dict[str, str | None] = field(default_factory=dict)  # rules arm -> skip|scan ("primary" + shadow arms)
    error: str | None = None
    cost_usd: float = 0.0
    duration_s: float | None = None


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class CaseScore:
    case_id: str
    scan_id: int
    passed: bool
    checks: list[Check]
    tp: int = 0
    fn: int = 0
    fp: int = 0
    expected_reproducible: int = 0  # expected findings that list `reproduced` as an acceptable label
    reproduced: int = 0  # ... and came out `reproduced`
    by_class: dict[str, dict[str, int]] = field(default_factory=dict)  # bug_class -> {tp, fp, fn}
    rules: dict[str, bool | None] = field(default_factory=dict)  # rules arm -> right skip/scan call (None: no decision)
    cost_usd: float = 0.0
    duration_s: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def canonical(bug_class: str, aliases: dict[str, str]) -> str:
    key = (bug_class or "").strip().lower()
    return aliases.get(key, key)


def _path(p: str) -> str:
    p = (p or "").replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p.lstrip("/")


def matches(exp: dict[str, Any], f: Reported, aliases: dict[str, str]) -> bool:
    if canonical(exp["bug_class"], aliases) != canonical(f.bug_class, aliases):
        return False
    if exp.get("sink_file") and _path(exp["sink_file"]) != _path(f.file):
        return False
    lines = exp.get("sink_lines")
    return not lines or lines[0] <= f.line <= lines[1]


def _where(exp: dict[str, Any]) -> str:
    lines = exp.get("sink_lines")
    return f"{exp.get('sink_file', '?')}" + (f":{lines[0]}-{lines[1]}" if lines else "")


def _tally(by_class: dict[str, dict[str, int]], bug_class: str, key: str) -> None:
    by_class.setdefault(bug_class, {"tp": 0, "fp": 0, "fn": 0})[key] += 1


def _finding_checks(exp: dict[str, Any], f: Reported, n: int) -> list[Check]:
    """Label, static verdict, severity and `introduced` of a matched finding."""
    tag = f"finding[{n}] {exp['bug_class']}"
    checks = [Check(f"{tag} label", f.label in exp.get("labels", [f.label]),
                    f"{f.label} (acceptable: {', '.join(exp.get('labels', []))})")]
    verdicts = exp.get("static_verdicts")
    if verdicts and f.static_verdict is not None:
        checks.append(Check(f"{tag} static verdict", f.static_verdict in verdicts,
                            f"{f.static_verdict} (acceptable: {', '.join(verdicts)})"))
    if exp.get("min_severity"):
        ok = SEVERITY_RANK.get(f.severity, -1) >= SEVERITY_RANK.get(exp["min_severity"], 0)
        checks.append(Check(f"{tag} severity", ok, f"{f.severity} (minimum {exp['min_severity']})"))
    if "introduced" in exp and f.introduced is not None:
        checks.append(Check(f"{tag} introduced", f.introduced == exp["introduced"],
                            f"{f.introduced} (expected {exp['introduced']})"))
    return checks


def score_case(case: Case, obs: Observed, aliases: dict[str, str]) -> CaseScore:
    exp = case.expected
    s = CaseScore(case_id=case.id, scan_id=obs.scan_id, passed=False, checks=[], cost_usd=obs.cost_usd,
                  duration_s=obs.duration_s)
    if obs.status not in ("done", "skipped"):
        s.checks.append(Check("scan", False, f"status {obs.status}" + (f": {obs.error}" if obs.error else "")))
    acceptable = (exp.get("triage") or {}).get("acceptable") or []
    s.checks.append(Check("triage", obs.triage in acceptable, f"{obs.triage} (acceptable: {', '.join(acceptable)})"))
    remaining = _score_expected(s, exp, list(obs.findings), aliases)
    _score_false_positives(s, exp, remaining, aliases)
    s.checks.extend(_refutation_checks(exp, obs, aliases))
    want = rules_expected(exp)
    s.rules = {arm: (None if got is None or want is None else got == want) for arm, got in obs.rules.items()}
    s.passed = all(c.ok for c in s.checks)  # rules arms are reported, never part of pass/fail
    return s


def _score_expected(s: CaseScore, exp: dict[str, Any], findings: list[Reported], aliases: dict[str, str]) -> list[Reported]:
    """Match every expected finding (TP / FN and its field checks); returns the findings nothing matched."""
    remaining = list(findings)
    for n, e in enumerate(exp.get("expected_findings") or []):
        cls = canonical(e["bug_class"], aliases)
        reproducible = REPRODUCED in e.get("labels", [])
        s.expected_reproducible += int(reproducible)
        hit = next((f for f in remaining if matches(e, f, aliases)), None)
        if hit is None:
            s.fn += 1
            _tally(s.by_class, cls, "fn")
            s.checks.append(Check(f"finding[{n}] {e['bug_class']}", False, f"not reported at {_where(e)}"))
            continue
        remaining.remove(hit)
        s.tp += 1
        _tally(s.by_class, cls, "tp")
        s.reproduced += int(reproducible and hit.label == REPRODUCED)
        s.checks.append(Check(f"finding[{n}] {e['bug_class']}", True, f"{hit.hypothesis_id} at {hit.file}:{hit.line}"))
        s.checks.extend(_finding_checks(e, hit, n))
    return remaining


def _score_false_positives(s: CaseScore, exp: dict[str, Any], remaining: list[Reported], aliases: dict[str, str]) -> None:
    for f in remaining:
        s.fp += 1
        _tally(s.by_class, canonical(f.bug_class, aliases), "fp")
        named = next((m for m in exp.get("must_not_find") or [] if matches(m, f, aliases)), None)
        why = f"must_not_find: {named['reason']}" if named else "matches no expected finding"
        s.checks.append(Check(f"false positive {f.bug_class}", False,
                              f"{f.hypothesis_id} at {f.file}:{f.line}, label {f.label}: {why}"))


def _refutation_checks(exp: dict[str, Any], obs: Observed, aliases: dict[str, str]) -> list[Check]:
    """Every hypothesis raised in an expected-refutation class must have been dropped."""
    checks = []
    for r in exp.get("expected_refutations") or []:
        cls = canonical(r["bug_class"], aliases)
        raised = sorted(h for h, c in obs.hypotheses.items() if canonical(c, aliases) == cls)
        survived = [h for h in raised if h not in obs.dropped]
        dropped = ", ".join(f"{h} ({obs.dropped[h]})" for h in raised if h in obs.dropped) or "none"
        detail = f"raised {', '.join(raised)}; dropped: {dropped}" if raised else "not raised (fine: nothing to refute)"
        checks.append(Check(f"refutation {r['bug_class']}", not survived, detail))
    return checks


def rules_expected(exp: dict[str, Any]) -> str | None:
    """The right rules call for a case: skip when triage may only skip, scan when it may not skip, else None."""
    acceptable = set((exp.get("triage") or {}).get("acceptable") or [])
    if acceptable == {"skip"}:
        return "skip"
    return "scan" if acceptable and "skip" not in acceptable else None


def _by_class(scores: list[CaseScore]) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for s in scores:
        for cls, t in s.by_class.items():
            agg = out.setdefault(cls, {"tp": 0, "fp": 0, "fn": 0})
            for k in agg:
                agg[k] += t[k]
    return dict(sorted(out.items()))


def _rules_bucket(ok: bool | None) -> str:
    if ok is None:
        return "none"
    return "right" if ok else "wrong"


def _rules_arms(scores: list[CaseScore]) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for s in scores:
        for arm, ok in s.rules.items():
            out.setdefault(arm, {"right": 0, "wrong": 0, "none": 0})[_rules_bucket(ok)] += 1
    return dict(sorted(out.items(), key=lambda kv: (kv[0] != "primary", kv[0])))


def _ratio(num: int, den: int) -> float | None:
    return round(num / den, 3) if den else None


def summarize(scores: list[CaseScore]) -> dict[str, Any]:
    tp, fp, fn = (sum(getattr(s, k) for s in scores) for k in ("tp", "fp", "fn"))
    return {
        "cases": len(scores),
        "passed": sum(s.passed for s in scores),
        "tp": tp, "fp": fp, "fn": fn,
        "precision": _ratio(tp, tp + fp),
        "recall": _ratio(tp, tp + fn),
        "reproduced": sum(s.reproduced for s in scores),
        "expected_reproducible": sum(s.expected_reproducible for s in scores),
        "by_class": _by_class(scores),
        "rules": _rules_arms(scores),
        "cost_usd": round(sum(s.cost_usd for s in scores), 4),
        "duration_s": round(sum(s.duration_s or 0 for s in scores), 1),
    }


def _pct(v: float | None) -> str:
    return "n/a" if v is None else f"{v:.0%}"


def _md_header(summary: dict[str, Any], meta: dict[str, Any]) -> list[str]:
    out = [f"# Eval run {meta.get('run', '')}".rstrip(), ""]
    out += [f"- **{k}:** {meta[k]}" for k in ("policy", "skills_version", "runner", "started_at") if meta.get(k)]
    return out + [
        "",
        f"**{summary['passed']}/{summary['cases']} cases passed** · precision {_pct(summary['precision'])} · "
        f"recall {_pct(summary['recall'])} · reproduced {summary['reproduced']}/{summary['expected_reproducible']} · "
        f"cost ${summary['cost_usd']:.2f} · {summary['duration_s'] / 60:.0f} min",
    ]


def _md_cases(scores: list[CaseScore]) -> list[str]:
    out = ["", "| Case | Scan | Result | TP | FP | FN | Reproduced | Minutes |", "|---|---|---|---|---|---|---|---|"]
    for s in scores:
        mins = f"{s.duration_s / 60:.1f}" if s.duration_s is not None else "?"
        out.append(f"| {s.case_id} | {s.scan_id} | {'pass' if s.passed else 'FAIL'} | {s.tp} | {s.fp} | {s.fn} | "
                   f"{s.reproduced}/{s.expected_reproducible} | {mins} |")
    failed = [s for s in scores if not s.passed]
    if failed:
        out += ["", "## Failed checks", ""]
        for s in failed:
            out += [f"**{s.case_id}** (scan {s.scan_id})", *[f"- {c.name}: {c.detail}" for c in s.checks if not c.ok], ""]
    return out


def _md_rules(scores: list[CaseScore], rules: dict[str, dict[str, int]]) -> list[str]:
    if not rules:
        return []
    out = ["", "## Rules arms (skip/scan call per case; shadow arms never decide)", "",
           "| Arm | Right | Wrong | No decision |", "|---|---|---|---|"]
    out += [f"| {arm} | {t['right']} | {t['wrong']} | {t['none']} |" for arm, t in rules.items()]
    wrong = [(s.case_id, arm) for s in scores for arm, ok in s.rules.items() if ok is False]
    if wrong:
        out += ["", "Wrong calls: " + ", ".join(f"{arm} on {cid}" for cid, arm in wrong)]
    return out


def _md_classes(by_class: dict[str, dict[str, int]]) -> list[str]:
    if not by_class:
        return []
    return ["", "## By bug class", "", "| Bug class | TP | FP | FN |", "|---|---|---|---|",
            *[f"| {cls} | {t['tp']} | {t['fp']} | {t['fn']} |" for cls, t in by_class.items()]]


def render_markdown(scores: list[CaseScore], summary: dict[str, Any], meta: dict[str, Any]) -> str:
    out = [*_md_header(summary, meta), *_md_cases(scores), *_md_rules(scores, summary.get("rules") or {}),
           *_md_classes(summary["by_class"])]
    return "\n".join(out).rstrip() + "\n"

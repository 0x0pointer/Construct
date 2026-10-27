"""Phase-1 verdict: deterministic rules over stage outputs. Never 'reproduced' without dynamic replay."""
from __future__ import annotations

from prsec.models import Label
from prsec.stages.outputs import Hypothesis, SkepticOutput, StaticVerifyOutput


def drop_reason(static: StaticVerifyOutput | None, citation_errors: list[str]) -> str | None:
    """Reason to drop a hypothesis entirely (not reported), or None to keep it."""
    if static is None:
        return None
    if static.verdict == "refuted":
        return "static_refuted"
    if citation_errors:
        return "static_citations_unverified"
    return None


def needs_skeptic(static: StaticVerifyOutput | None, citation_errors: list[str], hyp: Hypothesis | None = None) -> bool:
    """Only where the skeptic can still change the label: every other case is inconclusive regardless."""
    return (
        static is not None
        and drop_reason(static, citation_errors) is None
        and static.verdict == "confirmed_static"
        and static.reachable == "yes"
        and (hyp is None or static.hypothesis_id == hyp.id)
    )


def decide(
    hyp: Hypothesis,
    static: StaticVerifyOutput | None,
    skeptic: SkepticOutput | None,
    citation_errors: list[str],
) -> tuple[Label, str]:
    """Likely = confirmed_static AND reachable=yes AND citations verified AND skeptic ran and did not refute."""
    if static is None:
        return Label.inconclusive, "static_verify_unavailable"
    if static.hypothesis_id != hyp.id:
        return Label.inconclusive, "static_hypothesis_mismatch"
    if citation_errors:
        return Label.inconclusive, "citations_unverified"
    if static.verdict == "refuted":
        return Label.inconclusive, "static_refuted"
    if skeptic is not None and skeptic.refuted:
        return Label.inconclusive, "skeptic_refuted"
    if static.verdict == "plausible":
        return Label.inconclusive, "plausible_static_only"
    if static.reachable == "no":
        return Label.inconclusive, "unreachable"
    if static.reachable == "unknown":
        return Label.inconclusive, "reachability_unknown"
    if skeptic is None:
        return Label.inconclusive, "skeptic_unavailable"
    return Label.likely, "confirmed_static_reachable_skeptic_upheld"

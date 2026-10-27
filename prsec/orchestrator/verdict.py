"""Verdict: deterministic rules over stage outputs and, in phase 2, the agent-free replay evidence.

'reproduced' needs a confirmed replay (every head replay fired, at least two) through a real HTTP
entry point on a hypothesis static verification kept and found reachable. Dynamic results only
ever add proof: `not_reproduced` never lowers a static label (absence of proof is not proof).
"""
from __future__ import annotations

from prsec.dynamic.results import DynamicEvidence
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


def _static_gate(hyp: Hypothesis, static: StaticVerifyOutput | None, citation_errors: list[str]) -> str | None:
    """Reason the static record cannot back any label above inconclusive (dynamic proof included)."""
    if static is None:
        return "static_verify_unavailable"
    if static.hypothesis_id != hyp.id:
        return "static_hypothesis_mismatch"
    if citation_errors:
        return "citations_unverified"
    if static.verdict == "refuted":
        return "static_refuted"
    return None


def _static_label(static: StaticVerifyOutput, skeptic: SkepticOutput | None) -> tuple[Label, str]:
    """Phase-1 rule: likely = confirmed_static AND reachable=yes AND skeptic ran and did not refute."""
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


def _replay_label(static: StaticVerifyOutput, dynamic: DynamicEvidence) -> tuple[Label, str]:
    """Label for a confirmed replay. A direct call into code (script PoC), or a path whose reachability
    static verification could not establish, proves the bug exists, not that an attacker reaches it."""
    if dynamic.entry != "http":
        return Label.likely, "replay_confirmed_direct_call"
    if static.reachable != "yes":
        return Label.likely, f"replay_confirmed_reachability_{static.reachable}"
    return Label.reproduced, "replay_confirmed"


def _with_dynamic(reason: str, dynamic: DynamicEvidence | None) -> str:
    """Record the dynamic outcome in an inconclusive reason whenever dynamic actually ran."""
    if dynamic is None or dynamic.outcome == "skipped":
        return reason
    return f"{reason}; dynamic={dynamic.outcome}"


def decide(
    hyp: Hypothesis,
    static: StaticVerifyOutput | None,
    skeptic: SkepticOutput | None,
    citation_errors: list[str],
    dynamic: DynamicEvidence | None = None,
) -> tuple[Label, str]:
    """reproduced > likely > inconclusive; see the module docstring and docs/design/phase2-dynamic.md.
    The skeptic does not block 'reproduced': replayed evidence beats opinion."""
    gate = _static_gate(hyp, static, citation_errors)
    if gate is not None or static is None:
        return Label.inconclusive, _with_dynamic(gate or "static_verify_unavailable", dynamic)
    if dynamic is not None and dynamic.replay_confirmed:
        return _replay_label(static, dynamic)
    label, reason = _static_label(static, skeptic)
    if label == Label.inconclusive:
        reason = _with_dynamic(reason, dynamic)
    return label, reason


def introduced(dynamic: DynamicEvidence | None) -> bool | None:
    """False when the PoC also fires on base (pre-existing), True when the base replay ran and did
    not fire, None when there is no usable base replay."""
    if dynamic is None or not dynamic.base_ran or dynamic.base_fired is None:
        return None
    return not dynamic.base_fired

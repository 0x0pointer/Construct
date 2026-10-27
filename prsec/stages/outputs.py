"""Agent stage outputs. These pydantic models are the single source of truth;
`schema_for(stage)` gives the JSON Schema handed to the harness in StageTask.output_schema.
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from prsec.models import Severity, Stage


class Citation(BaseModel):
    file: str = Field(description="Repo-relative path at head_sha")
    line: int = Field(ge=1)
    end_line: int | None = Field(default=None, ge=1)
    quote: str = Field(description="Verbatim code at file:line (at least one full line)")


# ---------------------------------------------------------------- 1. triage


class TriageOutput(BaseModel):
    decision: Literal["skip", "light", "full"]
    rationale: str
    risk_tags: list[str] = Field(default_factory=list, description="e.g. sqli, authz, business_logic:pricing")
    focus_files: list[str] = Field(default_factory=list)
    business_flows_touched: list[str] = Field(default_factory=list)


# ----------------------------------------------------------- 2. hypothesise


class Hypothesis(BaseModel):
    id: str = Field(description="Stable short id, e.g. H1")
    vuln_class: Literal["technical", "business_logic"]
    bug_class: str = Field(description="kebab-case, e.g. sqli, idor, bfla, workflow-bypass, negative-quantity")
    title: str
    description: str
    entry_point: str = Field(description="How an attacker reaches it, e.g. 'POST /api/orders' or 'queue consumer X'")
    source: Citation | None = None
    sink: Citation = Field(description="Dangerous sink, or the code where the violated invariant should be enforced")
    path: list[Citation] = Field(default_factory=list)
    assumed_guards: list[str] = Field(default_factory=list)
    impact: str
    severity_guess: Severity
    introduced_by_diff: bool = Field(description="True if the PR introduces or materially changes this path")


class HypothesesOutput(BaseModel):
    summary: str = Field(description="What the PR does, security-relevant reading of intent vs implementation")
    hypotheses: list[Hypothesis] = Field(default_factory=list, max_length=12)


# --------------------------------------------------------- 3a. static verify


class GuardAnalysis(BaseModel):
    description: str
    effective: bool
    citation: Citation | None = None


class StaticVerifyOutput(BaseModel):
    hypothesis_id: str
    verdict: Literal["refuted", "plausible", "confirmed_static"]
    reachable: Literal["yes", "no", "unknown"]
    reasoning: str
    guards: list[GuardAnalysis] = Field(default_factory=list)
    citations: list[Citation] = Field(min_length=1)
    severity: Severity
    remediation: str | None = None


# ------------------------------------------------------------------ skeptic


class SkepticOutput(BaseModel):
    hypothesis_id: str
    refuted: bool
    confidence: Literal["low", "medium", "high"]
    reasoning: str


_MODELS: dict[Stage, type[BaseModel]] = {
    Stage.triage: TriageOutput,
    Stage.hypothesise: HypothesesOutput,
    Stage.static_verify: StaticVerifyOutput,
    Stage.skeptic: SkepticOutput,
}


def model_for(stage: Stage) -> type[BaseModel]:
    return _MODELS[stage]


def schema_for(stage: Stage) -> dict[str, Any]:
    return _MODELS[stage].model_json_schema()

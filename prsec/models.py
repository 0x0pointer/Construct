"""Shared, harness-neutral data contracts.

Every component (api, orchestrator, runner, sandbox entrypoint, harness adapters,
sinks) exchanges these types. Stage *outputs* produced by agents live in
`prsec.stages.outputs`; their JSON Schemas are what agents are asked to satisfy.
"""
from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field


# --------------------------------------------------------------------------- SCM


class PRCommit(BaseModel):
    sha: str
    message: str
    author: str | None = None


class PRInfo(BaseModel):
    scm: str = "github"
    repo: str  # "owner/name"
    number: int
    title: str
    body: str = ""
    author: str | None = None
    base_ref: str
    base_sha: str
    head_ref: str
    head_sha: str
    draft: bool = False
    is_fork: bool = False
    commits: list[PRCommit] = Field(default_factory=list)
    changed_files: list[str] = Field(default_factory=list)
    url: str | None = None


class ScanRequest(BaseModel):
    """Normalised trigger, independent of SCM."""

    scm: str = "github"
    repo: str
    pr: int
    head_sha: str
    base_sha: str | None = None
    installation_id: int | None = None
    reason: Literal["opened", "synchronize", "reopened", "ready_for_review", "reconcile", "manual"] = "opened"
    debug: "ScanDebug | None" = None  # manual scans only (POST /scans); webhooks never set it


class ScanDebug(BaseModel):
    """Per-scan debugging, requested through the admin API."""

    log_level: Literal["debug", "info"] = "debug"  # this scan's records pass at this level
    # keep work dir + envs this long after the scan; capped at the launcher's leftover-env reaper
    # (PRSEC_ENV_MAX_AGE_S, default 4 h), which would otherwise remove a kept env early
    keep_minutes: int = Field(default=0, ge=0, le=4 * 60)


class ScanStatus(StrEnum):
    queued = "queued"
    running = "running"
    done = "done"
    skipped = "skipped"
    failed = "failed"
    superseded = "superseded"


# ----------------------------------------------------------------------- Stages


class Stage(StrEnum):
    rules = "rules"  # first-pass noise filter: skip obvious noise, else scan (replaces deterministic rules)
    triage = "triage"
    hypothesise = "hypothesise"
    static_verify = "static_verify"
    skeptic = "skeptic"
    env = "env"  # phase 2: agent writes the EnvSpec (once per scan)
    dynamic = "dynamic"  # phase 2: agent runs the app and writes a PoC (per hypothesis)


class Limits(BaseModel):
    wall_clock_s: int = 900
    usd_budget: float = 3.0
    max_turns: int | None = None  # only honoured by harnesses whose Caps.max_turns is True
    repair_attempts: int = 2


class StageTask(BaseModel):
    """Everything a harness needs to run one stage. Harness-neutral.

    Paths are *inside* the workbench (container or local dir mapped by the runner).
    """

    scan_id: int
    stage: Stage
    task_id: str  # unique per stage run, e.g. "42-static_verify-h3"
    harness: str  # adapter name: claude-code | codex | opencode | pi | raw
    model_alias: str = "agent-large"  # resolved by the LLM gateway
    prompt_md: str  # fully-rendered stage prompt
    skills: list[str] = Field(default_factory=list)  # skill names (dirs under skills_dir)
    output_schema: dict[str, Any]
    output_path: str = "/work/out/output.json"
    workdir: str = "/work/src"
    in_dir: str = "/work/in"
    out_dir: str = "/work/out"
    skills_dir: str = "/skills"
    context_files: list[str] = Field(default_factory=list)  # paths relative to in_dir
    limits: Limits = Field(default_factory=Limits)


class EventKind(StrEnum):
    message = "message"
    tool_call = "tool_call"
    tool_result = "tool_result"
    usage = "usage"
    error = "error"
    system = "system"


class Event(BaseModel):
    """Normalised transcript event; every adapter maps its native stream onto this."""

    kind: EventKind
    text: str | None = None
    tool: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)
    ts: datetime | None = None


class Usage(BaseModel):
    tokens_in: int = 0
    tokens_out: int = 0
    tokens_cache_read: int = 0
    usd: float = 0.0
    turns: int = 0

    def __add__(self, other: "Usage") -> "Usage":
        return Usage(
            tokens_in=self.tokens_in + other.tokens_in,
            tokens_out=self.tokens_out + other.tokens_out,
            tokens_cache_read=self.tokens_cache_read + other.tokens_cache_read,
            usd=self.usd + other.usd,
            turns=self.turns + other.turns,
        )


class StageStatus(StrEnum):
    ok = "ok"
    output_invalid = "output_invalid"  # schema still invalid after repair attempts
    timeout = "timeout"
    budget_exceeded = "budget_exceeded"
    harness_error = "harness_error"


class StageResult(BaseModel):
    task_id: str
    stage: Stage
    status: StageStatus
    output: dict[str, Any] | None = None
    errors: list[str] = Field(default_factory=list)
    transcript: list[Event] = Field(default_factory=list)
    usage: Usage = Field(default_factory=Usage)
    harness: str
    harness_version: str | None = None
    model: str
    attempts: int = 1
    duration_s: float = 0.0


# --------------------------------------------------------------------- Findings


class Label(StrEnum):
    reproduced = "reproduced"
    likely = "likely"
    inconclusive = "inconclusive"


class Severity(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class CodeLoc(BaseModel):
    file: str
    line: int
    end_line: int | None = None
    snippet: str | None = None  # filled from the trusted snapshot, never from agent text


class Finding(BaseModel):
    fingerprint: str
    scan_id: int
    repo: str
    pr: int
    head_sha: str
    hypothesis_id: str
    vuln_class: Literal["technical", "business_logic"]
    bug_class: str
    title: str
    description: str
    label: Label
    label_reason: str
    severity: Severity
    introduced: bool | None = None  # None = unknown (no base replay ran)
    entry_point: str | None = None
    source: CodeLoc | None = None
    sink: CodeLoc
    path: list[CodeLoc] = Field(default_factory=list)
    guards: list[str] = Field(default_factory=list)
    remediation: str | None = None
    evidence_uri: str | None = None
    provenance: dict[str, Any] = Field(default_factory=dict)  # per stage: harness, version, model, skills, image
    dynamic: dict[str, Any] | None = None  # prsec.dynamic.results.DynamicEvidence (dumped), when dynamic ran

"""Replay and environment contracts shared by orchestrator, runners, launcher and the workbench."""
from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, Field

from prsec.dynamic.envspec import EnvSpec, StubSpec
from prsec.dynamic.poc import PoC

ENV_NAME = re.compile(r"[a-z0-9]{1,16}")  # env tag: network prsec-scan-<scan_id>-<env>

# Fixed container-side paths (part of the launcher's recipe).
APP_DIR = "/work/app"  # writable; prsec-env/prsec-replay copy /work/src into /work/app/src
REPLAY_REQUEST = "/work/in/replay.json"
REPLAY_RESULT = "/work/out/replay_result.json"
ENVSPEC_FILE = "envspec.json"  # in /work/in for the dynamic stage
SINK_HTTP = "http://sink"  # sink API: GET /__prsec/hits?contains=<s> -> {"hits": [...]}, GET /__prsec/health


# ------------------------------------------------------------ provisioning


class ServiceRequest(BaseModel):
    name: str
    kind: str
    seed_dir: str | None = None  # host dir (under the work root) mounted read-only at the catalog seed_path


class EnvRequest(BaseModel):
    """Ask the runner for a fresh dynamic environment on network prsec-scan-<scan_id>-<env>."""

    services: list[ServiceRequest] = Field(default_factory=list)
    stubs: list[StubSpec] = Field(default_factory=list)
    llm: bool = False  # attach the LLM gateway (agent runs); replays never get it
    packages: bool = True  # attach the egress proxy (install/build commands only)
    env_dir: str  # host dir under the work root the runner may write sink config / resolv.conf into


class EnvInfo(BaseModel):
    network: str
    sink_ip: str
    hosts: dict[str, str] = Field(default_factory=dict)  # name -> ip, as served by the sink DNS
    services: dict[str, str] = Field(default_factory=dict)  # name -> "healthy" | "unhealthy: <why>"


# ------------------------------------------------------------------ replay


class Canaries(BaseModel):
    token: str
    host: str
    url: str
    file: str
    file_content: str


class ReplayRequest(BaseModel):
    run_id: str
    envspec: EnvSpec
    poc: PoC
    timeout_s: int = 600


class OracleResult(BaseModel):
    index: int
    type: str
    passed: bool
    detail: str = ""


class StepRecord(BaseModel):
    name: str
    user: str | None = None
    method: str
    url: str
    status: int | None = None
    response_excerpt: str = ""  # first 4 KiB
    error: str | None = None


class ReplayResult(BaseModel):
    run_id: str
    env_ok: bool
    env_error: str | None = None
    fired: bool = False
    entry: Literal["http", "script"] = "http"
    oracle_results: list[OracleResult] = Field(default_factory=list)
    steps: list[StepRecord] = Field(default_factory=list)
    sink_hits: list[dict[str, Any]] = Field(default_factory=list)
    canaries: Canaries | None = None
    app_log_tail: str = ""
    duration_s: float = 0.0


# ---------------------------------------------------- per-hypothesis evidence


class DynamicEvidence(BaseModel):
    """What the orchestrator hands the verdict engine (and stores on the Finding as `dynamic`)."""

    hypothesis_id: str
    outcome: Literal["reproduced", "not_reproduced", "env_failed", "skipped", "error"]
    reason: str = ""
    entry: Literal["http", "script"] | None = None
    head_runs: int = 0
    head_fired: int = 0
    base_ran: bool = False
    base_fired: bool | None = None  # None = base replay not run or its env failed
    poc: PoC | None = None
    replays: list[ReplayResult] = Field(default_factory=list)
    evidence_uri: str | None = None
    provenance: dict[str, Any] = Field(default_factory=dict)  # the dynamic stage run: harness, version, model, ...

    @property
    def replay_confirmed(self) -> bool:
        return self.head_runs >= 2 and self.head_fired == self.head_runs

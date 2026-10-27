"""Non-harness seams: SCM, Runner, FindingsSink."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Protocol

from prsec.dynamic.results import EnvInfo, EnvRequest, ReplayResult
from prsec.models import Finding, PRInfo, StageResult, StageTask


class SCMAdapter(Protocol):
    name: str

    def get_pr(self, repo: str, number: int, installation_id: int | None = None) -> PRInfo: ...

    def get_diff(self, repo: str, number: int, installation_id: int | None = None) -> str:
        """Unified diff of the PR (base...head)."""

    def fetch_source(self, repo: str, sha: str, dest: Path, installation_id: int | None = None) -> Path:
        """Download + extract the tree at `sha` into `dest` (no .git). Returns dest."""

    def list_open_prs(self, installation_id: int | None = None) -> list[PRInfo]:
        """Open PRs across all repos visible to the installation(s) (reconciler)."""


@dataclass
class WorkbenchSpec:
    """One container (or local process) running `prsec-stage` for one StageTask."""

    scan_id: int
    task: StageTask
    image: str  # workbench-<stack>
    harness_volume: str | None  # host path / volume name of /opt/harness/<name>/<ver>
    src_dir: Path  # host dir mounted read-only at task.workdir
    in_dir: Path  # host dir mounted at task.in_dir (task.json + context files)
    out_dir: Path  # host dir mounted at task.out_dir
    skills_dir: Path  # host dir mounted read-only at task.skills_dir
    env: dict[str, str] = field(default_factory=dict)  # gateway url/key etc.
    network: str | None = None  # per-scan network name (static stages)
    # phase 2: run inside dynamic environment `env_name` (network prsec-scan-<scan_id>-<env_name>,
    # DNS = its sink) with `app_dir` mounted writable at /work/app. mode "replay" runs
    # `prsec-replay /work/in/replay.json` instead of `prsec-stage /work/in/task.json`.
    env_name: str | None = None
    app_dir: Path | None = None
    mode: Literal["stage", "replay"] = "stage"


class Runner(Protocol):
    name: str
    supports_envs: bool  # phase 2: create_env/run_replay work (checked before the paid env stage)

    def create_scan_network(self, scan_id: int) -> str:
        """Isolated network whose only egress is the LLM gateway. Returns its name."""

    def run_workbench(self, spec: WorkbenchSpec) -> StageResult:
        """Run `prsec-stage <in_dir>/task.json`, enforce wall clock, return parsed <out_dir>/result.json."""

    def destroy_scan(self, scan_id: int) -> None:
        """Remove every container and network of the scan, including its dynamic environments."""

    def create_env(self, scan_id: int, env_name: str, req: EnvRequest) -> EnvInfo:
        """Phase 2: fresh dynamic environment (network, sink, catalog services). Raises
        NotImplementedError where unsupported (LocalRunner)."""

    def destroy_env(self, scan_id: int, env_name: str) -> None: ...

    def run_replay(self, spec: WorkbenchSpec) -> ReplayResult:
        """Run `prsec-replay` (spec.mode == "replay") and parse <out_dir>/replay_result.json; a
        failed run is returned as ReplayResult(env_ok=False, env_error=...)."""


class FindingsSink(Protocol):
    name: str

    def write_scan(self, scan_id: int, pr: PRInfo, findings: list[Finding], meta: dict) -> str:
        """Persist a scan's findings; return a URI (e.g. s3://prsec/sarif/...)."""

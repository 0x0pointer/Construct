"""Runtime settings (env vars, prefix PRSEC_) and central policy."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PRSEC_", env_file=".env", extra="ignore")

    database_url: str = "postgresql://prsec:prsec@localhost:5432/prsec"

    # GitHub App (reader). Private key path or inline PEM.
    github_app_id: int | None = None
    github_private_key_path: Path | None = None
    github_private_key: str | None = None
    github_webhook_secret: str = ""
    github_api_url: str = "https://api.github.com"

    # LLM gateway (LiteLLM). master key is used to mint per-scan virtual keys.
    gateway_url: str = "http://llm-gateway:4000"
    gateway_master_key: str = ""

    # Object storage (MinIO / S3)
    s3_endpoint: str = "minio:9000"
    s3_access_key: str = ""
    s3_secret_key: str = ""
    s3_bucket: str = "prsec"
    s3_secure: bool = False

    # Runtime
    runner: str = "docker"  # docker | launcher | local
    work_root: Path = Path("/var/lib/prsec/work")
    skills_dir: Path = Path("/var/lib/prsec/skills/current")
    skills_version: str = "dev"
    harness_root: Path = Path("/var/lib/prsec/harness")  # <root>/<name>/<version>
    policy_path: Path = Path(__file__).parent / "policy" / "policy.yaml"
    debounce_s: int = 120
    max_supersedes: int = 5  # anti-starvation: after N supersedes, scan anyway
    worker_concurrency: int = 4
    reconcile_interval_s: int = 900
    admin_token: str = ""  # X-PRSec-Admin for POST /scans; empty disables the route

    # Workbench launcher (runner "launcher"): the only service with the Docker socket.
    launcher_url: str = "http://launcher:8090"
    launcher_token: str = ""  # shared bearer token between worker and launcher


@lru_cache
def settings() -> Settings:
    return Settings()


SKILLS_VERSION_FILE = "VERSION"


def current_skills_version(s: Settings | None = None) -> str:
    """Version of the skills actually mounted at settings().skills_dir, read on every call so a
    `make skills` release (which repoints skills/current) is picked up without a restart:
    the VERSION file `make skills` writes, else the directory skills/current links to,
    else settings().skills_version."""
    s = s or settings()
    try:
        text = (s.skills_dir / SKILLS_VERSION_FILE).read_text().strip()
        if text:
            return text
    except OSError:
        pass
    try:
        if s.skills_dir.is_symlink():
            return s.skills_dir.resolve(strict=True).name
    except OSError:
        pass
    return s.skills_version


# ------------------------------------------------------------------- policy


class StagePolicy(BaseModel):
    harness: str
    model: str = "agent-large"
    skills: list[str] = Field(default_factory=list)
    wall_clock_s: int = 900
    usd_budget: float = 3.0
    max_turns: int | None = None


class Experiment(BaseModel):
    stage: str
    harnesses: list[str]
    sample: float = 0.1  # fraction of scans


class RepoOverride(BaseModel):
    enabled: bool = True
    stages: dict[str, StagePolicy] = Field(default_factory=dict)
    workbench_image: str | None = None


class Policy(BaseModel):
    version: str = "1"
    defaults: dict[str, StagePolicy]
    workbench_image: str = "prsec/workbench-base:latest"
    max_hypotheses: int = 8
    static_verify_min_severity: str = "medium"
    skip_audit_sample: float = 0.03
    scan_drafts: bool = True
    scan_forks: bool = False
    experiments: list[Experiment] = Field(default_factory=list)
    repos: dict[str, RepoOverride] = Field(default_factory=dict)  # key: owner/name (glob allowed)

    def stage(self, stage: str, repo: str | None = None) -> StagePolicy:
        base = self.defaults[stage]
        if repo:
            import fnmatch

            for pattern, ov in self.repos.items():
                if fnmatch.fnmatch(repo, pattern) and stage in ov.stages:
                    return base.model_copy(update=ov.stages[stage].model_dump(exclude_unset=True))
        return base

    def repo_enabled(self, repo: str) -> bool:
        import fnmatch

        return all(ov.enabled for p, ov in self.repos.items() if fnmatch.fnmatch(repo, p))


def load_policy(path: Path | None = None) -> Policy:
    data: dict[str, Any] = yaml.safe_load((path or settings().policy_path).read_text())
    return Policy.model_validate(data)

"""EnvSpec: how to run the PR's app inside the workbench, written by the `env` stage agent.

Commands run with bash in the app dir (`/work/app/src/<workdir>`), which is a writable copy of the
repository. install/build commands may reach package registries through the egress proxy; the
app itself (`start`) runs with no proxy, so every outbound call it makes lands at the sink.
"""
from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator

SERVICE_NAME = re.compile(r"[a-z][a-z0-9-]{0,30}")
ENV_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
# Names a service may not take: they are resolved to infrastructure by the sink's DNS.
RESERVED_NAMES = frozenset({"sink", "llm-gateway", "egress-proxy", "localhost", "app"})


class ServiceSpec(BaseModel):
    name: str = Field(description="Hostname the app uses for it, e.g. 'db'. Lowercase, [a-z][a-z0-9-]*")
    kind: str = Field(description="Catalog key, e.g. postgres, mysql, redis, mongo, mailpit, oauth2")
    seed: list[str] = Field(default_factory=list, description=(
        "Repo-relative files loaded into the service at start (e.g. schema.sql, seed.sql), "
        "only for kinds whose catalog entry has a seed_path"))

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        if not SERVICE_NAME.fullmatch(v) or v in RESERVED_NAMES:
            raise ValueError(f"invalid service name {v!r}")
        return v


class StubSpec(BaseModel):
    """A canned answer the sink gives for outbound HTTP calls (third-party APIs the app calls)."""

    host: str = Field(description="Exact hostname or a glob like '*.stripe.com'")
    method: str = "*"
    path_prefix: str = "/"
    status: int = 200
    headers: dict[str, str] = Field(default_factory=lambda: {"Content-Type": "application/json"})
    body: str = "{}"


class HealthCheck(BaseModel):
    path: str = "/"
    expect_status: list[int] = Field(default_factory=lambda: list(range(200, 500)),
                                      description="Any of these means the app is up (4xx counts: auth-protected roots)")
    timeout_s: int = Field(default=120, ge=5, le=900)


class EnvSpec(BaseModel):
    stack: Literal["python", "node", "go", "java", "other"]
    workdir: str = Field(default=".", description="Repo-relative dir the commands run in")
    install: list[str] = Field(default_factory=list, description="e.g. ['python -m venv .venv', '.venv/bin/pip install -r requirements.txt']")
    build: list[str] = Field(default_factory=list, description="e.g. ['npm run build']; may also prepare a local DB file")
    start: str = Field(description="Starts the app in the foreground, listening on 0.0.0.0 or 127.0.0.1:<port>")
    port: int = Field(ge=1, le=65535)
    health: HealthCheck = Field(default_factory=HealthCheck)
    env: dict[str, str] = Field(default_factory=dict, description="App environment (DB URLs use service names as hosts)")
    services: list[ServiceSpec] = Field(default_factory=list, max_length=6)
    stubs: list[StubSpec] = Field(default_factory=list, max_length=50)
    install_timeout_s: int = Field(default=900, ge=30, le=3600)

    @field_validator("env")
    @classmethod
    def _env(cls, v: dict[str, str]) -> dict[str, str]:
        for k in v:
            if not ENV_KEY.fullmatch(k):
                raise ValueError(f"invalid env name {k!r}")
        return v

    @field_validator("workdir")
    @classmethod
    def _workdir(cls, v: str) -> str:
        parts = [p for p in v.replace("\\", "/").split("/") if p not in ("", ".")]
        if v.startswith("/") or ".." in parts:
            raise ValueError("workdir must be repo-relative and stay inside the repo")
        return "/".join(parts) or "."

    @field_validator("services")
    @classmethod
    def _unique(cls, v: list[ServiceSpec]) -> list[ServiceSpec]:
        names = [s.name for s in v]
        if len(names) != len(set(names)):
            raise ValueError("service names must be unique")
        return v

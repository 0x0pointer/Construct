"""Launcher HTTP API. Bearer-token auth; every request is validated against the fixed recipe."""
from __future__ import annotations

import hmac
import logging
import os
import re
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

from prsec.adapters.protocols import WorkbenchSpec
from prsec.adapters.runner.docker import ENTRYPOINT, DockerRunner, network_name
from prsec.config import load_policy, settings
from prsec.models import StageTask

log = logging.getLogger("prsec.launcher")

HARNESS_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,40}")
ENV_NAME = re.compile(r"[A-Z_][A-Z0-9_]{0,127}")
MAX_ENV_BYTES = 64 * 1024
MAX_LOG_BYTES = 1024 * 1024
# The container-side layout is part of the recipe; only the host side varies per task.
CONTAINER_PATHS = {f: StageTask.model_fields[f].default for f in ("workdir", "in_dir", "out_dir", "skills_dir")}


class Refused(ValueError):
    """The request is outside the fixed recipe."""


class RunRequest(BaseModel):
    scan_id: int = Field(ge=0)
    task: StageTask
    image: str
    harness_volume: str | None = None
    src_dir: str
    in_dir: str
    out_dir: str
    skills_dir: str
    env: dict[str, str] = Field(default_factory=dict)
    network: str | None = None
    timeout_s: float = Field(gt=0)


class RunResponse(BaseModel):
    exit_code: int | None
    logs: str
    killed: bool


def max_timeout_s() -> float:
    return float(os.environ.get("PRSEC_LAUNCHER_MAX_TIMEOUT_S", "7200"))


def allowed_images() -> set[str]:
    """Workbench images named in the AppSec policy (read on every call, so edits apply without a restart)."""
    policy = load_policy()
    images = {policy.workbench_image}
    images.update(ov.workbench_image for ov in policy.repos.values() if ov.workbench_image)
    images.update(i.strip() for i in os.environ.get("PRSEC_LAUNCHER_EXTRA_IMAGES", "").split(",") if i.strip())
    return images


def _under(path: str, root: Path, what: str) -> Path:
    """Resolve `path` (following symlinks) and require it strictly below `root`."""
    if not Path(path).is_absolute():
        raise Refused(f"{what} must be an absolute path")
    resolved = Path(path).resolve()
    root = root.resolve()
    if resolved == root or not resolved.is_relative_to(root):
        raise Refused(f"{what} is outside {root}")
    return resolved


def _check_env(env: dict[str, str]) -> None:
    for k in env:
        if not ENV_NAME.fullmatch(k):
            raise Refused(f"invalid env name {k!r}")
    if sum(len(k) + len(v) for k, v in env.items()) > MAX_ENV_BYTES:
        raise Refused("env too large")


def _check_task(req: RunRequest) -> None:
    t = req.task
    if t.scan_id != req.scan_id:
        raise Refused("task.scan_id does not match scan_id")
    if not HARNESS_NAME.fullmatch(t.harness):
        raise Refused(f"invalid harness name {t.harness!r}")
    for field, expected in CONTAINER_PATHS.items():
        if getattr(t, field) != expected:
            raise Refused(f"task.{field} must be {expected}")


def _harness_volume(req: RunRequest, harness_root: Path) -> str | None:
    if req.harness_volume is None:
        return None
    expected = harness_root / req.task.harness / "current"
    if Path(req.harness_volume) != expected:
        raise Refused(f"harness_volume must be {expected}")
    return str(_under(req.harness_volume, harness_root, "harness_volume"))


def validate(req: RunRequest) -> WorkbenchSpec:
    """Turn a request into a WorkbenchSpec built only from checked parts, or raise Refused."""
    s = settings()
    _check_task(req)
    if req.network not in (None, network_name(req.scan_id)):
        raise Refused(f"network must be {network_name(req.scan_id)} or none")
    if req.image not in allowed_images():
        raise Refused(f"image {req.image!r} is not a workbench image in the policy")
    if Path(req.skills_dir).resolve() != s.skills_dir.resolve():
        raise Refused(f"skills_dir must be {s.skills_dir}")
    if req.timeout_s > max_timeout_s():
        raise Refused(f"timeout_s exceeds {max_timeout_s()}")
    _check_env(req.env)
    # Pass the resolved paths on, so Docker mounts exactly what was checked.
    return WorkbenchSpec(
        scan_id=req.scan_id, task=req.task, image=req.image,
        harness_volume=_harness_volume(req, s.harness_root),
        src_dir=_under(req.src_dir, s.work_root, "src_dir"),
        in_dir=_under(req.in_dir, s.work_root, "in_dir"),
        out_dir=_under(req.out_dir, s.work_root, "out_dir"),
        skills_dir=s.skills_dir.resolve(), env=req.env, network=req.network,
    )


def _require_token(authorization: str | None) -> None:
    token = settings().launcher_token
    if not token:
        raise HTTPException(503, "launcher token not configured")
    scheme, _, given = (authorization or "").partition(" ")
    if scheme != "Bearer" or not hmac.compare_digest(given.encode(), token.encode()):
        raise HTTPException(401, "invalid launcher token")


def _auth(authorization: Annotated[str | None, Header()] = None) -> None:
    _require_token(authorization)


def _docker(request: Request) -> Any:
    if request.app.state.runner is None:
        request.app.state.runner = DockerRunner()
    return request.app.state.runner


Auth = Annotated[None, Depends(_auth)]
Docker = Annotated[Any, Depends(_docker)]


def create_app(runner: Any = None) -> FastAPI:
    app = FastAPI(title="Construct workbench launcher", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.runner = runner

    @app.get("/healthz")
    def healthz() -> dict[str, bool]:
        return {"ok": True}

    @app.post("/scans/{scan_id}/network", responses={401: {"description": "Invalid token"}})
    def create_network(scan_id: int, _: Auth, runner: Docker) -> dict[str, str]:
        if scan_id < 0:
            raise HTTPException(422, "scan_id must be >= 0")
        return {"network": runner.create_scan_network(scan_id)}

    @app.delete("/scans/{scan_id}", responses={401: {"description": "Invalid token"}})
    def destroy(scan_id: int, _: Auth, runner: Docker) -> dict[str, bool]:
        runner.destroy_scan(scan_id)
        return {"ok": True}

    @app.post("/run", responses={401: {"description": "Invalid token"}, 403: {"description": "Outside the recipe"}})
    def run(req: RunRequest, _: Auth, runner: Docker) -> RunResponse:
        try:
            spec = validate(req)
        except Refused as e:
            log.warning("refused run for scan %s task %s: %s", req.scan_id, req.task.task_id, e)
            raise HTTPException(403, str(e)) from None
        command = [f"{spec.task.in_dir.rstrip('/')}/task.json"]
        code, logs, killed = runner.run_container(spec, command, req.timeout_s, entrypoint=ENTRYPOINT)
        return RunResponse(exit_code=code, logs=logs[-MAX_LOG_BYTES:], killed=killed)

    return app


app = create_app()


def run() -> None:
    import uvicorn

    # Loopback by default; the service image sets PRSEC_LAUNCHER_HOST=0.0.0.0 inside the container,
    # where only the worker shares its network.
    uvicorn.run(
        "prsec.launcher.main:app",
        host=os.environ.get("PRSEC_LAUNCHER_HOST", "127.0.0.1"),
        port=int(os.environ.get("PRSEC_LAUNCHER_PORT", "8090")),
    )

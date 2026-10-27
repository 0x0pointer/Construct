"""Phase 2 environment helpers shared by DockerRunner, the launcher and LauncherRunner.

Request checks (catalog kinds, names, host dirs under the work root, stub size), the sink's
config files (hosts.json, stubs.json, resolv.conf) and parsing replay results.
"""
from __future__ import annotations

import json
from pathlib import Path

from prsec.dynamic.catalog import Catalog
from prsec.dynamic.envspec import RESERVED_NAMES, SERVICE_NAME
from prsec.dynamic.results import ENV_NAME, REPLAY_REQUEST, REPLAY_RESULT, EnvRequest, ReplayResult, ServiceRequest

LABEL_ENV = "prsec.env"
LABEL_ENV_DIR = "prsec.env_dir"  # host dir holding resolv.conf; read back when a workbench joins the env
LABEL_LLM = "prsec.llm"  # "1" when the LLM gateway is attached (replays refuse such envs)
SINK_ALIAS = "sink"
EGRESS_ALIAS = "egress-proxy"
SINK_DIR = "sink"  # <env_dir>/sink: hosts.json, stubs.json and the sink's own data
SINK_MOUNT = "/sink"
HOSTS_FILE = "hosts.json"
STUBS_FILE = "stubs.json"
RESOLV_FILE = "resolv.conf"
MAX_SERVICES = 6
MAX_STUBS = 50
MAX_STUBS_BYTES = 256 * 1024
REPLAY_ENTRYPOINT = ["prsec-replay"]
REPLAY_COMMAND = [REPLAY_REQUEST]


class EnvRefused(ValueError):
    """The environment request is outside the recipe."""


def env_network_name(scan_id: int, env_name: str) -> str:
    return f"prsec-scan-{scan_id}-{env_name}"


def check_env_name(env_name: str) -> str:
    if not ENV_NAME.fullmatch(env_name or ""):
        raise EnvRefused(f"invalid env name {env_name!r}")
    return env_name


def under_root(path: str, root: Path, what: str) -> Path:
    """Resolve `path` (following symlinks) and require it strictly below `root`."""
    if not Path(path).is_absolute():
        raise EnvRefused(f"{what} must be an absolute path")
    resolved = Path(path).resolve()
    root = root.resolve()
    if resolved == root or not resolved.is_relative_to(root):
        raise EnvRefused(f"{what} is outside {root}")
    return resolved


def _check_service(s: ServiceRequest, catalog: Catalog, work_root: Path) -> ServiceRequest:
    if not SERVICE_NAME.fullmatch(s.name) or s.name in RESERVED_NAMES:
        raise EnvRefused(f"invalid service name {s.name!r}")
    entry = catalog.services.get(s.kind)
    if entry is None:
        raise EnvRefused(f"service kind {s.kind!r} is not in the catalog")
    if s.seed_dir is None:
        return s
    if not entry.seed_path:
        raise EnvRefused(f"service kind {s.kind!r} takes no seed files")
    return s.model_copy(update={"seed_dir": str(under_root(s.seed_dir, work_root, f"seed_dir of {s.name}"))})


def _check_stubs(req: EnvRequest) -> None:
    if len(req.stubs) > MAX_STUBS:
        raise EnvRefused(f"more than {MAX_STUBS} stubs")
    if len(stubs_json(req)) > MAX_STUBS_BYTES:
        raise EnvRefused("stubs too large")


def check_env_request(req: EnvRequest, catalog: Catalog, work_root: Path) -> EnvRequest:
    """Return a copy of `req` built only from checked parts (resolved host paths), or raise EnvRefused."""
    if len(req.services) > MAX_SERVICES:
        raise EnvRefused(f"more than {MAX_SERVICES} services")
    names = [s.name for s in req.services]
    if len(names) != len(set(names)):
        raise EnvRefused("service names must be unique")
    services = [_check_service(s, catalog, work_root) for s in req.services]
    _check_stubs(req)
    env_dir = under_root(req.env_dir, work_root, "env_dir")
    return req.model_copy(update={"services": services, "env_dir": str(env_dir)})


# ------------------------------------------------------------ sink config


def stubs_json(req: EnvRequest) -> str:
    return json.dumps([s.model_dump(mode="json") for s in req.stubs], indent=2)


def sink_dir(env_dir: str | Path) -> Path:
    return Path(env_dir) / SINK_DIR


def write_hosts(env_dir: str | Path, hosts: dict[str, str]) -> Path:
    """hosts.json: name -> ip served by the sink's DNS; every other name resolves to the sink."""
    path = sink_dir(env_dir) / HOSTS_FILE
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(hosts, indent=2, sort_keys=True))
    tmp.replace(path)  # atomic, the sink reloads on change
    return path


def write_stubs(env_dir: str | Path, req: EnvRequest) -> Path:
    path = sink_dir(env_dir) / STUBS_FILE
    path.write_text(stubs_json(req))
    return path


def write_resolv(env_dir: str | Path, sink_ip: str) -> Path:
    path = Path(env_dir) / RESOLV_FILE
    path.write_text(f"nameserver {sink_ip}\noptions ndots:0 timeout:2 attempts:2\n")
    return path


# ------------------------------------------------------------------ replay


def replay_run_id(in_dir: str | Path, fallback: str) -> str:
    """run_id from <in_dir>/replay.json (written by the orchestrator), else `fallback`."""
    try:
        return str(json.loads((Path(in_dir) / Path(REPLAY_REQUEST).name).read_text())["run_id"])
    except (OSError, ValueError, KeyError, TypeError):
        return fallback


def replay_result_path(out_dir: str | Path) -> Path:
    return Path(out_dir) / Path(REPLAY_RESULT).name


def load_replay_result(out_dir: str | Path, run_id: str, *, exit_code: int | None, killed: bool,
                       log_tail: str) -> ReplayResult:
    """Parse <out_dir>/replay_result.json; a missing or unreadable file becomes env_ok=False."""
    path = replay_result_path(out_dir)
    try:
        return ReplayResult.model_validate_json(path.read_text())
    except FileNotFoundError:
        reason = "replay produced no replay_result.json"
    except (OSError, ValueError) as e:
        reason = f"unreadable replay_result.json: {e}"
    reason = f"replay killed after its wall clock; {reason}" if killed else f"{reason} (exit code {exit_code})"
    return ReplayResult(run_id=run_id, env_ok=False, env_error=reason, app_log_tail=log_tail)

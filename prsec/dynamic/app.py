"""App lifecycle inside the workbench, shared by `prsec-env`, `prsec-poc` and `prsec-replay`.

    prepare   copy /work/src -> /work/app/src once (without .git)
    install   EnvSpec.install + build, with the egress proxy in the env when packages are allowed;
              skipped when the same commands already succeeded in this app dir
    start     EnvSpec.start in the background in its own process group, WITHOUT proxy env, so every
              outbound call the app makes lands at the sink; log + pid under /work/app/.prsec
    health    poll http://127.0.0.1:<port><health.path> until a status in expect_status

All paths default to the fixed container layout and are overridable (tests, CLIs).
"""
from __future__ import annotations

import json
import os
import secrets
import shutil
import signal
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

import httpx

from prsec.dynamic.envspec import EnvSpec
from prsec.dynamic.results import APP_DIR, Canaries

SRC_DIR = "/work/src"
PROXY_HOST = "egress-proxy"
PROXY_PORT = 3128
SINK_HOST = "sink"
PROXY_VARS = ("http_proxy", "https_proxy", "all_proxy", "no_proxy")
CANARY_DOMAIN = "canary.invalid"
LOG_TAIL_BYTES = 16 * 1024


class EnvError(RuntimeError):
    """The app could not be prepared, installed, started or made healthy."""


def app_root_default() -> Path:
    return Path(os.environ.get("PRSEC_APP_DIR", APP_DIR))


def src_default() -> Path:
    return Path(os.environ.get("PRSEC_SRC_DIR", SRC_DIR))


def detect_proxy(host: str = PROXY_HOST, sink: str = SINK_HOST) -> str | None:
    """Proxy URL when `host` resolves to something other than the sink (i.e. packages are allowed)."""
    try:
        ip = socket.gethostbyname(host)
    except OSError:
        return None
    try:
        sink_ip = socket.gethostbyname(sink)
    except OSError:
        sink_ip = None
    return None if ip == sink_ip else f"http://{host}:{PROXY_PORT}"


# ------------------------------------------------------------------ canaries


def state_dir(app_root: Path) -> Path:
    return app_root / ".prsec"


def new_canaries(app_root: Path) -> Canaries:
    """Fresh canary values; the sentinel file lives under the app root's state dir."""
    token = secrets.token_hex(12)
    host = f"{token}.{CANARY_DOMAIN}"
    return Canaries(
        token=token,
        host=host,
        url=f"http://{host}/{token}",
        file=str(state_dir(app_root) / "canary" / f"sentinel-{token}.txt"),
        file_content=f"prsec-sentinel-{secrets.token_hex(16)}",
    )


def write_sentinel(canaries: Canaries) -> None:
    path = Path(canaries.file)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canaries.file_content + "\n")
    path.chmod(0o644)


def canaries_file(app_root: Path) -> Path:
    return state_dir(app_root) / "canaries.json"


def save_canaries(app_root: Path, canaries: Canaries) -> None:
    canaries_file(app_root).parent.mkdir(parents=True, exist_ok=True)
    canaries_file(app_root).write_text(canaries.model_dump_json(indent=2))


def load_or_create_canaries(app_root: Path) -> Canaries:
    """The canaries an agent session works with (stable across prsec-* calls until `prsec-canary new`)."""
    try:
        canaries = Canaries.model_validate_json(canaries_file(app_root).read_text())
    except (OSError, ValueError):
        canaries = new_canaries(app_root)
        save_canaries(app_root, canaries)
    if not Path(canaries.file).exists():
        write_sentinel(canaries)
    return canaries


# ------------------------------------------------------------------ processes


def _alive(pid: int) -> bool:
    try:
        reaped, _ = os.waitpid(pid, os.WNOHANG)  # reap our own exited child (else it stays a zombie)
        if reaped == pid:
            return False
    except ChildProcessError:
        pass
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _tail(path: Path, nbytes: int = LOG_TAIL_BYTES) -> str:
    try:
        with path.open("rb") as f:
            f.seek(0, os.SEEK_END)
            f.seek(max(0, f.tell() - nbytes))
            return f.read().decode(errors="replace")
    except OSError:
        return ""


@dataclass
class AppStatus:
    running: bool
    healthy: bool
    pid: int | None
    port: int
    url: str

    def as_dict(self) -> dict[str, object]:
        return {"running": self.running, "healthy": self.healthy, "pid": self.pid,
                "port": self.port, "url": self.url}


class AppRunner:
    def __init__(self, envspec: EnvSpec, app_root: Path | None = None, src: Path | None = None,
                 proxy: str | None = "auto") -> None:
        self.spec = envspec
        self.app_root = Path(app_root) if app_root else app_root_default()
        self.src = Path(src) if src else src_default()
        self._proxy = proxy
        self._proc: subprocess.Popen[bytes] | None = None

    # ---------------------------------------------------------------- paths

    @property
    def state(self) -> Path:
        return state_dir(self.app_root)

    @property
    def app_src(self) -> Path:
        return self.app_root / "src"

    @property
    def workdir(self) -> Path:
        return self.app_src if self.spec.workdir == "." else self.app_src / self.spec.workdir

    @property
    def log_file(self) -> Path:
        return self.state / "app.log"

    @property
    def install_log(self) -> Path:
        return self.state / "install.log"

    @property
    def pid_file(self) -> Path:
        return self.state / "app.pid"

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.spec.port}"

    # ---------------------------------------------------------------- env

    def proxy_url(self) -> str | None:
        if self._proxy == "auto":
            self._proxy = detect_proxy()
        return self._proxy

    def app_env(self) -> dict[str, str]:
        """Environment of the app (and of script PoCs / command oracles): no proxy, EnvSpec.env."""
        env = {k: v for k, v in os.environ.items() if k.lower() not in PROXY_VARS}
        env.update(self.spec.env)
        return env

    def install_env(self) -> dict[str, str]:
        env = self.app_env()
        proxy = self.proxy_url()
        if proxy:
            for k in ("HTTP_PROXY", "HTTPS_PROXY"):
                env[k] = env[k.lower()] = proxy
            env["NO_PROXY"] = env["no_proxy"] = "localhost,127.0.0.1"
        return env

    # ---------------------------------------------------------------- lifecycle

    def prepare(self) -> None:
        """Copy the repo into the writable app dir once."""
        if not self.app_src.exists():
            if not self.src.is_dir():
                raise EnvError(f"source dir {self.src} does not exist")
            shutil.copytree(self.src, self.app_src, symlinks=True, ignore=shutil.ignore_patterns(".git"))
        self.state.mkdir(parents=True, exist_ok=True)
        if not self.workdir.is_dir():
            raise EnvError(f"workdir {self.spec.workdir!r} does not exist in the repo")

    def _install_marker(self) -> Path:
        return self.state / "installed.json"

    def install(self) -> None:
        """Run install + build commands (once per distinct command list)."""
        commands = [*self.spec.install, *self.spec.build]
        marker = self._install_marker()
        if marker.exists() and marker.read_text() == json.dumps(commands):
            return
        deadline = time.monotonic() + self.spec.install_timeout_s
        env = self.install_env()
        for cmd in commands:
            self._run_install_cmd(cmd, env, deadline)
        marker.write_text(json.dumps(commands))

    def _run_install_cmd(self, cmd: str, env: dict[str, str], deadline: float) -> None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise EnvError(f"install/build timed out after {self.spec.install_timeout_s}s before {cmd!r}")
        with self.install_log.open("ab") as log:
            log.write(f"\n$ {cmd}\n".encode())
            log.flush()
            try:
                rc = subprocess.run(["bash", "-c", cmd], cwd=self.workdir, env=env, stdout=log,
                                    stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                    timeout=remaining).returncode
            except subprocess.TimeoutExpired:
                raise EnvError(f"install/build timed out on {cmd!r}\n{_tail(self.install_log, 4096)}") from None
        if rc != 0:
            raise EnvError(f"command {cmd!r} failed with exit {rc}\n{_tail(self.install_log, 4096)}")

    def start(self, canaries: Canaries | None = None) -> int:
        """Start the app in the background (own process group). Returns its pid."""
        if canaries is not None:
            write_sentinel(canaries)
        self.state.mkdir(parents=True, exist_ok=True)
        with self.log_file.open("ab") as log:
            log.write(f"\n$ {self.spec.start}\n".encode())
            log.flush()
            self._proc = subprocess.Popen(["bash", "-c", self.spec.start], cwd=self.workdir,
                                          env=self.app_env(), stdout=log, stderr=subprocess.STDOUT,
                                          stdin=subprocess.DEVNULL, start_new_session=True)
        self.pid_file.write_text(str(self._proc.pid))
        return self._proc.pid

    def probe(self, timeout: float = 2.0) -> bool:
        path = self.spec.health.path if self.spec.health.path.startswith("/") else "/" + self.spec.health.path
        try:
            r = httpx.get(self.base_url + path, timeout=timeout, trust_env=False)
        except httpx.HTTPError:
            return False
        return r.status_code in self.spec.health.expect_status

    def wait_healthy(self, timeout_s: float | None = None) -> None:
        timeout = self.spec.health.timeout_s if timeout_s is None else timeout_s
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.probe():
                return
            pid = self.pid()
            if pid is None or not _alive(pid):
                raise EnvError(f"app exited before it became healthy\n{self.logs(40)}")
            time.sleep(0.3)
        raise EnvError(f"app not healthy on {self.base_url}{self.spec.health.path} after {timeout}s\n{self.logs(40)}")

    def up(self, canaries: Canaries | None = None) -> AppStatus:
        """prepare + install + start + wait for health; no-op when already running and healthy."""
        self.prepare()
        current = self.status()
        if current.running and current.healthy:
            if canaries is not None:
                write_sentinel(canaries)
            return current
        if current.running:
            self.stop()
        self.install()
        self.start(canaries)
        self.wait_healthy()
        return self.status()

    def pid(self) -> int | None:
        try:
            return int(self.pid_file.read_text().strip())
        except (OSError, ValueError):
            return None

    def stop(self, grace_s: float = 10.0) -> None:
        pid = self.pid()
        if pid is not None and _alive(pid):
            self._signal(pid, signal.SIGTERM)
            deadline = time.monotonic() + grace_s
            while _alive(pid) and time.monotonic() < deadline:
                time.sleep(0.1)
            if _alive(pid):
                self._signal(pid, signal.SIGKILL)
        if self._proc is not None:
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            self._proc = None
        self.pid_file.unlink(missing_ok=True)

    @staticmethod
    def _signal(pid: int, sig: int) -> None:
        try:
            os.killpg(pid, sig)  # the start command leads its own group: kills workers too
        except (ProcessLookupError, PermissionError):
            try:
                os.kill(pid, sig)
            except ProcessLookupError:
                pass

    def reset(self) -> None:
        """Stop the app and throw away the app copy (fresh DB files etc.); the next `up` starts clean."""
        self.stop()
        shutil.rmtree(self.app_src, ignore_errors=True)
        self._install_marker().unlink(missing_ok=True)

    def status(self) -> AppStatus:
        pid = self.pid()
        running = pid is not None and _alive(pid)
        return AppStatus(running=running, healthy=running and self.probe(), pid=pid if running else None,
                         port=self.spec.port, url=self.base_url)

    def logs(self, n: int = 100) -> str:
        lines = _tail(self.log_file).splitlines()
        return "\n".join(lines[-n:]) if n > 0 else ""

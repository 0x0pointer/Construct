import json
from pathlib import Path

import httpx
import pytest

from prsec.dynamic import app as appmod
from prsec.dynamic.app import AppRunner, EnvError, load_or_create_canaries, new_canaries

from .fixtures.workbench import Workbench, workbench  # noqa: F401 - pytest fixture


def test_up_status_logs_down(workbench: Workbench) -> None:  # noqa: F811
    runner = workbench.runner()
    status = runner.up()
    assert status.healthy
    assert httpx.get(f"{runner.base_url}/health", trust_env=False).status_code == 200
    assert runner.pid_file.exists()
    httpx.get(f"{runner.base_url}/search?q=hello-log", trust_env=False)
    assert "hello-log" in runner.logs(50)
    runner.stop()
    assert not runner.status().running
    assert not runner.pid_file.exists()


def test_prepare_copies_src_once_without_git(workbench: Workbench) -> None:  # noqa: F811
    runner = workbench.runner()
    runner.prepare()
    assert (runner.app_src / "server.py").exists()
    assert not (runner.app_src / ".git").exists()
    (runner.app_src / "server.py").write_text("# modified in the app copy\n")
    runner.prepare()
    assert (runner.app_src / "server.py").read_text() == "# modified in the app copy\n"


def test_up_is_idempotent_when_healthy(workbench: Workbench) -> None:  # noqa: F811
    runner = workbench.runner()
    first = runner.up().pid
    assert runner.up().pid == first


def test_install_and_build_run_once_with_proxy_env(workbench: Workbench) -> None:  # noqa: F811
    spec = workbench.spec(install=['echo "$HTTP_PROXY" >> installed.txt'], build=["echo built >> built.txt"])
    runner = AppRunner(spec, app_root=workbench.app_root, src=workbench.src, proxy="http://egress-proxy:3128")
    runner.prepare()
    runner.install()
    runner.install()
    assert (runner.app_src / "installed.txt").read_text() == "http://egress-proxy:3128\n"
    assert (runner.app_src / "built.txt").read_text() == "built\n"


def test_app_env_has_no_proxy(workbench: Workbench, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811
    monkeypatch.setenv("HTTPS_PROXY", "http://somewhere:1")
    runner = AppRunner(workbench.spec(env={"APP_MODE": "test"}), app_root=workbench.app_root,
                       src=workbench.src, proxy="http://egress-proxy:3128")
    env = runner.app_env()
    assert "HTTPS_PROXY" not in env
    assert env["APP_MODE"] == "test"


@pytest.mark.parametrize("name", ["PRSEC_GATEWAY_KEY", "PRSEC_GATEWAY_URL", "ANTHROPIC_AUTH_TOKEN",
                                  "OPENAI_API_KEY", "SOME_SERVICE_TOKEN"])
def test_app_env_drops_workbench_credentials(workbench: Workbench, monkeypatch: pytest.MonkeyPatch, name: str) -> None:  # noqa: F811
    monkeypatch.setenv(name, "s3cret")
    runner = AppRunner(workbench.spec(), app_root=workbench.app_root, src=workbench.src, proxy="http://egress-proxy:3128")
    assert name not in runner.install_env()


def test_app_env_keeps_toolchain_and_envspec_values(workbench: Workbench, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811
    monkeypatch.setenv("JAVA_HOME", "/opt/java")
    runner = AppRunner(workbench.spec(env={"API_KEY": "test-key"}), app_root=workbench.app_root,
                       src=workbench.src, proxy=None)
    env = runner.app_env()
    assert env["JAVA_HOME"] == "/opt/java"
    assert env["API_KEY"] == "test-key"


def test_failing_install_raises_with_output(workbench: Workbench) -> None:  # noqa: F811
    runner = workbench.runner(install=["echo broken-dependency; exit 3"])
    with pytest.raises(EnvError, match="exit 3") as ei:
        runner.up()
    assert "broken-dependency" in str(ei.value)


def test_bad_start_command_fails_fast(workbench: Workbench) -> None:  # noqa: F811
    runner = workbench.runner(start="echo starting; exit 7")
    with pytest.raises(EnvError, match="exited before it became healthy") as ei:
        runner.up()
    assert "starting" in str(ei.value)


def test_unhealthy_app_times_out(workbench: Workbench) -> None:  # noqa: F811
    runner = workbench.runner(health={"path": "/health", "expect_status": [299], "timeout_s": 5})
    with pytest.raises(EnvError, match="not healthy"):
        runner.up()


def test_missing_workdir(workbench: Workbench) -> None:  # noqa: F811
    runner = workbench.runner(workdir="nope")
    with pytest.raises(EnvError, match="workdir"):
        runner.prepare()


def test_missing_src(tmp_path: Path) -> None:
    runner = AppRunner(Workbench(tmp_path / "none", tmp_path / "app", 1).spec(), app_root=tmp_path / "app",
                       src=tmp_path / "none", proxy=None)
    with pytest.raises(EnvError, match="does not exist"):
        runner.prepare()


def test_sentinel_written_before_start(workbench: Workbench) -> None:  # noqa: F811
    runner = workbench.runner()
    canaries = new_canaries(workbench.app_root)
    runner.up(canaries)
    rel = Path(canaries.file).relative_to(runner.app_root)
    r = httpx.get(f"{runner.base_url}/file", params={"name": f"../{rel}"}, trust_env=False)
    assert canaries.file_content in r.text


def test_stop_kills_a_backgrounded_app_whose_leader_exited(workbench: Workbench) -> None:  # noqa: F811
    import sys
    runner = workbench.runner(start=f"{sys.executable} server.py {workbench.port} & sleep 0.1")
    runner.up()
    assert runner.status().running
    runner.stop(grace_s=2)
    with pytest.raises(httpx.HTTPError):
        httpx.get(f"{runner.base_url}/health", trust_env=False, timeout=1)


def test_up_refuses_a_port_held_by_an_untracked_process(workbench: Workbench) -> None:  # noqa: F811
    import socket
    with socket.socket() as held:
        held.bind(("127.0.0.1", workbench.port))
        held.listen()
        runner = workbench.runner()
        with pytest.raises(EnvError, match="already in use"):
            runner.up()


def test_reset_discards_app_copy(workbench: Workbench) -> None:  # noqa: F811
    runner = workbench.runner()
    runner.up()
    (runner.app_src / "state.db").write_text("dirty")
    runner.reset()
    assert not runner.app_src.exists()
    assert not runner.status().running


def test_canaries_are_stable_until_rotated(tmp_path: Path) -> None:
    first = load_or_create_canaries(tmp_path)
    assert load_or_create_canaries(tmp_path) == first
    assert Path(first.file).read_text().strip() == first.file_content
    assert json.loads((tmp_path / ".prsec" / "canaries.json").read_text())["token"] == first.token


def test_new_canaries_shape(tmp_path: Path) -> None:
    c = new_canaries(tmp_path)
    assert c.host == f"{c.token}.canary.invalid"
    assert c.url == f"http://{c.host}/{c.token}"
    assert new_canaries(tmp_path).token != c.token


def test_detect_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    ips = {"egress-proxy": "10.0.0.5", "sink": "10.0.0.2"}
    monkeypatch.setattr(appmod.socket, "gethostbyname", lambda h: ips[h])
    assert appmod.detect_proxy() == "http://egress-proxy:3128"


def test_detect_proxy_resolving_to_sink_means_no_packages(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(appmod.socket, "gethostbyname", lambda h: "10.0.0.2")
    assert appmod.detect_proxy() is None


def test_detect_proxy_unresolvable(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(_: str) -> str:
        raise OSError("no such host")

    monkeypatch.setattr(appmod.socket, "gethostbyname", fail)
    assert appmod.detect_proxy() is None

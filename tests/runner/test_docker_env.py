"""DockerRunner phase 2: dynamic environments (network, sink, catalog services) and replays, mocked client."""
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from docker.errors import NotFound
from fakeharness import make_task

from prsec.adapters.protocols import WorkbenchSpec
from prsec.adapters.runner.docker import DockerRunner
from prsec.adapters.runner.env import EnvRefused
from prsec.config import settings
from prsec.dynamic.catalog import load_catalog
from prsec.dynamic.envspec import StubSpec
from prsec.dynamic.results import EnvRequest, ReplayResult, ServiceRequest

NET = "prsec-scan-42-h1"


def _container(name: str, ip: str, status: str = "running") -> MagicMock:
    c = MagicMock()
    c.name = name
    c.status = status
    c.attrs = {"NetworkSettings": {"Networks": {NET: {"IPAddress": ip}}}}
    c.exec_run.return_value = MagicMock(exit_code=0)
    return c


@pytest.fixture
def work(tmp_path, monkeypatch):
    monkeypatch.setenv("PRSEC_WORK_ROOT", str(tmp_path))
    monkeypatch.setenv("PRSEC_SINK_IMAGE", "prsec/prsec:test")
    monkeypatch.setenv("PRSEC_GATEWAY_CONTAINER", "gw")
    monkeypatch.setenv("PRSEC_EGRESS_CONTAINER", "proxy")
    monkeypatch.delenv("PRSEC_DOCKER_RUNTIME", raising=False)
    monkeypatch.delenv("PRSEC_DOCKER_USER", raising=False)
    settings.cache_clear()
    (tmp_path / "scan-42" / "seed").mkdir(parents=True)
    yield tmp_path
    settings.cache_clear()


@pytest.fixture
def client():
    c = MagicMock()
    started: list[MagicMock] = []

    def run(**kw):
        ct = _container(kw["name"], f"10.0.0.{len(started) + 2}")
        ct.kw = kw
        started.append(ct)
        return ct

    infra = {"gw": _container("gw", "10.0.0.100"), "proxy": _container("proxy", "10.0.0.101")}
    c.containers.run.side_effect = run
    c.containers.get.side_effect = lambda name: infra[name]
    c.containers.list.return_value = []
    c.networks.get.side_effect = NotFound("no env yet")
    c.started = started
    return c


def _runner(client) -> DockerRunner:
    r = DockerRunner(client)
    r.poll_s = 0
    return r


def _req(work: Path, **kw) -> EnvRequest:
    base = {"env_dir": str(work / "scan-42" / "env" / "h1"),
            "services": [ServiceRequest(name="db", kind="postgres", seed_dir=str(work / "scan-42" / "seed")),
                         ServiceRequest(name="cache", kind="redis")],
            "stubs": [StubSpec(host="api.stripe.com", body='{"ok": true}')], "llm": True, "packages": True}
    return EnvRequest(**(base | kw))


def _by_name(client, prefix: str) -> MagicMock:
    (c,) = [c for c in client.started if c.kw["name"].startswith(prefix)]
    return c


def test_env_network_is_internal_and_labelled(client, work):
    info = _runner(client).create_env(42, "h1", _req(work))
    assert info.network == NET
    args, kw = client.networks.create.call_args
    assert args == (NET,)
    assert kw["internal"] is True
    assert kw["labels"]["prsec.scan_id"] == "42"
    assert kw["labels"]["prsec.env"] == "h1"
    assert kw["labels"]["prsec.llm"] == "1"
    assert kw["labels"]["prsec.env_dir"] == str((work / "scan-42" / "env" / "h1").resolve())


def test_sink_started_first_and_hardened(client, work):
    _runner(client).create_env(42, "h1", _req(work))
    sink = client.started[0].kw
    assert sink["name"] == "prsec-sink-42-h1"
    assert sink["image"] == "prsec/prsec:test"
    assert sink["command"][0] == "prsec-sink"
    assert sink["sysctls"] == {"net.ipv4.ip_unprivileged_port_start": "0"}
    assert sink["read_only"] is True
    assert sink["cap_drop"] == ["ALL"]
    assert sink["security_opt"] == ["no-new-privileges:true"]
    assert sink["network"] == NET
    assert sink["labels"]["prsec.env"] == "h1"
    sink_dir = str((work / "scan-42" / "env" / "h1" / "sink").resolve())
    assert sink["volumes"][sink_dir]["mode"] == "rw"
    first_alias = client.api.create_endpoint_config.call_args_list[0].kwargs
    assert first_alias == {"aliases": ["sink"]}


def test_sink_image_defaults_to_prsec_image(client, monkeypatch):
    monkeypatch.delenv("PRSEC_SINK_IMAGE", raising=False)
    monkeypatch.setenv("PRSEC_IMAGE", "prsec/prsec:1.2")
    assert DockerRunner(client).sink_image == "prsec/prsec:1.2"
    monkeypatch.delenv("PRSEC_IMAGE")
    assert DockerRunner(client).sink_image == "prsec/prsec:latest"


def test_hosts_resolv_and_stubs_written(client, work):
    info = _runner(client).create_env(42, "h1", _req(work))
    env_dir = work / "scan-42" / "env" / "h1"
    hosts = json.loads((env_dir / "sink" / "hosts.json").read_text())
    assert hosts == {"sink": "10.0.0.2", "db": "10.0.0.3", "cache": "10.0.0.4",
                     "llm-gateway": "10.0.0.100", "egress-proxy": "10.0.0.101"}
    assert info.hosts == hosts
    assert info.sink_ip == "10.0.0.2"
    assert (env_dir / "resolv.conf").read_text().startswith("nameserver 10.0.0.2\n")
    stubs = json.loads((env_dir / "sink" / "stubs.json").read_text())
    assert stubs[0]["host"] == "api.stripe.com"


def test_services_come_from_the_catalog(client, work):
    _runner(client).create_env(42, "h1", _req(work))
    catalog = load_catalog().services
    db = _by_name(client, "prsec-svc-42-h1-db").kw
    assert db["image"] == catalog["postgres"].image
    assert db["environment"] == catalog["postgres"].env
    assert db["cap_drop"] == ["ALL"]
    assert db["cap_add"] == catalog["postgres"].caps
    assert db["security_opt"] == ["no-new-privileges:true"]
    assert db["mem_limit"]
    assert db["pids_limit"] > 0
    assert db["labels"]["prsec.scan_id"] == "42"
    seed = str((work / "scan-42" / "seed").resolve())
    assert db["volumes"] == {seed: {"bind": "/docker-entrypoint-initdb.d", "mode": "ro"}}
    cache = _by_name(client, "prsec-svc-42-h1-cache").kw
    assert cache["cap_add"] == ["SETUID", "SETGID"]
    assert "volumes" not in cache


def test_services_get_their_name_as_alias(client, work):
    _runner(client).create_env(42, "h1", _req(work))
    aliases = [c.kwargs["aliases"] for c in client.api.create_endpoint_config.call_args_list]
    assert aliases == [["sink"], ["db"], ["cache"]]


@pytest.mark.parametrize("llm,packages,attached", [
    (True, True, ["gw", "proxy"]), (False, True, ["proxy"]), (True, False, ["gw"]), (False, False, []),
])
def test_gateway_and_proxy_attach_rules(client, work, llm, packages, attached):
    info = _runner(client).create_env(42, "h1", _req(work, llm=llm, packages=packages))
    net = client.networks.create.return_value
    assert [c.args[0] for c in net.connect.call_args_list] == attached
    assert ("llm-gateway" in info.hosts) == llm


def test_proxy_alias_is_fixed(client, work):
    _runner(client).create_env(42, "h1", _req(work, llm=False))
    net = client.networks.create.return_value
    net.connect.assert_called_once_with("proxy", aliases=["egress-proxy"])


def test_missing_gateway_is_fatal_and_cleans_up(client, work):
    net = client.networks.create.return_value
    net.connect.side_effect = NotFound("no gateway")
    with pytest.raises(RuntimeError, match="'gw' not found"):
        _runner(client).create_env(42, "h1", _req(work, packages=False))
    labels = client.containers.list.call_args.kwargs["filters"]["label"]
    assert labels == ["prsec.scan_id=42", "prsec.env=h1"]


def test_missing_proxy_is_not_fatal(client, work):
    client.networks.create.return_value.connect.side_effect = NotFound("no proxy")
    info = _runner(client).create_env(42, "h1", _req(work, llm=False))
    assert "egress-proxy" not in info.hosts


@pytest.mark.parametrize("bad", [
    {"services": [ServiceRequest(name="db", kind="oracle")]},
    {"services": [ServiceRequest(name="sink", kind="redis")]},
    {"services": [ServiceRequest(name="cache", kind="redis", seed_dir="/etc")]},
    {"env_dir": "/etc"},
])
def test_refused_requests_start_nothing(client, work, bad):
    with pytest.raises(EnvRefused):
        _runner(client).create_env(42, "h1", _req(work, **bad))
    client.containers.run.assert_not_called()
    client.networks.create.assert_not_called()


@pytest.mark.parametrize("env", ["H1", "a-b", "", "x" * 17, "../x"])
def test_bad_env_name_refused(client, work, env):
    with pytest.raises(EnvRefused):
        _runner(client).create_env(42, env, _req(work))


def test_unhealthy_service_is_reported_not_fatal(client, work):
    runner = _runner(client)
    runner.service_health_s = 0
    original = client.containers.run.side_effect

    def run(**kw):
        c = original(**kw)
        if "-db" in kw["name"]:
            c.exec_run.return_value = MagicMock(exit_code=1)
        if "-cache" in kw["name"]:
            c.status = "exited"
        return c

    client.containers.run.side_effect = run
    info = runner.create_env(42, "h1", _req(work))
    assert info.services["db"].startswith("unhealthy: not healthy")
    assert info.services["cache"] == "unhealthy: container exited"


def test_healthy_services(client, work):
    info = _runner(client).create_env(42, "h1", _req(work))
    assert info.services == {"db": "healthy", "cache": "healthy"}
    db = _by_name(client, "prsec-svc-42-h1-db")
    db.exec_run.assert_called_with(["pg_isready", "-U", "app", "-d", "app"])


# ------------------------------------------------------------------ workbench / replay in an env


def _env_net(env_dir: Path, llm: str = "0") -> MagicMock:
    net = MagicMock()
    net.attrs = {"Labels": {"prsec.env_dir": str(env_dir), "prsec.llm": llm}}
    return net


@pytest.fixture
def env_spec(tmp_path) -> WorkbenchSpec:
    make_task(tmp_path)
    return WorkbenchSpec(
        scan_id=42, task=make_task(tmp_path, harness="codex", container_paths=True), image="prsec/workbench-base:test",
        harness_volume=None, src_dir=tmp_path / "src", in_dir=tmp_path / "in", out_dir=tmp_path / "out",
        skills_dir=tmp_path / "skills", network="prsec-scan-42", env_name="h1", app_dir=tmp_path / "app",
    )


def test_workbench_joins_env_with_sink_dns_and_app_dir(client, env_spec, tmp_path):
    client.networks.get.side_effect = None
    client.networks.get.return_value = _env_net(tmp_path / "envdir")
    kw = DockerRunner(client).container_kwargs(env_spec, ["/work/in/task.json"], ["prsec-stage"])
    assert kw["network"] == NET
    assert kw["volumes"][str(tmp_path / "envdir" / "resolv.conf")] == {"bind": "/etc/resolv.conf", "mode": "ro"}
    assert kw["volumes"][str(tmp_path / "app")] == {"bind": "/work/app", "mode": "rw"}
    assert kw["cap_drop"] == ["ALL"]
    assert kw["read_only"] is True


def test_workbench_in_missing_env_fails(client, env_spec):
    with pytest.raises(RuntimeError, match="does not exist"):
        DockerRunner(client).container_kwargs(env_spec, ["x"])


def test_run_replay_uses_fixed_entrypoint_and_parses_result(client, env_spec, tmp_path):
    client.networks.get.side_effect = None
    client.networks.get.return_value = _env_net(tmp_path / "envdir")
    env_spec.in_dir.mkdir(parents=True, exist_ok=True)
    (env_spec.in_dir / "replay.json").write_text(json.dumps({"run_id": "r1"}))
    container = MagicMock()
    client.containers.run.side_effect = None
    client.containers.run.return_value = container

    def finish(timeout):
        (env_spec.out_dir / "replay_result.json").write_text(
            ReplayResult(run_id="r1", env_ok=True, fired=True).model_dump_json())
        return {"StatusCode": 0}

    container.wait.side_effect = finish
    container.logs.return_value = b"replayed"
    res = DockerRunner(client).run_replay(env_spec)
    assert res.fired is True
    kw = client.containers.run.call_args.kwargs
    assert kw["entrypoint"] + kw["command"] == ["prsec-replay", "/work/in/replay.json"]
    assert env_spec.app_dir.is_dir()


def test_run_replay_without_result_is_env_failure(client, env_spec, tmp_path):
    client.networks.get.side_effect = None
    client.networks.get.return_value = _env_net(tmp_path / "envdir")
    client.containers.run.side_effect = None
    client.containers.run.return_value.wait.return_value = {"StatusCode": 3}
    client.containers.run.return_value.logs.return_value = b"app never came up"
    res = DockerRunner(client).run_replay(env_spec)
    assert res.env_ok is False
    assert "exit code 3" in res.env_error
    assert res.run_id == env_spec.task.task_id
    assert res.app_log_tail == "app never came up"


def test_run_replay_refuses_env_with_gateway(client, env_spec, tmp_path):
    client.networks.get.side_effect = None
    client.networks.get.return_value = _env_net(tmp_path / "envdir", llm="1")
    res = DockerRunner(client).run_replay(env_spec)
    assert res.env_ok is False
    assert "LLM gateway" in res.env_error
    client.containers.run.assert_not_called()


# ------------------------------------------------------------------ teardown


def test_destroy_env_removes_labelled_containers_and_network(client, work):
    leftover = MagicMock()
    leftover.labels = {"prsec.env": "h1"}
    client.containers.list.return_value = [leftover]
    client.networks.get.side_effect = None
    net = client.networks.get.return_value
    DockerRunner(client).destroy_env(42, "h1")
    assert client.containers.list.call_args.kwargs["filters"] == {"label": ["prsec.scan_id=42", "prsec.env=h1"]}
    leftover.remove.assert_called_once_with(force=True, v=True)
    assert [c.args[0] for c in net.disconnect.call_args_list] == ["gw", "proxy"]
    net.remove.assert_called_once()


def test_destroy_scan_also_removes_env_networks(client, work):
    env_net = MagicMock()
    client.networks.list.return_value = [env_net]
    client.networks.get.side_effect = NotFound("no static network")
    DockerRunner(client).destroy_scan(42)
    assert client.networks.list.call_args.kwargs["filters"] == {"label": ["prsec.scan_id=42", "prsec.env"]}
    assert [c.args[0] for c in env_net.disconnect.call_args_list] == ["gw", "proxy"]
    env_net.remove.assert_called_once()

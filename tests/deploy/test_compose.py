"""Static checks on the single-VM compose stack and .env.example."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from prsec.config import Settings

ROOT = Path(__file__).resolve().parents[2]
COMPOSE_DIR = ROOT / "deploy" / "compose"
COMPOSE_FILE = COMPOSE_DIR / "docker-compose.yml"


@pytest.fixture(scope="module")
def compose() -> dict:
    return yaml.safe_load(COMPOSE_FILE.read_text())


@pytest.fixture(scope="module")
def services(compose: dict) -> dict:
    return compose["services"]


def test_expected_services(services: dict) -> None:
    assert {
        "caddy", "oauth2-proxy", "api", "worker", "dashboard", "postgres",
        "minio", "minio-init", "llm-gateway", "llm-gateway-db", "migrate",
    } <= set(services)


def test_only_caddy_publishes_ports(services: dict) -> None:
    assert [n for n, s in services.items() if s.get("ports")] == ["caddy"]


def test_long_running_services_restart_and_healthcheck(services: dict) -> None:
    one_shot = {"migrate", "minio-init"}
    for name, svc in services.items():
        if name in one_shot:
            continue
        assert svc.get("restart") == "unless-stopped", name
    for name in ("caddy", "api", "dashboard", "postgres", "minio", "llm-gateway", "llm-gateway-db"):
        assert "healthcheck" in services[name], name


def test_images_are_pinned(services: dict) -> None:
    for name, svc in services.items():
        image = svc.get("image", "")
        if image.startswith("${PRSEC_IMAGE"):
            continue
        assert ":" in image, name
        tag = image.split("@")[0].rsplit(":", 1)[1]
        assert tag != "latest" or "@sha256:" in image, f"{name}: {image} is not pinned"


def test_gateway_has_fixed_name_and_own_database(services: dict, compose: dict) -> None:
    gw = services["llm-gateway"]
    assert gw["container_name"] == "prsec-llm-gateway"
    assert gw["image"].startswith("ghcr.io/berriai/litellm:v")
    assert "@llm-gateway-db:5432/litellm" in gw["environment"]["DATABASE_URL"]
    assert "gateway-db" in gw["networks"]
    # the gateway DB is reachable only by the gateway
    members = [n for n, s in services.items() if "gateway-db" in (s.get("networks") or [])]
    assert sorted(members) == ["llm-gateway", "llm-gateway-db"]
    assert compose["networks"]["gateway-db"]["internal"] is True


def test_provider_keys_only_in_gateway(services: dict) -> None:
    for name, svc in services.items():
        env = svc.get("environment") or {}
        has = any(k in env for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY"))
        assert has == (name == "llm-gateway"), name


def test_worker_mounts_host_paths_identically(services: dict) -> None:
    worker = services["worker"]
    binds = [v for v in worker["volumes"] if isinstance(v, dict)]
    assert any(v["source"] == "/var/run/docker.sock" for v in binds)
    for sub in ("work", "skills", "harness"):
        (bind,) = [v for v in binds if v["target"].endswith(f"/{sub}")]
        assert bind["source"] == bind["target"], sub
    env = worker["environment"]
    assert env["PRSEC_RUNNER"] == "docker"
    assert env["PRSEC_GATEWAY_URL"] == "http://llm-gateway:4000"
    assert env["PRSEC_WORK_ROOT"].endswith("/work")
    assert env["PRSEC_HARNESS_ROOT"].endswith("/harness")


def test_docker_socket_only_in_worker(services: dict) -> None:
    for name, svc in services.items():
        vols = yaml.safe_dump(svc.get("volumes") or [])
        assert ("docker.sock" in vols) == (name == "worker"), name


def test_minio_healthcheck_uses_mc_ready(services: dict) -> None:
    assert services["minio"]["healthcheck"]["test"] == ["CMD", "mc", "ready", "local"]


def test_caddy_routes() -> None:
    caddyfile = (COMPOSE_DIR / "caddy" / "Caddyfile").read_text()
    assert re.search(r"handle /webhooks/\*\s*\{[^}]*\{[^}]*\}\s*reverse_proxy api:8080", caddyfile)
    assert "reverse_proxy oauth2-proxy:4180" in caddyfile


def _env_example_keys() -> set[str]:
    keys = set()
    for line in (ROOT / ".env.example").read_text().splitlines():
        m = re.match(r"^#?\s*([A-Z][A-Z0-9_]*)=", line)
        if m:
            keys.add(m.group(1))
    return keys


def test_env_example_lists_every_setting() -> None:
    keys = _env_example_keys()
    missing = [f"PRSEC_{f.upper()}" for f in Settings.model_fields if f"PRSEC_{f.upper()}" not in keys]
    assert not missing


def test_env_example_covers_required_compose_vars() -> None:
    text = COMPOSE_FILE.read_text()
    required = set(re.findall(r"\$\{([A-Z0-9_]+):\?", text))
    assert required
    assert required <= _env_example_keys()
    for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "LITELLM_MASTER_KEY", "MINIO_ROOT_USER",
              "MINIO_ROOT_PASSWORD", "PRSEC_GITHUB_APP_ID", "PRSEC_GITHUB_WEBHOOK_SECRET"):
        assert k in _env_example_keys()


@pytest.mark.docker
@pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI not installed")
def test_compose_config_validates() -> None:
    env = {k: "x" for k in re.findall(r"\$\{([A-Z0-9_]+):\?", COMPOSE_FILE.read_text())}
    proc = subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), "config", "-q"],
        cwd=COMPOSE_DIR, env={**os.environ, **env}, capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr


def test_dashboard_sso_restricted_to_appsec(services: dict) -> None:
    text = COMPOSE_FILE.read_text()
    assert "${OIDC_ALLOWED_GROUPS:?" in text and "${OIDC_EMAIL_DOMAINS:?" in text
    assert "OIDC_EMAIL_DOMAINS:-*" not in text
    # no fallback credentials or placeholder IdP
    assert "${OIDC_CLIENT_SECRET:?" in text and "${OIDC_ISSUER_URL:?" in text

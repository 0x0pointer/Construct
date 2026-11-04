"""K8sRunner on the kind cluster (make kind-deploy). Skipped unless the cluster and the chart are there.

The tests drive K8sRunner from this machine with PRSEC_K8S_CONTEXT (kind-construct): the node's
/var/lib/prsec is work/kind here, so PRSEC_K8S_DATA_ROOT=work/kind maps every host path to the same
subPath the in-cluster launcher would use.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from prsec.config import settings

ROOT = Path(__file__).resolve().parents[2]
DATA = Path(os.environ.get("PRSEC_K8S_DATA_ROOT") or ROOT / "work" / "kind")
CONTEXT = os.environ.get("PRSEC_K8S_CONTEXT", "kind-construct")
WORKBENCH = os.environ.get("PRSEC_TEST_WORKBENCH_IMAGE", "prsec/workbench-base:latest")


@pytest.fixture(scope="session")
def kube_ready():
    kubernetes = pytest.importorskip("kubernetes")
    try:
        kubernetes.config.load_kube_config(context=CONTEXT)
        core = kubernetes.client.CoreV1Api()
        core.read_namespaced_service("llm-gateway", "prsec", _request_timeout=5)
        core.read_namespaced_service("egress-proxy", "prsec", _request_timeout=5)
    except Exception as e:
        pytest.skip(f"no kind cluster with the chart deployed ({CONTEXT}): {type(e).__name__}: {str(e)[:120]}")
    if not (DATA / "skills" / "current").exists():
        pytest.skip(f"{DATA} is not prepared: run make kind-data")
    return core


@pytest.fixture
def k8s(kube_ready, monkeypatch, tmp_path_factory):
    """A K8sRunner on the kind cluster, with a fresh work dir under the data volume."""
    from prsec.adapters.runner.k8s import K8sRunner

    monkeypatch.setenv("PRSEC_K8S_CONTEXT", CONTEXT)
    monkeypatch.setenv("PRSEC_K8S_DATA_ROOT", str(DATA))
    monkeypatch.setenv("PRSEC_WORK_ROOT", str(DATA / "work"))
    monkeypatch.setenv("PRSEC_SKILLS_DIR", str(DATA / "skills" / "current"))
    monkeypatch.setenv("PRSEC_SINK_IMAGE", os.environ.get("PRSEC_TEST_IMAGE", "prsec/prsec:latest"))
    settings.cache_clear()
    runner = K8sRunner()
    runner.service_health_s = 180
    yield runner
    settings.cache_clear()

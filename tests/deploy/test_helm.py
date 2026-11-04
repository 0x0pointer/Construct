"""The Helm chart (deploy/helm/construct): rendered with `helm template`, checked for its security invariants."""
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from prsec.dynamic.catalog import load_catalog

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "deploy" / "helm" / "construct"
SET_FILES = {"policy": "policy-spark.yaml", "gateway.config": "deploy/compose/litellm/config.spark.yaml",
             "gateway.hooks": "deploy/compose/litellm/prsec_hooks.py"}

pytestmark = pytest.mark.skipif(shutil.which("helm") is None, reason="helm not installed")


def render(*extra: str) -> list[dict]:
    args = ["helm", "template", "construct", str(CHART), "-n", "prsec"]
    for k, f in SET_FILES.items():
        args += ["--set-file", f"{k}={ROOT / f}"]
    out = subprocess.run([*args, *extra], capture_output=True, text=True, check=True).stdout
    return [d for d in yaml.safe_load_all(out) if d]


@pytest.fixture(scope="module")
def docs() -> list[dict]:
    return render()


def get(docs, kind, name):
    return next(d for d in docs if d["kind"] == kind and d["metadata"]["name"] == name)


def pod(docs, name):
    return get(docs, "Deployment", name)["spec"]["template"]["spec"]


def test_admission_allows_exactly_the_catalog_and_our_images(docs):
    chart_values = yaml.safe_load((CHART / "values.yaml").read_text())
    assert sorted(chart_values["admission"]["catalogImages"]) == sorted(e.image for e in load_catalog().services.values())
    expr = get(docs, "ValidatingAdmissionPolicy", "construct-scan-pods")["spec"]["variables"][0]["expression"]
    images = chart_values["images"]
    assert not images["prsec"].endswith(":latest")
    assert not images["workbench"].endswith(":latest")
    for image in [images["workbench"], images["prsec"], *chart_values["admission"]["catalogImages"]]:
        assert f"'{image}'" in expr
    binding = get(docs, "ValidatingAdmissionPolicyBinding", "construct-scan-pods")
    assert binding["spec"]["validationActions"] == ["Deny"]
    assert binding["spec"]["matchResources"]["namespaceSelector"]["matchLabels"] == {"kubernetes.io/metadata.name": "prsec-scans"}


def test_only_the_launcher_has_kubernetes_rights(docs):
    launcher = pod(docs, "launcher")
    assert launcher["serviceAccountName"] == "construct-launcher"
    assert launcher["automountServiceAccountToken"] is False  # an explicit, short-lived projected token instead
    [token] = [v for v in launcher["volumes"] if v["name"] == "kube-api-access"]
    assert token["projected"]["sources"][0]["serviceAccountToken"]["expirationSeconds"] == 3600
    mounts = {m["mountPath"]: m for m in launcher["containers"][0]["volumeMounts"]}
    assert mounts["/var/run/secrets/kubernetes.io/serviceaccount"]["readOnly"] is True
    for name in ("worker", "api", "dashboard", "llm-gateway", "egress-proxy", "postgres"):
        assert pod(docs, name)["automountServiceAccountToken"] is False, name
    role = get(docs, "Role", "construct-launcher")
    assert role["metadata"]["namespace"] == "prsec-scans"
    verbs = {v for r in role["rules"] for v in r["verbs"]}
    assert verbs <= {"get", "list", "watch", "create", "delete"}  # no update/patch/escalate/bind
    assert not [d for d in docs if d["kind"] in ("ClusterRole", "ClusterRoleBinding")]
    lookup = get(docs, "Role", "construct-launcher-lookup")
    assert lookup["rules"] == [{"apiGroups": [""], "resources": ["services"],
                                "resourceNames": ["llm-gateway", "egress-proxy"], "verbs": ["get"]}]


def test_scans_namespace_is_default_deny_and_baseline(docs):
    ns = get(docs, "Namespace", "prsec-scans")
    assert ns["metadata"]["labels"]["pod-security.kubernetes.io/enforce"] == "baseline"
    deny = get(docs, "NetworkPolicy", "default-deny")
    assert deny["metadata"]["namespace"] == "prsec-scans"
    assert deny["spec"] == {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}


def test_gateway_and_proxy_accept_only_labelled_scan_pods(docs):
    gw = get(docs, "NetworkPolicy", "llm-gateway-ingress")["spec"]["ingress"][0]["from"]
    assert {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "prsec-scans"}},
            "podSelector": {"matchLabels": {"prsec.llm": "1"}}} in gw
    proxy = get(docs, "NetworkPolicy", "egress-proxy-ingress")["spec"]["ingress"][0]["from"]
    assert proxy == [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "prsec-scans"}},
                      "podSelector": {"matchLabels": {"prsec.packages": "1"}}}]


def test_one_volume_two_claims(docs):
    pvs = {d["metadata"]["name"]: d for d in docs if d["kind"] == "PersistentVolume"}
    assert {p["spec"]["claimRef"]["namespace"] for p in pvs.values()} == {"prsec", "prsec-scans"}
    assert all(p["spec"]["hostPath"]["path"] == "/var/lib/prsec" for p in pvs.values())
    claims = [d for d in docs if d["kind"] == "PersistentVolumeClaim" and d["metadata"]["name"] == "prsec-data"]
    assert {c["metadata"]["namespace"] for c in claims} == {"prsec", "prsec-scans"}


def test_launcher_runs_k8s_backend_with_matching_names(docs):
    env = {e["name"]: e.get("value") for e in pod(docs, "launcher")["containers"][0]["env"]}
    assert env["PRSEC_LAUNCHER_BACKEND"] == "k8s"
    assert (env["PRSEC_K8S_NAMESPACE"], env["PRSEC_K8S_CONTROL_NAMESPACE"]) == ("prsec-scans", "prsec")
    assert env["PRSEC_K8S_DATA_CLAIM"] == "prsec-data"
    assert env["PRSEC_WORK_ROOT"] == "/var/lib/prsec/work"
    worker = {e["name"]: e.get("value") for e in pod(docs, "worker")["containers"][0]["env"]}
    assert (worker["PRSEC_RUNNER"], worker["PRSEC_LAUNCHER_URL"]) == ("launcher", "http://launcher:8090")


def test_control_pods_are_hardened(docs):
    for name in ("worker", "api", "dashboard", "launcher", "egress-proxy"):
        spec = pod(docs, name)
        assert spec["securityContext"]["runAsNonRoot"] is True, name
        c = spec["containers"][0]["securityContext"]
        assert c["readOnlyRootFilesystem"] is True, name
        assert c["allowPrivilegeEscalation"] is False, name


def test_required_files_are_enforced():
    with pytest.raises(subprocess.CalledProcessError) as e:
        subprocess.run(["helm", "template", "construct", str(CHART)], capture_output=True, text=True, check=True)
    assert "--set-file policy=" in e.value.stderr


def test_every_container_limits_memory_and_ephemeral_storage(docs):
    for d in docs:
        if d["kind"] != "Deployment":
            continue
        spec = d["spec"]["template"]["spec"]
        for c in [*spec.get("initContainers", []), *spec["containers"]]:
            limits = c["resources"]["limits"]
            assert "memory" in limits, (d["metadata"]["name"], c["name"])
            assert "ephemeral-storage" in limits, (d["metadata"]["name"], c["name"])


def test_kind_values_use_the_locally_built_images():
    out = render("-f", str(ROOT / "deploy" / "kind" / "values.yaml"))
    expr = get(out, "ValidatingAdmissionPolicy", "construct-scan-pods")["spec"]["variables"][0]["expression"]
    assert "'prsec/workbench-base:latest'" in expr
    assert pod(out, "worker")["containers"][0]["image"] == "prsec/prsec:latest"

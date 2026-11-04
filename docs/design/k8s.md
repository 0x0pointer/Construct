# Kubernetes runner and in-cluster deployment (design)

Construct runs every agent stage, dynamic environment and replay in its own container. Today
`DockerRunner` starts them through the Docker socket, held by the launcher. This design adds a
`K8sRunner` behind the **same `Runner` contract** (`prsec/adapters/protocols.py`) and moves the
whole stack into one cluster, deployed with a Helm chart. The pipeline, the orchestrator, the
workbench entrypoint and the replay do not change.

Development and tests run on a local **kind** cluster. Production targets a **managed cluster**
(EKS, GKE, AKS, DOKS or similar).

## Topology

| Namespace | Runs | Notes |
|---|---|---|
| `prsec` | api, worker, launcher, dashboard (+ oauth2-proxy), llm-gateway (+ its DB), egress-proxy, Postgres and MinIO (or managed RDS/S3 through values) | an Ingress replaces Caddy |
| `prsec-scans` | every workbench, sink and catalog-service pod | default-deny NetworkPolicy; Pod Security `baseline` enforced, `restricted` audited |

- **The launcher keeps its role.** It is still the only component that can start containers, now
  through a ServiceAccount whose Role is limited to `prsec-scans` (pods, pods/log, services,
  configmaps, networkpolicies). The worker has no Kubernetes credentials and keeps talking to the
  launcher's HTTP API (`LauncherRunner`), so its security model is unchanged.
  `PRSEC_LAUNCHER_BACKEND=k8s` selects `K8sRunner` inside the launcher; `docker` stays the default.
- **No Docker socket anywhere.**
- **An admission policy repeats the launcher's fixed recipe at the cluster level.** A
  `ValidatingAdmissionPolicy` on `prsec-scans` admits only allowlisted images (the policy's workbench
  images, the sink image, the catalog's digests), no `hostPath`, no privileged pods, and no
  service-account token. A compromised launcher still cannot run anything else there.

## Storage: one shared read-write-many volume

The file contract between worker, launcher and workbench stays as it is: `task.json` in,
`result.json` out, the live `events.jsonl` tail, `replay.json`, per-env app dirs. All of those
paths live under `/var/lib/prsec`, on **one read-write-many store**. A claim belongs to a single
namespace, so the chart creates **two PersistentVolumes on the same store**, one bound to the
`prsec-data` claim in each namespace. The control namespace mounts it at `/var/lib/prsec` in the
worker, launcher, api and dashboard. Each workbench pod mounts only its own dirs from it, **by
`subPath`**: its `src`, `in`, `out` and `app` dirs, `skills/current` and `harness/<name>/current`.
`subPath`s are resolved first, because kubelet refuses symlinks. Absolute paths stay the same as
with Docker, so no orchestrator code changes.

- **kind:** a `hostPath` PersistentVolume on the single node, with the node directory mapped to
  `./work/kind` on the Mac (`extraMounts`), so you can inspect it.
- **Managed clusters:** EFS (EKS), Filestore (GKE), Azure Files (AKS) or any NFS-backed RWX class.
- **Object storage later, if needed.** Moving the files through object storage instead (S3/MinIO
  with init and upload containers) remains possible behind the same seam if RWX performance or
  cost becomes a problem. It would change the file contract, so it is not the first step.
- **Harness volumes and skills are prepared on the same volume** by one-off Jobs, the equivalents
  of `make harness-volumes` and `make skills`.

## Network and isolation, Docker to Kubernetes

| Docker today | Kubernetes |
|---|---|
| per-scan internal network, gateway attached | pods labelled `prsec.scan_id=<id>`; NetworkPolicy egress only to the gateway pods on :4000 |
| Docker's embedded DNS on the scan network | **no DNS at all** for static stages (`dnsPolicy: None`); `hostAliases` maps `llm-gateway` to the gateway Service's ClusterIP. Cluster DNS would recursively resolve any name, which is an exfiltration channel. |
| env network `prsec-scan-<id>-<env>` | pods labelled `prsec.env=<id>-<env>`; NetworkPolicy allows egress only inside the env, plus the gateway (`llm`) and the egress proxy (`packages`) when requested |
| sink container + `resolv.conf` mount | sink **Pod + Service** (53/udp, 53/tcp, 80, 443); env pods use `dnsPolicy: None` with `nameservers: [sink ClusterIP]` |
| `hosts.json` / `stubs.json` written into the sink dir | a ConfigMap mounted at `/sink` (read-only, so the sink records in memory only). Every catalog service gets a Service first, and Service ClusterIPs are allocated at creation, so `hosts.json` is complete **before** any pod starts. No IP polling or rewrites. |
| catalog service container | Pod + Service named after the EnvSpec service; the catalog `health` command becomes an exec readiness probe |
| seed dir bind mount | PVC `subPath`, read-only, at the catalog's `seed_path` |
| app dir bind mount | PVC `subPath`, read-write, at `/work/app` |
| wait / kill on wall clock / logs / remove | Pod with `restartPolicy: Never` and `activeDeadlineSeconds` = wall clock + grace; the runner watches the phase, collects logs, deletes the pod |
| labels + reaper | the same labels; the reaper deletes env objects older than `PRSEC_ENV_MAX_AGE_S` |

**Hardening (both pod kinds).** `runAsNonRoot`, read-only root filesystem, no privilege
escalation, all capabilities dropped, `seccompProfile: RuntimeDefault`, no service-account token,
CPU, memory and ephemeral-storage limits, and `/tmp` as an `emptyDir` with a size limit. The sink
gets the namespaced safe sysctl `net.ipv4.ip_unprivileged_port_start=0` so it can bind ports
53, 80 and 443 as non-root. Catalog services get exactly their catalog capabilities, which are all
within Pod Security `baseline`. gVisor or Kata come in through `runtimeClassName`
(`PRSEC_K8S_RUNTIME_CLASS`) where the provider offers them (GKE Sandbox; on EKS it needs custom
node pools).

**Gaps versus Docker.**
- Kubernetes has no per-pod pids limit; use the node's `podPidsLimit` on managed node pools.
- There is no swap limit; Kubernetes runs nodes without swap by default.

**NetworkPolicy enforcement.** NetworkPolicy only works with a CNI that enforces it. Both the kind
cluster and every managed cluster must be checked by a test: a workbench pod must not reach the
internet, cluster DNS or another scan's pods, and a replay pod must not reach the gateway.

## Tests

- **Unit:** `K8sRunner` against a fake Kubernetes API. Assert the generated objects: security
  context, labels, NetworkPolicy rules, DNS config, mounts and the admission-relevant fields.
- **kind (`-m k8s`):**
  - the reference-PoC replays from `tests/dynamic/test_reference_replays.py`, with the runner
    switched to `K8sRunner`;
  - an isolation probe (no internet, no DNS, no other scan, gateway only when `llm`);
  - `make eval` against the in-cluster worker.
- **CI:** a kind job that runs the `k8s` marker.

## Order of work

1. `K8sRunner` (static stages, then dynamic envs and replays) plus unit tests.
2. A kind cluster script (`make kind-up`), image loading, and the `k8s`-marked tests above.
3. The Helm chart (`deploy/helm/construct`): the control plane and the `prsec-scans` namespace,
   Roles, NetworkPolicies, admission policy and the PVC. `make kind-deploy` runs the whole stack on
   kind. Values select managed Postgres/S3, the storage class, the runtime class and the Ingress.
4. The launcher backend switch and the eval through the in-cluster worker.

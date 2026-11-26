#!/usr/bin/env bash
# One-time devcontainer setup (Codespaces): the venv for "1. Run the tests", rsync for
# make kind-data, and the kind binary for the Kubernetes tier. Docker, kubectl and helm
# come from the devcontainer features.
set -euo pipefail
cd "$(dirname "$0")/.."

sudo apt-get update -qq
sudo apt-get install -y -qq --no-install-recommends rsync

KIND_VERSION="${KIND_VERSION:-v0.30.0}"
if ! command -v kind >/dev/null 2>&1; then
  arch="$(dpkg --print-architecture)"
  sudo curl -fsSL --proto '=https' --tlsv1.2 -o /usr/local/bin/kind \
    "https://github.com/kubernetes-sigs/kind/releases/download/${KIND_VERSION}/kind-linux-${arch}"
  sudo chmod 0755 /usr/local/bin/kind
fi

python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -e '.[dev]'

# Run the first two test tiers now so results are already waiting when the Codespace
# opens. A failure here is a finding to look at, not a broken container: exit 0 either way.
log=work/startup-tests.log
mkdir -p work
status=PASSED
{ echo "== make test =="; make test; } 2>&1 | tee "$log" || status=FAILED
for _ in $(seq 1 60); do docker info >/dev/null 2>&1 && break; sleep 2; done  # dockerd may still be coming up
{ echo "== make test-db =="; make test-db; } 2>&1 | tee -a "$log" || status=FAILED
echo "Startup tests: $status" >> "$log"  # the Test Console panel reads this verdict line

echo
echo "Startup tests: $status (full log: $log). Next: make test-e2e"

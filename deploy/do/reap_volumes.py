"""Delete the block volumes a deleted DOKS cluster left behind (make do-down).

`doctl kubernetes cluster delete --dangerous` does not always take the PVC volumes with it: they are
still attached while the node droplets shut down, and then stay as detached volumes that keep billing.
Every one carries the tag `k8s:<cluster id>`. This waits for those to detach and deletes them; a volume
of any other cluster is never touched.

    python3 deploy/do/reap_volumes.py <cluster id> [timeout seconds]
"""
from __future__ import annotations

import json
import subprocess
import sys
import time


def tagged(cluster_id: str) -> list[dict]:
    out = subprocess.run(["doctl", "compute", "volume", "list", "--output", "json"],
                         check=True, capture_output=True, text=True).stdout
    tag = f"k8s:{cluster_id}"
    return [v for v in json.loads(out or "[]") if tag in (v.get("tags") or [])]


def main(argv: list[str]) -> int:
    if len(argv) < 2 or not argv[1].strip():
        print("usage: reap_volumes.py <cluster id> [timeout seconds]", file=sys.stderr)
        return 2
    cluster_id = argv[1].strip()
    deadline = time.monotonic() + (float(argv[2]) if len(argv) > 2 else 900.0)
    while True:
        volumes = tagged(cluster_id)
        for v in volumes:
            if not v.get("droplet_ids"):
                subprocess.run(["doctl", "compute", "volume", "delete", v["id"], "--force"], check=True)
                print(f"deleted volume {v['name']} ({v['size_gigabytes']} GB)")
        if not [v for v in volumes if v.get("droplet_ids")]:
            return 0
        if time.monotonic() > deadline:
            print(f"volumes still attached: {[v['name'] for v in volumes if v.get('droplet_ids')]}", file=sys.stderr)
            return 1
        time.sleep(20)


if __name__ == "__main__":
    sys.exit(main(sys.argv))

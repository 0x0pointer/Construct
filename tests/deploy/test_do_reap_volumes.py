"""deploy/do/reap_volumes.py: only the deleted cluster's detached volumes are deleted."""
from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "deploy" / "do" / "reap_volumes.py"
CLUSTER = "dbd51954-557d-4a63-bce0-d687875ef59a"


@pytest.fixture
def reap(monkeypatch):
    spec = importlib.util.spec_from_file_location("reap_volumes", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod.time, "sleep", lambda s: None)
    return mod


def fake_doctl(monkeypatch, mod, listings: list[list[dict]]) -> list[str]:
    """Each `volume list` returns the next listing (the last one repeats); returns the deleted ids."""
    deleted: list[str] = []

    def run(cmd, **kw):
        if cmd[:4] == ["doctl", "compute", "volume", "list"]:
            listing = listings.pop(0) if len(listings) > 1 else listings[0]
            return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(listing))
        assert cmd[:4] == ["doctl", "compute", "volume", "delete"]
        deleted.append(cmd[4])
        return subprocess.CompletedProcess(cmd, 0, stdout="")

    monkeypatch.setattr(mod.subprocess, "run", run)
    return deleted


def vol(vid: str, cluster: str = CLUSTER, attached: list[int] | None = None) -> dict:
    return {"id": vid, "name": f"pvc-{vid}", "size_gigabytes": 2, "droplet_ids": attached or [],
            "tags": [f"k8s:{cluster}"]}


def test_waits_for_detach_and_spares_other_clusters(monkeypatch, reap):
    other = vol("keep", cluster="102acd17-dca7-4d8e-ba65-149c266778a8")
    deleted = fake_doctl(monkeypatch, reap, [
        [vol("a", attached=[1]), vol("b"), other],
        [vol("a"), other],
        [other],
    ])
    assert reap.main(["reap", CLUSTER]) == 0
    assert deleted == ["b", "a"]


def test_times_out_while_attached(monkeypatch, reap):
    deleted = fake_doctl(monkeypatch, reap, [[vol("a", attached=[1])]])
    assert reap.main(["reap", CLUSTER, "0"]) == 1
    assert deleted == []


@pytest.mark.parametrize("argv", [["reap"], ["reap", ""], ["reap", "  "]])
def test_needs_a_cluster_id(reap, argv):
    assert reap.main(argv) == 2

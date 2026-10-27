"""Worker: leases scans from the Postgres queue and runs the pipeline, `worker_concurrency` at a time."""
from __future__ import annotations

import logging
import signal
import threading
from concurrent.futures import ThreadPoolExecutor

from prsec.config import settings
from prsec.db import queue
from prsec.obs.logging import setup_logging
from prsec.orchestrator import pipeline, reconciler

log = logging.getLogger(__name__)

LEASE_S = 600
HEARTBEAT_S = 60
POLL_S = 5.0


def run_one(lease_s: int = LEASE_S, heartbeat_s: float = HEARTBEAT_S) -> bool:
    """Lease and run one scan with a heartbeat thread. False if nothing was due."""
    row = queue.lease_next(lease_s)
    if row is None:
        return False
    scan_id = int(row["id"])
    token = row.get("lease_token")
    done = threading.Event()

    def beat() -> None:
        while not done.wait(heartbeat_s):
            try:
                if not queue.heartbeat(scan_id, lease_s, token):
                    # superseded or lease lost: the pipeline sees it at its next check (owns_lease /
                    # is_superseded) and stops; every write it makes is conditional on the token.
                    log.warning("scan %s no longer running under this lease (superseded or lost)", scan_id)
                    return
            except Exception:
                log.exception("heartbeat for scan %s failed", scan_id)

    hb = threading.Thread(target=beat, name=f"heartbeat-{scan_id}", daemon=True)
    hb.start()
    try:
        pipeline.run_scan(row)
    finally:
        done.set()
        hb.join(timeout=5)
    return True


def _slot(stop: threading.Event, poll_s: float) -> None:
    while not stop.is_set():
        try:
            queue.requeue_expired_leases()
            pipeline.reap_kept()  # kept-for-debugging scans whose keep expired
            ran = run_one()
        except Exception:
            log.exception("worker slot error")
            ran = False
        if not ran:
            stop.wait(poll_s)


def serve(stop: threading.Event, concurrency: int | None = None, poll_s: float = POLL_S, reconcile: bool = True) -> None:
    n = concurrency or settings().worker_concurrency
    threads = []
    if reconcile:
        t = threading.Thread(target=reconciler.run_forever, args=(stop,), name="reconciler", daemon=True)
        t.start()
        threads.append(t)
    with ThreadPoolExecutor(max_workers=n, thread_name_prefix="scan") as pool:
        for _ in range(n):
            pool.submit(_slot, stop, poll_s)
    for t in threads:
        t.join(timeout=5)


def main() -> None:
    setup_logging("worker")
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    log.info("prsec worker starting (concurrency=%s)", settings().worker_concurrency)
    serve(stop)

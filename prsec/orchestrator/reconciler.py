"""Catches dropped webhooks: enqueue every open PR head that has no scan yet."""
from __future__ import annotations

import logging
import threading

from prsec.adapters import scm as scm_pkg
from prsec.config import Policy, current_skills_version, load_policy, settings
from prsec.db import queue
from prsec.models import PRInfo, ScanRequest
from prsec.obs.logging import setup_logging

log = logging.getLogger(__name__)


def _eligible(pr: PRInfo, policy: Policy) -> str | None:
    """Ignore reason, or None if the PR should be scanned."""
    if not policy.repo_enabled(pr.repo):
        return "repo_disabled"
    if pr.draft and not policy.scan_drafts:
        return "draft"
    if pr.is_fork and not policy.scan_forks:
        return "fork"
    return None


def reconcile_once(scm_name: str = "github", policy: Policy | None = None) -> list[int]:
    """Returns the ids of newly queued scans."""
    s = settings()
    skills_version = current_skills_version()
    policy = policy or load_policy()
    queued: list[int] = []
    for pr in scm_pkg.get_scm(scm_name).list_open_prs():
        if _eligible(pr, policy):
            continue
        if queue.known_head(pr.repo, pr.number, pr.head_sha, skills_version):
            continue
        req = ScanRequest(scm=pr.scm, repo=pr.repo, pr=pr.number, head_sha=pr.head_sha, base_sha=pr.base_sha, reason="reconcile")
        scan_id = queue.enqueue(req, skills_version, s.debounce_s, s.max_supersedes)
        if scan_id is not None:
            log.info("reconciler queued scan %s for %s#%s@%s", scan_id, pr.repo, pr.number, pr.head_sha[:12])
            queued.append(scan_id)
    return queued


def run_forever(stop: threading.Event, interval_s: int | None = None) -> None:
    interval = interval_s if interval_s is not None else settings().reconcile_interval_s
    while not stop.is_set():
        try:
            reconcile_once()
        except Exception:
            log.exception("reconcile failed")
        stop.wait(interval)


def main() -> None:
    setup_logging("reconciler")
    print(len(reconcile_once()))

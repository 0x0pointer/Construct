"""GitHub webhook payload -> ScanRequest. Pure: no I/O, policy is passed in."""
from __future__ import annotations

from typing import Any

from prsec.config import Policy
from prsec.models import ScanRequest

SCAN_ACTIONS = frozenset({"opened", "synchronize", "reopened", "ready_for_review"})

Normalized = tuple[ScanRequest | None, str | None]


def _get(d: Any, *path: str) -> Any:
    for key in path:
        if not isinstance(d, dict):
            return None
        d = d.get(key)
    return d


def github_event_to_request(event: str, payload: dict[str, Any], policy: Policy | None = None) -> Normalized:
    """Return (request, None) for a scannable event, else (None, ignore_reason).

    Without a policy, drafts are scanned, forks are not, and every repo is enabled.
    """
    if event != "pull_request":
        return None, f"event:{event}"
    action = payload.get("action")
    if action not in SCAN_ACTIONS:
        return None, f"action:{action}"

    pr = payload.get("pull_request")
    if not isinstance(pr, dict):
        return None, "malformed:pull_request"
    repo = _get(payload, "repository", "full_name") or _get(pr, "base", "repo", "full_name")
    number = payload.get("number", pr.get("number"))
    head_sha = _get(pr, "head", "sha")
    if not isinstance(repo, str) or not isinstance(number, int) or not isinstance(head_sha, str) or not head_sha:
        return None, "malformed:missing repo/number/head_sha"

    if pr.get("state", "open") != "open":
        return None, "pr_not_open"

    scan_drafts = policy.scan_drafts if policy else True
    scan_forks = policy.scan_forks if policy else False
    if policy and not policy.repo_enabled(repo):
        return None, "repo_disabled"
    if pr.get("draft") and not scan_drafts:
        return None, "draft"
    head_repo = _get(pr, "head", "repo", "full_name")
    base_repo = _get(pr, "base", "repo", "full_name") or repo
    if head_repo != base_repo and not scan_forks:
        return None, "fork"

    installation_id = _get(payload, "installation", "id")
    return ScanRequest(
        scm="github",
        repo=repo,
        pr=number,
        head_sha=head_sha,
        base_sha=_get(pr, "base", "sha"),
        installation_id=installation_id if isinstance(installation_id, int) else None,
        reason=action,
    ), None

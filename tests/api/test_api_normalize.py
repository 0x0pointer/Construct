from __future__ import annotations

import pytest

from prsec.api.normalize import github_event_to_request
from prsec.config import Policy, RepoOverride, StagePolicy
from .payloads import pr_payload


def policy(**kw) -> Policy:
    return Policy(defaults={"triage": StagePolicy(harness="raw")}, **kw)


@pytest.mark.parametrize("action", ["opened", "synchronize", "reopened", "ready_for_review"])
def test_scannable_actions(action):
    req, reason = github_event_to_request("pull_request", pr_payload(action=action), policy())
    assert reason is None
    assert req is not None
    assert (req.repo, req.pr, req.head_sha, req.base_sha) == ("acme/api", 7, "a" * 40, "b" * 40)
    assert req.installation_id == 99
    assert req.reason == action
    assert req.scm == "github"


@pytest.mark.parametrize("action", ["closed", "labeled", "edited", "converted_to_draft", "assigned", None])
def test_ignored_actions(action):
    req, reason = github_event_to_request("pull_request", pr_payload(action=action), policy())
    assert req is None
    assert reason == f"action:{action}"


@pytest.mark.parametrize("event", ["push", "issues", "check_run", ""])
def test_ignored_events(event):
    req, reason = github_event_to_request(event, pr_payload(), policy())
    assert req is None
    assert reason == f"event:{event}"


def test_draft_respects_policy():
    p = pr_payload(pull_request__draft=True)
    assert github_event_to_request("pull_request", p, policy(scan_drafts=True))[0] is not None
    assert github_event_to_request("pull_request", p, policy(scan_drafts=False)) == (None, "draft")


def test_ready_for_review_not_draft():
    p = pr_payload(action="ready_for_review", pull_request__draft=False)
    assert github_event_to_request("pull_request", p, policy(scan_drafts=False))[0] is not None


def test_fork_respects_policy():
    p = pr_payload(pull_request__head={"sha": "c" * 40, "repo": {"full_name": "mallory/api"}})
    assert github_event_to_request("pull_request", p, policy(scan_forks=False)) == (None, "fork")
    req, _ = github_event_to_request("pull_request", p, policy(scan_forks=True))
    assert req is not None
    assert req.head_sha == "c" * 40


def test_deleted_fork_head_repo_is_fork():
    p = pr_payload(pull_request__head={"sha": "c" * 40, "repo": None})
    assert github_event_to_request("pull_request", p, policy()) == (None, "fork")


def test_repo_disabled_by_glob():
    pol = policy(repos={"acme/*": RepoOverride(enabled=False)})
    assert github_event_to_request("pull_request", pr_payload(), pol) == (None, "repo_disabled")
    pol = policy(repos={"other/*": RepoOverride(enabled=False)})
    assert github_event_to_request("pull_request", pr_payload(), pol)[0] is not None


def test_closed_state_ignored():
    p = pr_payload(action="synchronize", pull_request__state="closed")
    assert github_event_to_request("pull_request", p, policy()) == (None, "pr_not_open")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p.pop("pull_request"),
        lambda p: p["pull_request"]["head"].pop("sha"),
        lambda p: (p.pop("number"), p["pull_request"].pop("number")),
        lambda p: (p.pop("repository"), p["pull_request"]["base"].pop("repo")),
    ],
)
def test_malformed(mutate):
    p = pr_payload()
    mutate(p)
    req, reason = github_event_to_request("pull_request", p, policy())
    assert req is None
    assert reason.startswith("malformed")


def test_missing_installation_and_no_policy_defaults():
    p = pr_payload()
    p.pop("installation")
    req, _ = github_event_to_request("pull_request", p)
    assert req is not None
    assert req.installation_id is None
    fork = pr_payload(pull_request__head={"sha": "c" * 40, "repo": {"full_name": "x/y"}})
    assert github_event_to_request("pull_request", fork) == (None, "fork")
    draft = pr_payload(pull_request__draft=True)
    assert github_event_to_request("pull_request", draft)[0] is not None


def test_number_falls_back_to_pull_request():
    p = pr_payload()
    p.pop("number")
    req, _ = github_event_to_request("pull_request", p, policy())
    assert req is not None
    assert req.pr == 7

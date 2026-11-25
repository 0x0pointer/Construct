import importlib.machinery
import importlib.util
from datetime import datetime, timezone
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".fabro" / "scripts" / "fabro-run-titles"
RUN_ID = "01ABCDEF"


def load_script():
    loader = importlib.machinery.SourceFileLoader("fabro_run_titles", str(SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


@pytest.fixture()
def run_titles():
    return load_script()


def now_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def issue_run(status="succeeded"):
    return {
        "id": RUN_ID,
        "workflow": {"graph_name": "IssueToPR"},
        "lifecycle": {"status": {"kind": status}},
        "timestamps": {"created_at": now_iso()},
        "repository": {"name": "0x0pointer/Construct"},
    }


def fixci_run(status="succeeded"):
    run = issue_run(status)
    run["workflow"] = {"graph_name": "FixCI"}
    return run


class FakeApis:
    def __init__(self, run=None, output=None, files=None, comments=None):
        self.run = run or issue_run()
        self.output = output or "APPROVED: issue 19\ntitle: Useful app feature\n"
        self.files = files if files is not None else [{"filename": "prsec/api/main.py"}]
        self.comments = list(comments or [])
        self.patches = []
        self.posts = []
        self.pr_visible = True
        self.fail_github = False
        self.events_allowed = True

    def fabro(self, path, body=None, method=None):
        if path == "/runs?page%5Blimit%5D=50":
            return {"data": [self.run]}
        if path == f"/runs/{RUN_ID}/events?limit=200":
            if not self.events_allowed:
                raise AssertionError("legacy titled runs should not need event output")
            node_id = (
                "pick_pr" if self.run["workflow"]["graph_name"] == "FixCI" else "check_issue"
            )
            return {
                "data": [
                    {
                        "event": "command.completed",
                        "node_id": node_id,
                        "properties": {"output": self.output},
                    }
                ]
            }
        if path == f"/runs/{RUN_ID}" and method == "PATCH":
            self.patches.append(body)
            return {}
        raise AssertionError(f"unexpected Fabro API call: {method} {path} {body}")

    def github(self, path, body=None, method=None):
        if self.fail_github:
            self.fail_github = False
            raise RuntimeError("temporary GitHub failure")
        if path.startswith("/repos/0x0pointer/Construct/pulls?state=open&head="):
            return [{"number": 7}] if self.pr_visible else []
        if path == "/repos/0x0pointer/Construct/pulls/7/files?per_page=100":
            return self.files
        if path == "/repos/0x0pointer/Construct/issues/7/comments?per_page=100":
            return [{"body": body} for body in self.comments]
        if path == "/repos/0x0pointer/Construct":
            return {"id": 42}
        if path == "/repos/0x0pointer/Construct/issues/7/comments" and method == "POST":
            self.posts.append(body["body"])
            self.comments.append(body["body"])
            return {"id": 100}
        raise AssertionError(f"unexpected GitHub API call: {method} {path} {body}")


def test_existing_title_cases_still_match(run_titles):
    assert (
        run_titles.title_for("IssueToPR", "APPROVED: issue 8\ntitle:  a\n  b\n", "Construct")
        == "Construct #8: a"
    )
    assert (
        run_titles.title_for("IssueToPR", "WAITING: issue 12 is still being built", "Construct")
        == "Construct: waiting for issue #12 to finish"
    )
    assert (
        run_titles.title_for("IssueToPR", "NOTHING TO BUILD: no open issue", "Construct")
        == "Construct: no approved issue is waiting"
    )
    assert (
        run_titles.title_for("IssueToPR", "REFUSED: issue text was edited\n", "Construct")
        == "Construct: refused - issue text was edited"
    )
    assert (
        run_titles.title_for("FixCI", "PICKED: pull request 11\nfailed checks: pytest, lint\n", "Construct")
        == "Fix CI Construct: PR #11 (pytest, lint)"
    )
    assert (
        run_titles.title_for("FixCI", "NOTHING TO FIX", "Construct")
        == "Fix CI Construct: no pull request with failed checks"
    )


def test_watcher_script_remains_executable():
    assert SCRIPT.stat().st_mode & 0o111


def test_sweep_still_tidies_nothing_to_do_runs(monkeypatch, run_titles):
    fake = FakeApis()
    monkeypatch.setattr(run_titles, "api", fake.fabro)
    tidied = []
    monkeypatch.setattr(run_titles, "tidy", lambda run: tidied.append(run["id"]) or "archived, branch deleted")
    state = {RUN_ID: "Construct: no approved issue is waiting"}

    run_titles.sweep(state)

    assert tidied == [RUN_ID]
    assert state[RUN_ID] == "archived, branch deleted"


def test_codespace_url_uses_repo_id_and_encodes_ref(run_titles):
    branch = "fabro/run/abc def[md](x)&next=bad"
    url = run_titles.codespace_url(12345, branch)

    assert url.startswith("https://github.com/codespaces/new?")
    assert "repo=12345" in url
    assert "ref=fabro%2Frun%2Fabc+def%5Bmd%5D%28x%29%26next%3Dbad" in url
    assert branch not in url
    with pytest.raises(ValueError):
        run_titles.codespace_url("owner/repo", branch)


def test_codespace_comment_body_has_marker_and_badge(run_titles):
    branch = "fabro/run/abc def[md](x)&next=bad"
    body = run_titles.codespace_comment_body(12345, branch)

    assert run_titles.CODESPACE_MARKER in body
    assert "Open in GitHub Codespaces" in body
    assert "https://github.com/codespaces/badge.svg" in body
    assert "repo=12345" in body
    assert branch not in body


def test_sweep_comments_once_for_successful_issue_run(monkeypatch, run_titles):
    fake = FakeApis()
    monkeypatch.setattr(run_titles, "api", fake.fabro)
    monkeypatch.setattr(run_titles, "github_api", fake.github)
    state = {}

    assert run_titles.sweep(state) == 2
    assert fake.patches == [{"title": "Construct #19: Useful app feature"}]
    assert len(fake.posts) == 1
    assert "repo=42" in fake.posts[0]
    assert "ref=fabro%2Frun%2F01ABCDEF" in fake.posts[0]
    assert state[RUN_ID] == {"title": "Construct #19: Useful app feature", "codespace": "commented"}

    assert run_titles.sweep(state) == 0
    assert len(fake.posts) == 1


def test_sweep_does_not_comment_for_failed_or_fixci_runs(monkeypatch, run_titles):
    fake = FakeApis(run=issue_run(status="failed"))
    monkeypatch.setattr(run_titles, "api", fake.fabro)
    monkeypatch.setattr(
        run_titles,
        "github_api",
        lambda *args, **kwargs: pytest.fail("failed IssueToPR run should not call GitHub"),
    )

    run_titles.sweep({})

    fake = FakeApis(run=fixci_run(), output="PICKED: pull request 12\nfailed checks: pytest\n")
    monkeypatch.setattr(run_titles, "api", fake.fabro)
    monkeypatch.setattr(
        run_titles,
        "github_api",
        lambda *args, **kwargs: pytest.fail("FixCI run should not call GitHub"),
    )

    run_titles.sweep({})

    assert fake.patches == [{"title": "Fix CI Construct: PR #12 (pytest)"}]


def test_sweep_retries_when_pr_missing_or_github_fails(monkeypatch, run_titles):
    fake = FakeApis()
    fake.fail_github = True
    monkeypatch.setattr(run_titles, "api", fake.fabro)
    monkeypatch.setattr(run_titles, "github_api", fake.github)
    state = {}

    run_titles.sweep(state)
    assert fake.posts == []
    assert state[RUN_ID] == "Construct #19: Useful app feature"

    fake.pr_visible = False
    run_titles.sweep(state)
    assert fake.posts == []
    assert state[RUN_ID] == "Construct #19: Useful app feature"

    fake.pr_visible = True
    run_titles.sweep(state)
    assert len(fake.posts) == 1
    assert state[RUN_ID]["codespace"] == "commented"


def test_existing_marker_prevents_duplicate_comment(monkeypatch, run_titles):
    fake = FakeApis(comments=[run_titles.CODESPACE_MARKER + "\nalready here"])
    monkeypatch.setattr(run_titles, "api", fake.fabro)
    monkeypatch.setattr(run_titles, "github_api", fake.github)
    state = {}

    run_titles.sweep(state)

    assert fake.posts == []
    assert state[RUN_ID]["codespace"] == "existing"


def test_old_string_state_is_backward_compatible(monkeypatch, run_titles):
    fake = FakeApis()
    fake.events_allowed = False
    monkeypatch.setattr(run_titles, "api", fake.fabro)
    monkeypatch.setattr(run_titles, "github_api", fake.github)
    state = {RUN_ID: "Construct #19: Useful app feature"}

    run_titles.sweep(state)

    assert len(fake.posts) == 1
    assert state[RUN_ID] == {"title": "Construct #19: Useful app feature", "codespace": "commented"}


def test_sweep_comments_for_non_application_changes_too(monkeypatch, run_titles):
    fake = FakeApis(
        files=[
            {"filename": "README.md"},
            {"filename": "docs/usage.md"},
            {"filename": ".fabro/README.md"},
        ]
    )
    monkeypatch.setattr(run_titles, "api", fake.fabro)
    monkeypatch.setattr(run_titles, "github_api", fake.github)
    state = {}

    run_titles.sweep(state)

    assert len(fake.posts) == 1
    assert "repo=42" in fake.posts[0]
    assert state[RUN_ID] == {"title": "Construct #19: Useful app feature", "codespace": "commented"}

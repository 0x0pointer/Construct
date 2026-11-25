import importlib.util
import tomllib
import urllib.parse
from importlib.machinery import SourceFileLoader
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[2] / ".fabro" / "scripts" / "comment-codespace"
WORKFLOW = Path(__file__).resolve().parents[2] / ".fabro" / "workflows" / "issue-to-pr" / "workflow.toml"


def load_module():
    loader = SourceFileLoader("comment_codespace", str(SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def install_fake_api(module, monkeypatch, handler):
    calls = []

    def fake(url, token, method="GET", body=None):
        calls.append({"url": url, "token": token, "method": method, "body": body})
        return handler(url, token, method, body)

    monkeypatch.setattr(module, "request_json", fake)
    return calls


def test_codespace_url_encodes_run_branch():
    module = load_module()

    ref = "fabro/run/01M89HT34WNSPBX0B7B7ZF945W"
    body = module.comment_body("0x0pointer", "Construct", ref)

    assert module.MARKER in body
    assert "Open in GitHub Codespaces" in body
    assert "https://github.com/codespaces/badge.svg" in body
    assert (
        "https://codespaces.new/0x0pointer/Construct?quickstart=1"
        "&ref=fabro%2Frun%2F01M89HT34WNSPBX0B7B7ZF945W"
    ) in body


def test_main_posts_comment_for_matching_open_pr(monkeypatch):
    module = load_module()
    ref = "fabro/run/01M89HT34WNSPBX0B7B7ZF945W"

    def handler(url, _token, method, body):
        if "/pulls?" in url:
            return [{"number": 17, "state": "open", "head": {"ref": ref, "repo": {"full_name": "0x0pointer/Construct"}}}]
        if "/issues/17/comments?" in url:
            return []
        if url.endswith("/issues/17/comments") and method == "POST":
            return {"body": body["body"]}
        raise AssertionError(f"unexpected request: {method} {url}")

    calls = install_fake_api(module, monkeypatch, handler)
    monkeypatch.setenv("GITHUB_TOKEN", "secret-token")

    assert module.main(["0x0pointer", "Construct", ref]) == 0

    post_calls = [call for call in calls if call["method"] == "POST"]
    assert len(post_calls) == 1
    assert post_calls[0]["url"].endswith("/issues/17/comments")
    assert module.MARKER in post_calls[0]["body"]["body"]
    assert "Open in GitHub Codespaces" in post_calls[0]["body"]["body"]


def test_main_skips_existing_marker_on_later_comment_page(monkeypatch):
    module = load_module()
    ref = "fabro/run/01M89HT34WNSPBX0B7B7ZF945W"
    first_page = [{"body": "no marker here"} for _ in range(module.PAGE_SIZE)]

    def handler(url, _token, method, _body):
        if "/pulls?" in url:
            return [{"number": 17, "state": "open", "head": {"ref": ref, "repo": {"full_name": "0x0pointer/Construct"}}}]
        if "/issues/17/comments?" in url:
            page = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)["page"][0]
            if page == "1":
                return first_page
            if page == "2":
                return [{"body": f"already posted\n{module.MARKER}"}]
            raise AssertionError(f"unexpected page: {url}")
        if method == "POST":
            raise AssertionError("comment should not be posted twice")
        raise AssertionError(f"unexpected request: {method} {url}")

    calls = install_fake_api(module, monkeypatch, handler)
    monkeypatch.setenv("GITHUB_TOKEN", "secret-token")

    assert module.main(["0x0pointer", "Construct", ref]) == 0
    assert any("page=2" in call["url"] for call in calls)
    assert not [call for call in calls if call["method"] == "POST"]


def test_main_ignores_fork_and_wrong_branch_prs(monkeypatch, capsys):
    module = load_module()
    ref = "fabro/run/01M89HT34WNSPBX0B7B7ZF945W"

    def handler(_url, _token, method, _body):
        assert method == "GET"
        return [
            {"number": 17, "state": "open", "head": {"ref": ref, "repo": {"full_name": "someone-else/Construct"}}},
            {"number": 18, "state": "open", "head": {"ref": "feature/not-this-run", "repo": {"full_name": "0x0pointer/Construct"}}},
        ]

    calls = install_fake_api(module, monkeypatch, handler)
    monkeypatch.setenv("GITHUB_TOKEN", "secret-token")

    assert module.main(["0x0pointer", "Construct", ref]) == 0

    assert not [call for call in calls if call["method"] == "POST"]
    assert "no open same-repo pull request found" in capsys.readouterr().err


def test_main_fails_open_without_token_or_on_api_error(monkeypatch, capsys):
    module = load_module()
    ref = "fabro/run/01M89HT34WNSPBX0B7B7ZF945W"

    assert module.main(["0x0pointer", "Construct", ref]) == 0
    missing_err = capsys.readouterr().err
    assert "warning:" in missing_err

    token = "secret-token"
    monkeypatch.setenv("GITHUB_TOKEN", token)
    install_fake_api(module, monkeypatch, lambda _u, seen_token, _m, _b: (_ for _ in ()).throw(RuntimeError(f"boom {seen_token}")))

    assert module.main(["0x0pointer", "Construct", ref]) == 0
    error_err = capsys.readouterr().err
    assert "could not add Codespaces comment" in error_err
    assert token not in error_err


def test_issue_to_pr_workflow_has_nonblocking_codespace_hook():
    data = tomllib.loads(WORKFLOW.read_text())
    hooks = data["run"]["hooks"]
    hook = next(item for item in hooks if item["id"] == "codespace-comment")

    assert hook["event"] == "run_complete"
    assert hook["script"] == ".fabro/scripts/comment-codespace 0x0pointer Construct fabro/run/$FABRO_RUN_ID"
    assert hook["blocking"] is False
    assert hook["sandbox"] is True
    assert data["run"]["pull_request"]["enabled"] is True
    assert data["run"]["pull_request"]["draft"] is True

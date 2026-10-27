from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from prsec.adapters.scm import get_scm
from prsec.adapters.scm.github import (
    MAX_COMMITS,
    GitHubAppSCM,
    UnsafeArchiveError,
    safe_extract,
)

API = "https://gh.test/api/v3"
NOW = 1_700_000_000.0


@pytest.fixture(scope="module")
def keypair() -> tuple[str, object]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    return pem, key.public_key()


class Clock:
    def __init__(self, t: float = NOW) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def sleeps() -> list[float]:
    return []


@pytest.fixture
def scm(keypair, clock, sleeps) -> GitHubAppSCM:
    return GitHubAppSCM(app_id=1234, private_key=keypair[0], api_url=API, clock=clock, sleep=sleeps.append)


def iso(ts: float) -> str:
    from datetime import UTC, datetime

    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def token_route(mock: respx.MockRouter, iid: int = 7, token: str = "ghs_abc", ttl: float = 3600):
    return mock.post(f"{API}/app/installations/{iid}/access_tokens").mock(
        return_value=httpx.Response(201, json={"token": token, "expires_at": iso(NOW + ttl)})
    )


def pr_json(number: int = 5, head_repo: str | None = "acme/app", base_repo: str = "acme/app") -> dict:
    return {
        "number": number,
        "title": "Add thing",
        "body": None,
        "user": {"login": "dev"},
        "draft": False,
        "html_url": f"https://gh.test/{base_repo}/pull/{number}",
        "head": {"ref": "feat", "sha": "h" * 40, "repo": {"full_name": head_repo} if head_repo else None},
        "base": {"ref": "main", "sha": "b" * 40, "repo": {"full_name": base_repo}},
    }


# ------------------------------------------------------------------ auth


def test_jwt_claims(scm, keypair):
    token = scm.app_jwt()
    claims = jwt.decode(token, keypair[1], algorithms=["RS256"], options={"verify_exp": False, "verify_iat": False})
    assert claims["iss"] == "1234"
    assert claims["iat"] == int(NOW) - 60
    assert claims["exp"] - int(NOW) <= 600
    assert claims["exp"] > int(NOW)
    assert jwt.get_unverified_header(token)["alg"] == "RS256"


@respx.mock
def test_installation_token_cached_until_margin(scm, clock):
    route = token_route(respx.mock, ttl=3600)
    assert scm.installation_token(7) == "ghs_abc"
    clock.t = NOW + 3600 - 301
    assert scm.installation_token(7) == "ghs_abc"
    assert route.call_count == 1
    clock.t = NOW + 3600 - 299
    scm.installation_token(7)
    assert route.call_count == 2
    req = route.calls[0].request
    assert req.headers["authorization"].startswith("Bearer ")
    assert json.loads(req.content) == {
        "permissions": {"contents": "read", "pull_requests": "read", "metadata": "read"}
    }


@respx.mock
def test_scoped_token_requests_repository(scm):
    route = token_route(respx.mock)
    scm.installation_token(7, "acme/app")
    scm.installation_token(7, "acme/app")
    scm.installation_token(7)
    assert route.call_count == 2
    assert json.loads(route.calls[0].request.content)["repositories"] == ["app"]
    assert "repositories" not in json.loads(route.calls[1].request.content)


@respx.mock
def test_installation_resolved_when_missing(scm):
    inst = respx.get(f"{API}/repos/acme/app/installation").mock(return_value=httpx.Response(200, json={"id": 7}))
    token_route(respx.mock)
    respx.get(f"{API}/repos/acme/app/pulls/5").mock(return_value=httpx.Response(200, json=pr_json()))
    respx.get(f"{API}/repos/acme/app/pulls/5/commits").mock(return_value=httpx.Response(200, json=[]))
    respx.get(f"{API}/repos/acme/app/pulls/5/files").mock(return_value=httpx.Response(200, json=[]))
    scm.get_pr("acme/app", 5)
    scm.get_pr("acme/app", 5)
    assert inst.call_count == 1
    assert inst.calls[0].request.headers["authorization"].startswith("Bearer ")
    pr_req = respx.calls.last.request
    assert pr_req.headers["authorization"] == "token ghs_abc"


def test_invalid_repo_rejected(scm):
    with pytest.raises(ValueError):
        scm.get_pr("acme/../x", 1, installation_id=7)


# ------------------------------------------------------------------ get_pr


@respx.mock
def test_get_pr_paginates_and_caps(scm):
    token_route(respx.mock)
    respx.get(f"{API}/repos/acme/app/pulls/5").mock(return_value=httpx.Response(200, json=pr_json()))

    def commit(i: int) -> dict:
        return {"sha": f"{i:040d}", "commit": {"message": f"m{i}", "author": {"name": "N"}}, "author": None}

    def commits_page(request: httpx.Request) -> httpx.Response:
        page = int(request.url.params.get("page", "1"))
        items = [commit(i) for i in range((page - 1) * 100, page * 100)]
        headers = {"link": f'<{API}/repos/acme/app/pulls/5/commits?per_page=100&page={page + 1}>; rel="next"'}
        return httpx.Response(200, json=items, headers=headers)

    commits = respx.get(f"{API}/repos/acme/app/pulls/5/commits").mock(side_effect=commits_page)
    respx.get(f"{API}/repos/acme/app/pulls/5/files", params={"page": "2"}).mock(
        return_value=httpx.Response(200, json=[{"filename": "b.py"}])
    )
    respx.get(f"{API}/repos/acme/app/pulls/5/files").mock(
        return_value=httpx.Response(
            200,
            json=[{"filename": "a.py"}],
            headers={"link": f'<{API}/repos/acme/app/pulls/5/files?per_page=100&page=2>; rel="next"'},
        )
    )
    pr = scm.get_pr("acme/app", 5, installation_id=7)
    assert len(pr.commits) == MAX_COMMITS
    assert commits.call_count == 3
    assert pr.commits[0].message == "m0" and pr.commits[0].author == "N"
    assert pr.changed_files == ["a.py", "b.py"]
    assert pr.head_sha == "h" * 40 and pr.base_ref == "main" and pr.body == ""
    assert pr.is_fork is False
    assert pr.author == "dev"


@pytest.mark.parametrize(
    ("head_repo", "expected"),
    [("acme/app", False), ("ACME/App", False), ("mallory/app", True), (None, True)],
)
@respx.mock
def test_fork_detection(scm, head_repo, expected):
    token_route(respx.mock)
    respx.get(f"{API}/repos/acme/app/pulls/5").mock(
        return_value=httpx.Response(200, json=pr_json(head_repo=head_repo))
    )
    respx.get(f"{API}/repos/acme/app/pulls/5/commits").mock(return_value=httpx.Response(200, json=[]))
    respx.get(f"{API}/repos/acme/app/pulls/5/files").mock(return_value=httpx.Response(200, json=[]))
    assert scm.get_pr("acme/app", 5, installation_id=7).is_fork is expected


# ------------------------------------------------------------------ rate limiting


@respx.mock
def test_rate_limit_backoff_then_success(scm, sleeps):
    token_route(respx.mock)
    respx.get(f"{API}/repos/acme/app/pulls/5").mock(
        side_effect=[
            httpx.Response(403, headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": str(int(NOW) + 10)}),
            httpx.Response(429, headers={"retry-after": "3"}),
            httpx.Response(200, text="diff --git a/x b/x\n"),
        ]
    )
    assert scm.get_diff("acme/app", 5, installation_id=7).startswith("diff --git")
    assert sleeps == [11.0, 3.0]


@respx.mock
def test_rate_limit_gives_up_after_three_retries(scm, sleeps):
    token_route(respx.mock)
    route = respx.get(f"{API}/repos/acme/app/pulls/5").mock(
        return_value=httpx.Response(429, headers={"retry-after": "1"})
    )
    with pytest.raises(httpx.HTTPStatusError):
        scm.get_diff("acme/app", 5, installation_id=7)
    assert route.call_count == 4
    assert len(sleeps) == 3


@respx.mock
def test_plain_403_not_retried(scm, sleeps):
    token_route(respx.mock)
    route = respx.get(f"{API}/repos/acme/app/pulls/5").mock(return_value=httpx.Response(403))
    with pytest.raises(httpx.HTTPStatusError):
        scm.get_diff("acme/app", 5, installation_id=7)
    assert route.call_count == 1 and sleeps == []


# ------------------------------------------------------------------ diff


@respx.mock
def test_get_diff_uses_diff_media_type(scm):
    token_route(respx.mock)
    route = respx.get(f"{API}/repos/acme/app/pulls/5").mock(return_value=httpx.Response(200, text="DIFF"))
    assert scm.get_diff("acme/app", 5, installation_id=7) == "DIFF"
    assert route.calls[0].request.headers["accept"] == "application/vnd.github.diff"


@respx.mock
def test_get_diff_falls_back_to_files(scm):
    token_route(respx.mock)
    respx.get(f"{API}/repos/acme/app/pulls/5").mock(
        return_value=httpx.Response(406, json={"message": "Sorry, the diff exceeded the maximum number of lines"})
    )
    respx.get(f"{API}/repos/acme/app/pulls/5/files").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"filename": "new.py", "status": "added", "patch": "@@ -0,0 +1 @@\n+x = 1"},
                {"filename": "mod.py", "status": "modified", "patch": "@@ -1 +1 @@\n-a\n+b"},
                {"filename": "n.py", "previous_filename": "o.py", "status": "renamed", "patch": "@@ -1 +1 @@\n-c\n+d"},
                {"filename": "img.png", "status": "modified"},
                {"filename": "gone.py", "status": "removed", "patch": "@@ -1 +0,0 @@\n-z"},
            ],
        )
    )
    diff = scm.get_diff("acme/app", 5, installation_id=7)
    lines = diff.splitlines()
    assert lines[0].startswith("# prsec: diff reconstructed") and "1 without patch" in lines[0]
    assert "diff --git a/new.py b/new.py\n--- /dev/null\n+++ b/new.py\n@@ -0,0 +1 @@\n+x = 1" in diff
    assert "--- a/mod.py\n+++ b/mod.py" in diff
    assert "diff --git a/o.py b/n.py\nrename from o.py\nrename to n.py\n--- a/o.py\n+++ b/n.py" in diff
    assert "Binary files a/img.png and b/img.png differ" in diff
    assert "--- a/gone.py\n+++ /dev/null" in diff


# ------------------------------------------------------------------ list_open_prs


@respx.mock
def test_list_open_prs_all_installations(scm):
    respx.get(f"{API}/app/installations").mock(return_value=httpx.Response(200, json=[{"id": 7}, {"id": 8}]))
    token_route(respx.mock, 7, "t7")
    token_route(respx.mock, 8, "t8")

    def repos(request: httpx.Request) -> httpx.Response:
        tok = request.headers["authorization"]
        if tok == "token t7":
            return httpx.Response(200, json={"total_count": 2, "repositories": [
                {"full_name": "acme/app"}, {"full_name": "acme/old", "archived": True}]})
        return httpx.Response(200, json={"total_count": 1, "repositories": [{"full_name": "other/lib"}]})

    respx.get(f"{API}/installation/repositories").mock(side_effect=repos)
    app = respx.get(f"{API}/repos/acme/app/pulls").mock(
        return_value=httpx.Response(200, json=[pr_json(1), pr_json(2, head_repo="x/app")])
    )
    respx.get(f"{API}/repos/other/lib/pulls").mock(
        return_value=httpx.Response(200, json=[pr_json(9, "other/lib", "other/lib")])
    )
    prs = scm.list_open_prs()
    assert [(p.repo, p.number, p.is_fork) for p in prs] == [
        ("acme/app", 1, False), ("acme/app", 2, True), ("other/lib", 9, False)]
    assert all(p.commits == [] and p.changed_files == [] for p in prs)
    params = app.calls[0].request.url.params
    assert params["state"] == "open" and params["sort"] == "updated" and params["per_page"] == "100"
    # installation learned from the listing: no /installation lookup needed afterwards
    assert scm.resolve_installation("other/lib") == 8


# ------------------------------------------------------------------ tarball


def make_tar(entries: list[tuple[str, str, bytes | str]]) -> bytes:
    """entries: (kind, name, data_or_linkname); kind in file|dir|sym|hard|fifo|chr."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for kind, name, payload in entries:
            ti = tarfile.TarInfo(name)
            if kind == "file":
                data = payload if isinstance(payload, bytes) else payload.encode()
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
                continue
            ti.type = {"dir": tarfile.DIRTYPE, "sym": tarfile.SYMTYPE, "hard": tarfile.LNKTYPE,
                       "fifo": tarfile.FIFOTYPE, "chr": tarfile.CHRTYPE}[kind]
            if kind in ("sym", "hard"):
                ti.linkname = str(payload)
            if kind == "dir":
                ti.mode = 0o755
            tf.addfile(ti)
    return buf.getvalue()


GOOD = [
    ("dir", "acme-app-abc123/", b""),
    ("file", "acme-app-abc123/README.md", "hi"),
    ("dir", "acme-app-abc123/src/", b""),
    ("file", "acme-app-abc123/src/main.py", "print(1)"),
    ("sym", "acme-app-abc123/src/link.py", "main.py"),
    ("hard", "acme-app-abc123/copy.md", "acme-app-abc123/README.md"),
]


@respx.mock
def test_fetch_source_follows_redirect_and_strips_top(scm, tmp_path):
    token_route(respx.mock)
    respx.get(f"{API}/repos/acme/app/tarball/{'h' * 40}").mock(
        return_value=httpx.Response(302, headers={"location": "https://codeload.gh.test/acme/app/tar.gz/hhh"})
    )
    cl = respx.get("https://codeload.gh.test/acme/app/tar.gz/hhh").mock(
        return_value=httpx.Response(200, content=make_tar(GOOD))
    )
    dest = scm.fetch_source("acme/app", "h" * 40, tmp_path / "src", installation_id=7)
    assert dest == tmp_path / "src"
    assert (dest / "README.md").read_text() == "hi"
    assert (dest / "src/main.py").read_text() == "print(1)"
    assert (dest / "src/link.py").is_symlink() and (dest / "src/link.py").read_text() == "print(1)"
    assert (dest / "copy.md").read_text() == "hi"
    assert not (dest / "acme-app-abc123").exists()
    assert "authorization" not in cl.calls[0].request.headers


@pytest.mark.parametrize(
    "bad",
    [
        [("file", "/etc/passwd", "x")],
        [("file", "top/../../evil", "x")],
        [("file", "top/a/../../../evil", "x")],
        [("sym", "top/s", "/etc/passwd")],
        [("sym", "top/s", "../../outside")],
        [("sym", "top/d", "."), ("sym", "top/d/t", "..")],
        [("sym", "top/d", "sub"), ("file", "top/d/x", "x")],
        [("hard", "top/h", "/etc/passwd")],
        [("hard", "top/h", "top/../../etc/passwd")],
        [("fifo", "top/f", b"")],
        [("chr", "top/dev", b"")],
    ],
    ids=["abs", "dotdot", "dotdot-nested", "sym-abs", "sym-escape", "sym-chain", "through-sym",
         "hard-abs", "hard-escape", "fifo", "chardev"],
)
def test_safe_extract_rejects_malicious(tmp_path, bad):
    data = make_tar([("dir", "top/", b""), ("file", "top/ok.txt", "ok"), *bad])
    dest = tmp_path / "out"
    dest.mkdir()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf, pytest.raises(UnsafeArchiveError):
        safe_extract(tf, dest, strip_top=True)
    assert list(dest.iterdir()) == []  # validated before anything is written
    assert not (tmp_path / "evil").exists() and not (tmp_path / "outside").exists()


def test_safe_extract_requires_single_top(tmp_path):
    data = make_tar([("file", "a/x", "1"), ("file", "b/y", "2")])
    with tarfile.open(fileobj=io.BytesIO(data)) as tf, pytest.raises(UnsafeArchiveError):
        safe_extract(tf, tmp_path, strip_top=True)


# ------------------------------------------------------------------ get_scm


def test_get_scm_singleton():
    assert get_scm() is get_scm("github")
    assert get_scm().name == "github"
    with pytest.raises(ValueError):
        get_scm("gitlab")


def test_private_key_from_settings(monkeypatch, keypair, tmp_path):
    from prsec.config import settings

    key_file = tmp_path / "app.pem"
    key_file.write_text(keypair[0])
    monkeypatch.setenv("PRSEC_GITHUB_APP_ID", "99")
    monkeypatch.setenv("PRSEC_GITHUB_PRIVATE_KEY_PATH", str(key_file))
    monkeypatch.delenv("PRSEC_GITHUB_PRIVATE_KEY", raising=False)
    settings.cache_clear()
    try:
        claims = jwt.decode(GitHubAppSCM().app_jwt(), keypair[1], algorithms=["RS256"])
        assert claims["iss"] == "99"
    finally:
        settings.cache_clear()

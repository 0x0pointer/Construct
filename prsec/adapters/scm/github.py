"""Read-only GitHub App SCM adapter (github.com and GHES via settings().github_api_url)."""
from __future__ import annotations

import re
import tarfile
import tempfile
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

import httpx
import jwt

from prsec.config import settings
from prsec.models import PRCommit, PRInfo

API_VERSION = "2022-11-28"
READ_PERMISSIONS = {"contents": "read", "pull_requests": "read", "metadata": "read"}
MAX_COMMITS = 250
MAX_FILES = 3000
TOKEN_REFRESH_MARGIN_S = 300
MAX_RETRIES = 3
MAX_BACKOFF_S = 120.0
MAX_TARBALL_BYTES = 2 * 1024**3

_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,64}$|^[A-Za-z0-9_./-]+$")


class GitHubError(RuntimeError):
    pass


class UnsafeArchiveError(GitHubError):
    pass


@dataclass
class _Token:
    token: str
    expires_at: float


def _split_repo(repo: str) -> tuple[str, str]:
    if not _REPO_RE.match(repo) or ".." in repo:
        raise ValueError(f"invalid repo name: {repo!r}")
    owner, name = repo.split("/", 1)
    return owner, name


def _load_private_key() -> str:
    s = settings()
    if s.github_private_key:
        return s.github_private_key.replace("\\n", "\n")
    if s.github_private_key_path:
        return Path(s.github_private_key_path).read_text()
    raise GitHubError("no GitHub App private key configured (PRSEC_GITHUB_PRIVATE_KEY[_PATH])")


class GitHubAppSCM:
    name = "github"

    def __init__(
        self,
        app_id: int | None = None,
        private_key: str | None = None,
        api_url: str | None = None,
        *,
        client: httpx.Client | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.time,
    ) -> None:
        s = settings()
        self.app_id = app_id if app_id is not None else s.github_app_id
        self._private_key = private_key
        self.api_url = (api_url or s.github_api_url).rstrip("/")
        self._client = client or httpx.Client(
            base_url=self.api_url,
            timeout=httpx.Timeout(30.0, connect=10.0),
            headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": API_VERSION,
                "User-Agent": "prsec",
            },
        )
        self._sleep = sleep
        self._clock = clock
        self._lock = threading.Lock()
        self._tokens: dict[tuple[int, str | None], _Token] = {}
        self._installations: dict[str, int] = {}

    # ---------------------------------------------------------------- auth

    def app_jwt(self) -> str:
        if self.app_id is None:
            raise GitHubError("PRSEC_GITHUB_APP_ID not configured")
        if self._private_key is None:
            self._private_key = _load_private_key()
        now = int(self._clock())
        payload = {"iat": now - 60, "exp": now + 540, "iss": str(self.app_id)}
        return jwt.encode(payload, self._private_key, algorithm="RS256")

    def installation_token(self, installation_id: int, repo: str | None = None) -> str:
        """Installation access token, optionally scoped to one repo; cached until 5 min before expiry."""
        repo_name = _split_repo(repo)[1] if repo else None
        key = (installation_id, repo_name)
        with self._lock:
            cached = self._tokens.get(key)
            if cached and cached.expires_at - TOKEN_REFRESH_MARGIN_S > self._clock():
                return cached.token
        body: dict[str, Any] = {"permissions": READ_PERMISSIONS}
        if repo_name:
            body["repositories"] = [repo_name]
        r = self._request(
            "POST", f"/app/installations/{int(installation_id)}/access_tokens", auth=self._jwt_auth(), json=body
        )
        data = r.json()
        tok = _Token(data["token"], datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00")).timestamp())
        with self._lock:
            self._tokens[key] = tok
        return tok.token

    def resolve_installation(self, repo: str) -> int:
        owner, name = _split_repo(repo)
        with self._lock:
            if repo in self._installations:
                return self._installations[repo]
        r = self._request("GET", f"/repos/{owner}/{name}/installation", auth=self._jwt_auth())
        iid = int(r.json()["id"])
        with self._lock:
            self._installations[repo] = iid
        return iid

    def _jwt_auth(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.app_jwt()}"}

    def _repo_auth(self, repo: str, installation_id: int | None) -> dict[str, str]:
        iid = installation_id if installation_id is not None else self.resolve_installation(repo)
        return {"Authorization": f"token {self.installation_token(iid, repo)}"}

    # ---------------------------------------------------------------- http

    def _backoff(self, r: httpx.Response, attempt: int) -> float | None:
        if r.status_code not in (403, 429):
            return None
        retry_after = r.headers.get("retry-after")
        if retry_after is not None:
            try:
                return min(float(retry_after), MAX_BACKOFF_S)
            except ValueError:
                return min(2.0**attempt, MAX_BACKOFF_S)
        if r.headers.get("x-ratelimit-remaining") == "0":
            reset = r.headers.get("x-ratelimit-reset")
            wait = float(reset) - self._clock() + 1 if reset and reset.isdigit() else 2.0**attempt
            return min(max(wait, 1.0), MAX_BACKOFF_S)
        if r.status_code == 429:
            return min(2.0**attempt, MAX_BACKOFF_S)
        return None

    def _request(
        self,
        method: str,
        url: str,
        *,
        auth: dict[str, str],
        headers: dict[str, str] | None = None,
        ok: tuple[int, ...] = (),
        **kw: Any,
    ) -> httpx.Response:
        hdrs = {**auth, **(headers or {})}
        for attempt in range(MAX_RETRIES + 1):
            r = self._client.request(method, url, headers=hdrs, **kw)
            wait = self._backoff(r, attempt) if attempt < MAX_RETRIES else None
            if wait is None:
                break
            self._sleep(wait)
        if r.status_code in ok:
            return r
        r.raise_for_status()
        return r

    def _paginate(
        self, url: str, *, auth: dict[str, str], cap: int, params: dict[str, Any] | None = None, key: str | None = None
    ) -> Iterator[dict[str, Any]]:
        n = 0
        next_url: str | None = url
        next_params: dict[str, Any] | None = {"per_page": 100, **(params or {})}
        while next_url and n < cap:
            r = self._request("GET", next_url, auth=auth, params=next_params)
            data = r.json()
            items = data[key] if key else data
            for item in items:
                if n >= cap:
                    return
                n += 1
                yield item
            next_url = r.links.get("next", {}).get("url")
            next_params = None  # the next link already carries the query

    # ---------------------------------------------------------------- SCMAdapter

    def get_pr(self, repo: str, number: int, installation_id: int | None = None) -> PRInfo:
        owner, name = _split_repo(repo)
        auth = self._repo_auth(repo, installation_id)
        base = f"/repos/{owner}/{name}/pulls/{int(number)}"
        pr = self._request("GET", base, auth=auth).json()
        commits = [
            PRCommit(
                sha=c["sha"],
                message=(c.get("commit") or {}).get("message", ""),
                author=(c.get("author") or {}).get("login") or ((c.get("commit") or {}).get("author") or {}).get("name"),
            )
            for c in self._paginate(f"{base}/commits", auth=auth, cap=MAX_COMMITS)
        ]
        files = [f["filename"] for f in self._paginate(f"{base}/files", auth=auth, cap=MAX_FILES)]
        return _pr_info(repo, pr, commits=commits, files=files)

    def get_diff(self, repo: str, number: int, installation_id: int | None = None) -> str:
        owner, name = _split_repo(repo)
        auth = self._repo_auth(repo, installation_id)
        base = f"/repos/{owner}/{name}/pulls/{int(number)}"
        r = self._request(
            "GET", base, auth=auth, headers={"Accept": "application/vnd.github.diff"}, ok=(406, 422)
        )
        if r.status_code == 200:
            return r.text
        return self._diff_from_files(base, auth)

    def _diff_from_files(self, base: str, auth: dict[str, str]) -> str:
        files = list(self._paginate(f"{base}/files", auth=auth, cap=MAX_FILES + 1))
        capped = len(files) > MAX_FILES
        files = files[:MAX_FILES]
        missing = sum(1 for f in files if not f.get("patch"))
        note = f"# prsec: diff reconstructed from /files patches ({len(files)} files"
        if missing:
            note += f", {missing} without patch (binary or too large)"
        if capped:
            note += f", truncated at {MAX_FILES} files"
        out = [note + ")"]
        for f in files:
            new = f["filename"]
            old = f.get("previous_filename") or new
            status = f.get("status")
            out.append(f"diff --git a/{old} b/{new}")
            if status == "renamed":
                out += [f"rename from {old}", f"rename to {new}"]
            patch = f.get("patch")
            if not patch:
                out.append(f"Binary files a/{old} and b/{new} differ (patch omitted by GitHub)")
                continue
            out.extend((
                "--- /dev/null" if status == "added" else f"--- a/{old}",
                "+++ /dev/null" if status == "removed" else f"+++ b/{new}",
                patch.rstrip("\n"),
            ))
        return "\n".join(out) + "\n"

    def fetch_source(self, repo: str, sha: str, dest: Path, installation_id: int | None = None) -> Path:
        owner, name = _split_repo(repo)
        if not _SHA_RE.match(sha) or ".." in sha:
            raise ValueError(f"invalid ref: {sha!r}")
        auth = self._repo_auth(repo, installation_id)
        dest = Path(dest)
        dest.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryFile() as buf:
            # httpx drops Authorization on the cross-origin redirect to codeload.
            with self._client.stream(
                "GET",
                f"/repos/{owner}/{name}/tarball/{sha}",
                headers=auth,
                follow_redirects=True,
                timeout=httpx.Timeout(300.0, connect=10.0),
            ) as r:
                r.raise_for_status()
                size = 0
                for chunk in r.iter_bytes(1 << 20):
                    size += len(chunk)
                    if size > MAX_TARBALL_BYTES:
                        raise GitHubError(f"tarball for {repo}@{sha} exceeds {MAX_TARBALL_BYTES} bytes")
                    buf.write(chunk)
            buf.seek(0)
            with tarfile.open(fileobj=buf, mode="r:*") as tf:
                safe_extract(tf, dest, strip_top=True)
        return dest

    def list_open_prs(self, installation_id: int | None = None) -> list[PRInfo]:
        """Open PRs for every repo visible to the installation(s).

        To keep API usage bounded only the first page (100 most recently updated) per repo
        is fetched, and `commits` / `changed_files` are left empty; callers needing them
        should call `get_pr`.
        """
        if installation_id is not None:
            iids = [installation_id]
        else:
            iids = [int(i["id"]) for i in self._paginate("/app/installations", auth=self._jwt_auth(), cap=10_000)]
        out: list[PRInfo] = []
        for iid in iids:
            auth = {"Authorization": f"token {self.installation_token(iid)}"}
            for repo in self._paginate("/installation/repositories", auth=auth, cap=100_000, key="repositories"):
                full = repo["full_name"]
                with self._lock:
                    self._installations[full] = iid
                if repo.get("archived"):
                    continue
                r = self._request(
                    "GET",
                    f"/repos/{full}/pulls",
                    auth=auth,
                    params={"state": "open", "sort": "updated", "direction": "desc", "per_page": 100},
                )
                out.extend(_pr_info(full, pr) for pr in r.json())
        return out


def _pr_info(repo: str, pr: dict[str, Any], *, commits: list[PRCommit] | None = None, files: list[str] | None = None) -> PRInfo:
    head, base = pr["head"], pr["base"]
    head_repo = (head.get("repo") or {}).get("full_name")
    base_repo = (base.get("repo") or {}).get("full_name") or repo
    return PRInfo(
        scm="github",
        repo=repo,
        number=int(pr["number"]),
        title=pr.get("title") or "",
        body=pr.get("body") or "",
        author=(pr.get("user") or {}).get("login"),
        base_ref=base["ref"],
        base_sha=base["sha"],
        head_ref=head["ref"],
        head_sha=head["sha"],
        draft=bool(pr.get("draft")),
        is_fork=head_repo is None or head_repo.lower() != base_repo.lower(),
        commits=commits or [],
        changed_files=files or [],
        url=pr.get("html_url"),
    )


# -------------------------------------------------------------------- tar safety


def _check_rel(name: str, what: str) -> PurePosixPath:
    p = PurePosixPath(name)
    if p.is_absolute() or name.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", name):
        raise UnsafeArchiveError(f"absolute {what}: {name!r}")
    if ".." in p.parts or "\\" in name:
        raise UnsafeArchiveError(f"path traversal in {what}: {name!r}")
    return p


def _single_top(members: list[tarfile.TarInfo]) -> str:
    tops = {p.parts[0] for p in (_check_rel(m.name, "member") for m in members) if p.parts}
    if len(tops) != 1:
        raise UnsafeArchiveError(f"expected a single top-level directory, got {sorted(tops)[:5]}")
    return tops.pop()


def _strip(name: str, top: str | None) -> str | None:
    parts = _check_rel(name, "member").parts
    if top is not None:
        parts = parts[1:]
    return "/".join(parts) if parts else None


def _plan_member(m: tarfile.TarInfo, rel: str, dest: Path, top: str | None, symlinks: set[str]) -> tarfile.TarInfo:
    """Validate one (already stripped) member against `dest`; returns it renamed to `rel`."""
    parts = rel.split("/")
    if any("/".join(parts[:i]) in symlinks for i in range(1, len(parts))):
        raise UnsafeArchiveError(f"member written through a symlink: {m.name!r}")
    target = (dest / rel).resolve()
    if not target.is_relative_to(dest):
        raise UnsafeArchiveError(f"member escapes destination: {m.name!r}")
    if m.issym():
        if PurePosixPath(m.linkname).is_absolute():
            raise UnsafeArchiveError(f"absolute symlink target: {m.name!r} -> {m.linkname!r}")
        link_target = ((dest / rel).parent / m.linkname).resolve()
        if not link_target.is_relative_to(dest):
            raise UnsafeArchiveError(f"symlink escapes destination: {m.name!r} -> {m.linkname!r}")
        symlinks.add(rel)
    if m.islnk():
        linked = _strip(m.linkname, top)
        if linked is None or not (dest / linked).resolve().is_relative_to(dest):
            raise UnsafeArchiveError(f"hardlink escapes destination: {m.name!r} -> {m.linkname!r}")
        m = m.replace(linkname=linked, deep=False)
    return m.replace(name=rel, deep=False)


def safe_extract(tf: tarfile.TarFile, dest: Path, *, strip_top: bool = False) -> None:
    """Validate every member first, then extract. Rejects absolute paths, '..', links escaping
    `dest`, and device/fifo members. With strip_top, removes the single top-level directory."""
    dest = Path(dest).resolve()
    members = tf.getmembers()
    top = _single_top(members) if strip_top else None

    plan: list[tarfile.TarInfo] = []
    symlinks: set[str] = set()
    for m in members:
        if not (m.isfile() or m.isdir() or m.issym() or m.islnk()):
            raise UnsafeArchiveError(f"unsupported member type for {m.name!r}")
        rel = _strip(m.name, top)
        if rel is not None:
            plan.append(_plan_member(m, rel, dest, top, symlinks))

    # data filter: defence in depth (re-checks with real paths, drops setuid bits / ownership).
    tf.extraction_filter = tarfile.data_filter

    try:
        for m in plan:
            tf.extract(m, dest)
    except tarfile.FilterError as e:
        raise UnsafeArchiveError(str(e)) from e

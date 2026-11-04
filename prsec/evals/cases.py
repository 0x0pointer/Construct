"""Eval cases (prsec-skills/evals/cases/<id>): load them and lay out their head and base source.

A case directory holds `pr.json`, `diff.patch`, `repo/` (the head state), `expected.json` and,
for dynamic cases, `reference/envspec.json` + `reference/poc.yaml`. The base state is `repo/` with
`diff.patch` reverse-applied. See prsec-skills/evals/README.md.
"""
from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from prsec.config import settings
from prsec.dynamic.envspec import EnvSpec
from prsec.dynamic.poc import PoC
from prsec.models import PRCommit, PRInfo

DEFAULT_CASES = Path(__file__).resolve().parents[2] / "prsec-skills" / "evals" / "cases"
DYNAMIC_TAG = "dynamic"
PR_FILE, DIFF_FILE, EXPECTED_FILE, REPO_DIR = "pr.json", "diff.patch", "expected.json", "repo"
REPO_OWNER = "evals"  # eval scans use repo evals/<case-id> and scm "evals"
CASE_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")


def case_sha(number: int, base: bool = False) -> str:
    """Cases have no git history: a placeholder sha that names the PR and the side ('a' head, 'b' base)."""
    return ("b" if base else "a") + f"{number:039d}"


def parse_case_sha(sha: str) -> tuple[int, bool]:
    """(PR number, is_base) of a `case_sha`."""
    if len(sha) != 40 or sha[0] not in "ab" or not sha[1:].isdigit():
        raise ValueError(f"not an eval case sha: {sha!r}")
    return int(sha[1:]), sha[0] == "b"


class CaseError(RuntimeError):
    """A case directory is incomplete, or its diff does not reverse-apply."""


@dataclass(frozen=True)
class Case:
    id: str
    dir: Path
    pr: dict[str, Any]
    expected: dict[str, Any]

    @property
    def repo(self) -> Path:
        return self.dir / REPO_DIR

    @property
    def diff(self) -> str:
        return (self.dir / DIFF_FILE).read_text()

    @property
    def tags(self) -> list[str]:
        return list(self.expected.get("tags") or [])

    @property
    def has_reference(self) -> bool:
        ref = self.dir / "reference"
        return (ref / "envspec.json").is_file() and (ref / "poc.yaml").is_file()

    @property
    def dynamic(self) -> bool:
        """Meant to be reproduced dynamically, with a reference envspec + PoC to compare against."""
        return DYNAMIC_TAG in self.tags and self.has_reference

    def reference_envspec(self) -> EnvSpec:
        return EnvSpec.model_validate_json((self.dir / "reference" / "envspec.json").read_text())

    def reference_poc(self) -> PoC:
        return PoC.model_validate(yaml.safe_load((self.dir / "reference" / "poc.yaml").read_text()))

    def pr_info(self, repo: str, number: int) -> PRInfo:
        p = self.pr
        return PRInfo(
            scm=REPO_OWNER, repo=repo, number=number, title=p["title"], body=p.get("body", ""), base_ref=p.get("base_ref", "main"),
            base_sha=case_sha(number, base=True), head_ref=p.get("head_ref", f"case/{self.id}"),
            head_sha=case_sha(number),
            changed_files=list(p.get("changed_files") or []),
            commits=[PRCommit.model_validate(c) for c in p.get("commits") or []],
        )


def load_case(case_dir: Path) -> Case:
    case_dir = Path(case_dir)
    for name in (PR_FILE, DIFF_FILE, EXPECTED_FILE, REPO_DIR):
        if not (case_dir / name).exists():
            raise CaseError(f"case {case_dir.name}: missing {name}")
    return Case(
        id=case_dir.name, dir=case_dir,
        pr=json.loads((case_dir / PR_FILE).read_text()),
        expected=json.loads((case_dir / EXPECTED_FILE).read_text()),
    )


def cases_root() -> Path:
    """The eval cases of this deployment: the mounted skills' evals/cases, else the repository's copy."""
    mounted = settings().skills_dir / "evals" / "cases"
    return mounted if mounted.is_dir() else DEFAULT_CASES


def list_cases(root: Path | None = None) -> list[Case]:
    base = Path(root) if root is not None else cases_root()
    return [load_case(d) for d in sorted(base.iterdir()) if d.is_dir() and (d / EXPECTED_FILE).is_file()]


def head_source(case: Case, dest: Path) -> Path:
    """Copy the head state (repo/) to a fresh `dest`. Returns dest."""
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(case.repo, dest)
    return dest


def base_source(case: Case, dest: Path) -> Path:
    """The base state in a fresh `dest`: repo/ with diff.patch reverse-applied, in pure Python (no git
    in the service image). Strict like `git apply`: every hunk must match exactly, else CaseError."""
    head_source(case, dest)
    try:
        for old_path, new_path, hunks in parse_patch(case.diff):
            _reverse_file(dest, old_path, new_path, hunks)
    except (ValueError, OSError) as e:
        raise CaseError(f"case {case.id}: {DIFF_FILE} does not reverse-apply: {e}") from None
    return dest


_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
Hunk = tuple[int, int, list[str]]  # (new start line, new line count, body lines with ' '/'-'/'+' prefix)


def _patch_path(raw: str, prefix: str) -> str | None:
    path = raw.split("\t", 1)[0].strip()
    if path == "/dev/null":
        return None
    return path[len(prefix):] if path.startswith(prefix) else path


def _hunk_body(lines: list[str], i: int, old_n: int, new_n: int) -> tuple[list[str], int]:
    """The body of one hunk (line counts from its header), keeping each line's newline; a
    '\\ No newline at end of file' marker strips the newline of the line before it."""
    body: list[str] = []
    seen_old = seen_new = 0
    while i < len(lines) and (seen_old < old_n or seen_new < new_n or lines[i].startswith("\\")):
        line = lines[i]
        if line.startswith("\\"):
            if body:
                body[-1] = body[-1].rstrip("\n")
        elif line[:1] in (" ", "-", "+") or line in ("\n", ""):
            line = line if line[:1] in (" ", "-", "+") else " " + line
            seen_old += line[0] in " -"
            seen_new += line[0] in " +"
            body.append(line)
        else:
            raise ValueError(f"malformed hunk line {i + 1}: {line[:60]!r}")
        i += 1
    if seen_old != old_n or seen_new != new_n:
        raise ValueError("hunk shorter than its header says")
    return body, i


def parse_patch(text: str) -> list[tuple[str | None, str | None, list[Hunk]]]:
    """Files of a unified diff: (old path, new path, hunks); /dev/null is None. No renames or binaries."""
    lines = text.splitlines(keepends=True)
    files: list[tuple[str | None, str | None, list[Hunk]]] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("--- ") and i + 1 < len(lines) and lines[i + 1].startswith("+++ "):
            files.append((_patch_path(line[4:], "a/"), _patch_path(lines[i + 1][4:], "b/"), []))
            i += 2
            continue
        m = _HUNK.match(line)
        if m:
            if not files:
                raise ValueError("hunk before any file header")
            old_n = int(m.group(2)) if m.group(2) is not None else 1
            new_n = int(m.group(4)) if m.group(4) is not None else 1
            body, i = _hunk_body(lines, i + 1, old_n, new_n)
            files[-1][2].append((int(m.group(3)), new_n, body))
            continue
        if line.startswith(("rename ", "Binary files", "GIT binary patch")):
            raise ValueError(f"unsupported patch content: {line.strip()[:60]}")
        i += 1
    if not files:
        raise ValueError("no file in the patch")
    return files


def _reverse_file(root: Path, old_path: str | None, new_path: str | None, hunks: list[Hunk]) -> None:
    if old_path is not None and new_path is not None and old_path != new_path:
        raise ValueError(f"renames are not supported ({old_path} -> {new_path})")
    if new_path is None:  # the PR deleted it: recreate it from the removed lines
        target = _inside(root, old_path or "")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("".join(l[1:] for _, _, body in hunks for l in body if l[0] in " -"))
        return
    target = _inside(root, new_path)
    if old_path is None:  # the PR added it: it did not exist on base
        target.unlink()
        return
    head = target.read_text().splitlines(keepends=True)
    offset = 0
    for start, count, body in hunks:
        expected = [l[1:] for l in body if l[0] in " +"]
        replacement = [l[1:] for l in body if l[0] in " -"]
        pos = start - 1 + offset if count else start + offset
        if head[pos:pos + len(expected)] != expected:
            raise ValueError(f"{new_path}: hunk at line {start} does not match the head file")
        head[pos:pos + len(expected)] = replacement
        offset += len(replacement) - len(expected)
    target.write_text("".join(head))


def _inside(root: Path, rel: str) -> Path:
    target = (root / rel).resolve()
    if not rel or not target.is_relative_to(root.resolve()):
        raise ValueError(f"patch path {rel!r} leaves the case repository")
    return target


class CaseSCM:
    """SCMAdapter "evals": repo `evals/<case-id>` is that case, any PR number; the placeholder shas
    (`case_sha`) pick head or base. Reads nothing but the case directories under `root`."""

    name = "evals"

    def __init__(self, root: Path | None = None):
        self._root = Path(root) if root is not None else None

    @property
    def root(self) -> Path:
        if self._root is not None:
            return self._root
        return cases_root()

    def case(self, repo: str) -> Case:
        owner, _, case_id = repo.partition("/")
        if owner != REPO_OWNER or not CASE_ID.fullmatch(case_id):
            raise CaseError(f"not an eval case repo: {repo!r} (expected {REPO_OWNER}/<case-id>)")
        case_dir = self.root / case_id
        if not (case_dir / EXPECTED_FILE).is_file():
            raise CaseError(f"no eval case {case_id!r} under {self.root}")
        return load_case(case_dir)

    def get_pr(self, repo: str, number: int, installation_id: int | None = None) -> PRInfo:  # NOSONAR(S1172) SCMAdapter signature
        return self.case(repo).pr_info(repo, number)

    def get_diff(self, repo: str, number: int, installation_id: int | None = None) -> str:  # NOSONAR(S1172) SCMAdapter signature
        return self.case(repo).diff

    def fetch_source(self, repo: str, sha: str, dest: Path, installation_id: int | None = None) -> Path:  # NOSONAR(S1172) SCMAdapter signature
        _, is_base = parse_case_sha(sha)
        case = self.case(repo)
        return base_source(case, dest) if is_base else head_source(case, dest)

    def list_open_prs(self, installation_id: int | None = None) -> list[PRInfo]:  # NOSONAR(S1172) SCMAdapter signature
        return []  # eval scans are queued explicitly (prsec-eval), never by the reconciler

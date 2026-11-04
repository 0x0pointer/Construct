"""Eval cases (prsec-skills/evals/cases/<id>): load them and lay out their head and base source.

A case directory holds `pr.json`, `diff.patch`, `repo/` (the head state), `expected.json` and,
for dynamic cases, `reference/envspec.json` + `reference/poc.yaml`. The base state is `repo/` with
`diff.patch` reverse-applied. See prsec-skills/evals/README.md.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
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


def list_cases(root: Path = DEFAULT_CASES) -> list[Case]:
    return [load_case(d) for d in sorted(Path(root).iterdir()) if d.is_dir() and (d / EXPECTED_FILE).is_file()]


def head_source(case: Case, dest: Path) -> Path:
    """Copy the head state (repo/) to a fresh `dest`. Returns dest."""
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(case.repo, dest)
    return dest


def base_source(case: Case, dest: Path) -> Path:
    """The base state in a fresh `dest`: repo/ with diff.patch reverse-applied (no .git left behind).

    A throwaway `git init` makes `git apply` resolve paths against `dest`, even when `dest` sits
    inside another work tree."""
    head_source(case, dest)
    try:
        subprocess.run(["git", "init", "-q"], cwd=dest, check=True, capture_output=True)
        proc = subprocess.run(["git", "apply", "-R", "--whitespace=nowarn", str(case.dir / DIFF_FILE)],
                              cwd=dest, capture_output=True, text=True)
    finally:
        shutil.rmtree(dest / ".git", ignore_errors=True)
    if proc.returncode != 0:
        raise CaseError(f"case {case.id}: {DIFF_FILE} does not reverse-apply: {proc.stderr.strip()[:500]}")
    return dest


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
        mounted = settings().skills_dir / "evals" / "cases"  # the skills mounted for this deployment
        return mounted if mounted.is_dir() else DEFAULT_CASES

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

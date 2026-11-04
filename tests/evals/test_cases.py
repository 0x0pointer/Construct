"""prsec.evals.cases: loading cases, head/base source, the evals SCM."""
from pathlib import Path

import pytest

from prsec.adapters import scm as scm_pkg
from prsec.evals.cases import (
    CaseError,
    CaseSCM,
    base_source,
    case_sha,
    list_cases,
    load_case,
    parse_case_sha,
)

CASES = {c.id: c for c in list_cases()}
ROOT = Path(__file__).resolve().parents[2] / "prsec-skills" / "evals" / "cases"


def test_lists_every_case_dir():
    assert set(CASES) == {d.name for d in ROOT.iterdir() if (d / "expected.json").is_file()}


def test_dynamic_cases_have_references():
    dynamic = {cid for cid, c in CASES.items() if c.dynamic}
    assert dynamic == {"idor-two-users", "negative-quantity", "ssrf-webhook-test"}
    for cid in dynamic:
        assert CASES[cid].reference_poc().hypothesis_id
        assert CASES[cid].reference_envspec().port


def test_case_sha_round_trip():
    assert parse_case_sha(case_sha(42)) == (42, False)
    assert parse_case_sha(case_sha(42, base=True)) == (42, True)
    with pytest.raises(ValueError):
        parse_case_sha("c" * 40)


def test_scm_serves_head_and_base(tmp_path):
    scm = CaseSCM(ROOT)
    case = CASES["idor-two-users"]
    pr = scm.get_pr("evals/idor-two-users", 7)
    assert (pr.scm, pr.number, pr.title) == ("evals", 7, case.pr["title"])
    assert pr.head_sha == case_sha(7)
    assert pr.base_sha == case_sha(7, base=True)
    assert scm.get_diff("evals/idor-two-users", 7) == case.diff
    head = scm.fetch_source(pr.repo, pr.head_sha, tmp_path / "head")
    base = scm.fetch_source(pr.repo, pr.base_sha, tmp_path / "base")
    sink = case.expected["expected_findings"][0]["sink_file"]
    assert (head / sink).read_text() == (case.repo / sink).read_text()
    assert (base / sink).read_text() != (head / sink).read_text()
    assert not (base / ".git").exists()
    assert scm.list_open_prs() == []


@pytest.mark.parametrize("repo", ["github/idor-two-users", "evals/../evals/idor-two-users", "evals/IDOR",
                                  "evals/", "evals/no-such-case", "evals/idor-two-users/repo"])
def test_scm_refuses_other_repos(repo):
    scm = CaseSCM(ROOT)
    with pytest.raises(CaseError):
        scm.get_pr(repo, 1)


def test_registered_as_evals_scm(monkeypatch):
    monkeypatch.setattr(scm_pkg, "_instances", {})
    assert isinstance(scm_pkg.get_scm("evals"), CaseSCM)


def test_bad_diff_and_missing_files(tmp_path):
    broken = tmp_path / "broken"
    (broken / "repo").mkdir(parents=True)
    (broken / "repo" / "a.txt").write_text("unrelated\n")
    for name, text in (("pr.json", '{"title": "t"}'), ("expected.json", "{}"),
                       ("diff.patch", "--- a/a.txt\n+++ b/a.txt\n@@ -1 +1 @@\n-old\n+new\n")):
        (broken / name).write_text(text)
    case = load_case(broken)
    with pytest.raises(CaseError, match="does not reverse-apply"):
        base_source(case, tmp_path / "base")
    with pytest.raises(CaseError, match="missing"):
        load_case(tmp_path / "nothing-here")


def _git_base(case, dest):
    """The base as `git apply -R` builds it (the reference for the pure-Python reverse patch)."""
    import shutil
    import subprocess

    shutil.copytree(case.repo, dest)
    subprocess.run(["git", "init", "-q"], cwd=dest, check=True)
    subprocess.run(["git", "apply", "-R", str(case.dir / "diff.patch")], cwd=dest, check=True)
    shutil.rmtree(dest / ".git")
    return dest


def _tree(root):
    return {str(p.relative_to(root)): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


@pytest.mark.skipif(__import__("shutil").which("git") is None, reason="git not installed")
@pytest.mark.parametrize("case_id", sorted(CASES))
def test_base_matches_git_apply_reverse(case_id, tmp_path):
    case = CASES[case_id]
    assert _tree(base_source(case, tmp_path / "ours")) == _tree(_git_base(case, tmp_path / "git"))


def _case_with(tmp_path, files: dict[str, str], diff: str):
    d = tmp_path / "c"
    for rel, text in files.items():
        (d / "repo" / rel).parent.mkdir(parents=True, exist_ok=True)
        (d / "repo" / rel).write_text(text)
    (d / "repo").mkdir(parents=True, exist_ok=True)
    for name, text in (("pr.json", '{"title": "t"}'), ("expected.json", "{}"), ("diff.patch", diff)):
        (d / name).write_text(text)
    return load_case(d)


def test_reverse_patch_added_deleted_and_no_newline(tmp_path):
    diff = (
        "--- /dev/null\n+++ b/new.py\n@@ -0,0 +1,2 @@\n+a\n+b\n"
        "--- a/gone.py\n+++ /dev/null\n@@ -1,2 +0,0 @@\n-x\n-y\n"
        "--- a/app.py\n+++ b/app.py\n@@ -1,2 +1,3 @@\n keep\n-old\n\\ No newline at end of file\n+new\n+more\n"
        "\\ No newline at end of file\n"
    )
    case = _case_with(tmp_path, {"new.py": "a\nb\n", "app.py": "keep\nnew\nmore"}, diff)
    base = base_source(case, tmp_path / "base")
    assert not (base / "new.py").exists()
    assert (base / "gone.py").read_text() == "x\ny\n"
    assert (base / "app.py").read_text() == "keep\nold"


@pytest.mark.parametrize(("files", "diff", "why"), [
    ({"app.py": "other\n"}, "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-old\n+new\n", "does not match"),
    ({"app.py": "new\n"}, "--- a/../escape.py\n+++ b/../escape.py\n@@ -1 +1 @@\n-old\n+new\n", "leaves the case"),
    ({"app.py": "new\n"}, "--- /tmp/escape.py\n+++ /tmp/escape.py\n@@ -1 +1 @@\n-old\n+new\n", "leaves the case"),
    ({"app.py": "new\n"}, "--- a/../gone.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n", "leaves the case"),
    ({"app.py": "new\n"}, "--- a/.\n+++ b/.\n@@ -1 +1 @@\n-old\n+new\n", "leaves the case"),
    ({"b.py": "x\n"}, "--- a/a.py\n+++ b/b.py\n@@ -1 +1 @@\n-x\n+x\n", "renames"),
])
def test_reverse_patch_refuses(tmp_path, files, diff, why):
    case = _case_with(tmp_path, files, diff)
    with pytest.raises(CaseError, match=why):
        base_source(case, tmp_path / "base")

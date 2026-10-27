from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import jsonschema
import pytest
import yaml

from prsec.skills_lint import bug_class_aliases, lint_tree, main, split_frontmatter
from prsec.stages.outputs import HypothesesOutput, StaticVerifyOutput, TriageOutput

SKILLS = Path(__file__).resolve().parents[2] / "prsec-skills"
CASES = SKILLS / "evals" / "cases"
SKILL_NAMES = ["triage", "taint-analysis", "business-logic", "static-validation", "org"]
REQUIRED_REFS = [
    "sqli", "nosqli", "xss", "ssrf", "idor", "bfla", "mass-assignment", "path-traversal", "cmdi",
    "ssti", "deserialization", "open-redirect", "crypto-misuse", "authn-session", "race-condition",
    "workflow-bypass", "value-tampering", "data-exposure",
]
JSON_BLOCK_RE = re.compile(r"```json\n(.*?)\n```", re.S)


def test_whole_skills_repo_lints_clean() -> None:
    issues = lint_tree(SKILLS)
    assert [i.format(SKILLS) for i in issues if i.level == "error"] == []
    assert main([str(SKILLS), "--quiet"]) == 0


@pytest.mark.parametrize("name", SKILL_NAMES)
def test_skill_layout(name: str) -> None:
    text = (SKILLS / name / "SKILL.md").read_text()
    fm_text, body, _ = split_frontmatter(text)  # type: ignore[misc]
    fm = yaml.safe_load(fm_text)
    assert fm["name"] == name
    assert 0 < len(fm["description"]) <= 1024
    assert "prsec-cite check" in body


def test_static_validation_references_cover_required_classes() -> None:
    refs = {p.stem for p in (SKILLS / "static-validation" / "references").glob("*.md")}
    assert set(REQUIRED_REFS) <= refs
    aliases = bug_class_aliases(SKILLS)
    assert aliases["negative-quantity"] == "value-tampering"
    assert all(aliases[r] == r for r in REQUIRED_REFS)


def _json_examples() -> list[tuple[Path, dict]]:
    out = []
    for md in sorted(SKILLS.rglob("*.md")):
        for block in JSON_BLOCK_RE.findall(md.read_text()):
            try:
                out.append((md, json.loads(block)))
            except json.JSONDecodeError:
                continue
    return out


def test_json_examples_match_stage_schemas_and_vocabulary() -> None:
    aliases = bug_class_aliases(SKILLS)
    examples = _json_examples()
    assert examples, "skills should contain worked JSON examples"
    checked = 0
    for md, data in examples:
        if "hypotheses" in data:
            out = HypothesesOutput.model_validate(data)
            for h in out.hypotheses:
                assert aliases.get(h.bug_class) == h.bug_class, f"{md}: non-canonical bug_class {h.bug_class}"
            checked += 1
        elif "verdict" in data and "hypothesis_id" in data:
            StaticVerifyOutput.model_validate(data)
            checked += 1
        elif "decision" in data:
            TriageOutput.model_validate(data)
            checked += 1
    assert checked >= 2


CASE_DIRS = sorted(p for p in CASES.iterdir() if p.is_dir())


def test_seed_cases_present() -> None:
    assert {p.name for p in CASE_DIRS} >= {"sqli-new-endpoint", "sqli-parameterised", "css-only"}


@pytest.mark.parametrize("case", CASE_DIRS, ids=lambda p: p.name)
def test_eval_case_is_well_formed(case: Path) -> None:
    schema = json.loads((SKILLS / "evals" / "expected.schema.json").read_text())
    expected = json.loads((case / "expected.json").read_text())
    jsonschema.validate(expected, schema)
    assert expected["id"] == case.name
    pr = json.loads((case / "pr.json").read_text())
    assert pr["changed_files"]
    aliases = bug_class_aliases(SKILLS)
    for f in expected["expected_findings"] + expected["must_not_find"]:
        assert aliases.get(f["bug_class"]) == f["bug_class"]
        sink = case / "repo" / f["sink_file"]
        assert sink.is_file()
        if "sink_lines" in f:
            start, end = f["sink_lines"]
            assert 1 <= start <= end <= len(sink.read_text().splitlines())


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
@pytest.mark.parametrize("case", CASE_DIRS, ids=lambda p: p.name)
def test_eval_diff_reverse_applies(case: Path, tmp_path: Path) -> None:
    work = tmp_path / "repo"
    shutil.copytree(case / "repo", work)
    subprocess.run(["git", "init", "-q"], cwd=work, check=True)
    proc = subprocess.run(
        ["git", "apply", "-R", "--check", "-v", str(case / "diff.patch")],
        cwd=work,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert "Checking patch" in proc.stderr


def test_seed_case_labels() -> None:
    by_id = {p.name: json.loads((p / "expected.json").read_text()) for p in CASE_DIRS}
    assert by_id["css-only"]["triage"]["acceptable"] == ["skip"]
    assert by_id["sqli-new-endpoint"]["expected_findings"][0]["bug_class"] == "sqli"
    assert by_id["sqli-parameterised"]["known_false_positive"] is True

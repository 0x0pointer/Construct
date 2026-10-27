"""Phase 2 skills (env-building, mocking, poc-authoring, oracles) and the dynamic eval cases."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

from prsec.dynamic.catalog import load_catalog
from prsec.dynamic.envspec import EnvSpec
from prsec.dynamic.poc import PoC
from prsec.skills_lint import split_frontmatter
from prsec.stages.outputs import DynamicOutput, EnvOutput

SKILLS = Path(__file__).resolve().parents[2] / "prsec-skills"
CASES = SKILLS / "evals" / "cases"
DYNAMIC_SKILLS = ["env-building", "mocking", "poc-authoring", "oracles"]
POC_REFS = ["sqli", "idor", "bfla", "ssrf", "path-traversal", "cmdi", "xss", "business-logic"]
DYNAMIC_CASES = ["idor-two-users", "negative-quantity"]
YAML_BLOCK_RE = re.compile(r"```yaml\n(.*?)\n```", re.S)
JSON_BLOCK_RE = re.compile(r"```json\n(.*?)\n```", re.S)


def _dynamic_markdown() -> list[Path]:
    return sorted(p for name in DYNAMIC_SKILLS for p in (SKILLS / name).rglob("*.md"))


def _poc_yaml_examples() -> list[tuple[Path, dict]]:
    out = []
    for md in _dynamic_markdown():
        for block in YAML_BLOCK_RE.findall(md.read_text()):
            data = yaml.safe_load(block)
            if isinstance(data, dict) and "oracles" in data:
                out.append((md, data))
    return out


def _json_examples(key: str) -> list[dict]:
    out = []
    for md in _dynamic_markdown():
        for block in JSON_BLOCK_RE.findall(md.read_text()):
            data = json.loads(block)
            if key in data:
                out.append(data)
    return out


@pytest.mark.parametrize("name", DYNAMIC_SKILLS)
def test_dynamic_skill_frontmatter(name: str) -> None:
    fm_text, body, _ = split_frontmatter((SKILLS / name / "SKILL.md").read_text())  # type: ignore[misc]
    fm = yaml.safe_load(fm_text)
    assert fm["name"] == name
    assert 0 < len(fm["description"]) <= 1024
    assert len(body) > 1000


@pytest.mark.parametrize("name", DYNAMIC_SKILLS)
def test_dynamic_skill_listed_in_readme(name: str) -> None:
    assert f"]({name}/SKILL.md)" in (SKILLS / "README.md").read_text()


def test_env_building_references_present() -> None:
    refs = {p.stem for p in (SKILLS / "env-building" / "references").glob("*.md")}
    assert refs >= {"python", "node"}


def test_poc_authoring_references_cover_classes() -> None:
    refs = {p.stem for p in (SKILLS / "poc-authoring" / "references").glob("*.md")}
    assert refs >= set(POC_REFS)


def test_every_poc_example_validates() -> None:
    examples = _poc_yaml_examples()
    assert len(examples) >= 10
    for md, data in examples:
        poc = PoC.model_validate(data)
        assert poc.hypothesis_id, md


@pytest.mark.parametrize("ref", POC_REFS)
def test_each_poc_reference_has_a_valid_example(ref: str) -> None:
    md = SKILLS / "poc-authoring" / "references" / f"{ref}.md"
    blocks = [yaml.safe_load(b) for b in YAML_BLOCK_RE.findall(md.read_text())]
    pocs = [PoC.model_validate(b) for b in blocks if isinstance(b, dict) and "oracles" in b]
    assert pocs


def _ref_pocs(ref: str) -> list[PoC]:
    md = SKILLS / "poc-authoring" / "references" / f"{ref}.md"
    return [PoC.model_validate(b) for b in map(yaml.safe_load, YAML_BLOCK_RE.findall(md.read_text()))]


def test_cmdi_examples_only_echo_the_canary() -> None:
    dumped = [p.model_dump_json(by_alias=True) for p in _ref_pocs("cmdi")]
    assert all("echo" in d for d in dumped)
    assert all("${CANARY.token}" in d for d in dumped)


def test_ssrf_example_fetches_canary_url() -> None:
    poc = _ref_pocs("ssrf")[0]
    assert "${CANARY.url}" in poc.model_dump_json(by_alias=True)
    assert poc.oracles[0].type == "canary_hit"


def test_path_traversal_example_reads_sentinel() -> None:
    poc = _ref_pocs("path-traversal")[0]
    assert "${CANARY.file}" in poc.steps[0].query["name"]
    assert poc.oracles[0].value == "${CANARY.file_content}"  # type: ignore[union-attr]


def test_business_logic_example_uses_json_compare() -> None:
    types = {o.type for p in _ref_pocs("business-logic") for o in p.oracles}
    assert "json_compare" in types


def test_authz_examples_use_two_users_or_a_control() -> None:
    idor = _ref_pocs("idor")[0]
    assert len(idor.users) >= 2
    assert any(getattr(o, "negate", False) for o in idor.oracles)


def test_env_output_examples_validate() -> None:
    examples = _json_examples("envspec")
    env_outputs = [e for e in examples if "outcome" not in e]
    assert env_outputs
    for data in env_outputs:
        EnvOutput.model_validate(data)


def test_dynamic_output_examples_validate() -> None:
    examples = _json_examples("outcome")
    assert examples
    for data in examples:
        out = DynamicOutput.model_validate(data)
        assert out.outcome != "reproduced" or out.poc is not None


def test_mocking_lists_catalog_exactly() -> None:
    text = (SKILLS / "mocking" / "SKILL.md").read_text()
    for kind, entry in load_catalog().services.items():
        row = f"| `{kind}` | {entry.port} | {'yes' if entry.seed_path else 'no'} | `{entry.connection}` |"
        assert row in text, kind


# ------------------------------------------------------------------ dynamic eval cases


@pytest.mark.parametrize("case", DYNAMIC_CASES)
def test_dynamic_case_reference_envspec(case: str) -> None:
    spec = EnvSpec.model_validate_json((CASES / case / "reference" / "envspec.json").read_text())
    for cmd in spec.build:
        script = cmd.split()[-1]
        assert (CASES / case / "repo" / script).is_file()


@pytest.mark.parametrize("case", DYNAMIC_CASES)
def test_dynamic_case_reference_poc(case: str) -> None:
    poc = PoC.model_validate(yaml.safe_load((CASES / case / "reference" / "poc.yaml").read_text()))
    assert poc.kind == "http"


@pytest.mark.parametrize("case", DYNAMIC_CASES)
def test_dynamic_case_expects_reproduced(case: str) -> None:
    expected = json.loads((CASES / case / "expected.json").read_text())
    assert "dynamic" in expected["tags"]
    assert "reproduced" in expected["expected_findings"][0]["labels"]


def test_dynamic_case_bug_classes() -> None:
    by_id = {c: json.loads((CASES / c / "expected.json").read_text()) for c in DYNAMIC_CASES}
    assert by_id["idor-two-users"]["expected_findings"][0]["bug_class"] == "idor"
    assert by_id["negative-quantity"]["expected_findings"][0]["bug_class"] == "value-tampering"


def test_idor_case_reference_logs_in_two_users() -> None:
    poc = PoC.model_validate(yaml.safe_load((CASES / "idor-two-users" / "reference" / "poc.yaml").read_text()))
    assert set(poc.users) == {"alice", "bob"}
    assert all(u.login for u in poc.users.values())


def test_negative_quantity_reference_uses_json_compare() -> None:
    poc = PoC.model_validate(yaml.safe_load((CASES / "negative-quantity" / "reference" / "poc.yaml").read_text()))
    assert [o.type for o in poc.oracles].count("json_compare") == 1


def test_sqli_new_endpoint_allows_reproduced() -> None:
    expected = json.loads((CASES / "sqli-new-endpoint" / "expected.json").read_text())
    assert expected["expected_findings"][0]["labels"] == ["reproduced", "likely"]

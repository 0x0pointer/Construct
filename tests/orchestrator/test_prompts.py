import re

import pytest

from prsec import prompts

FORBIDDEN = re.compile(
    r"subagent|sub-agent|task tool|todo|slash command|claude|codex|opencode|\bpi\b|anthropic|openai|mcp|agents\.md",
    re.I,
)
STAGES = ["triage", "hypothesise", "static_verify", "skeptic"]


def _ctx(has_tools: bool) -> dict:
    files = ["pr.json", "diff.patch", "changed_files.txt", "triage.json", "hypothesis.json", "output_schema.json"]
    return dict(
        repo="acme/shop", pr_number=7, has_tools=has_tools, context_files=files, skills=["business-logic", "org"],
        skills_dir="/skills", in_dir="/work/in", out_dir="/work/out", workdir="/work/src",
        output_path="/work/out/output.json", max_hypotheses=5, hypothesis_id="H2", bug_class="idor",
        triage_decision="full", focus_files=["app/orders.py"], has_repo_profile=False,
    )


@pytest.mark.parametrize("stage", STAGES)
@pytest.mark.parametrize("has_tools", [True, False])
def test_prompts_are_harness_neutral(stage, has_tools):
    text = prompts.render(stage, **_ctx(has_tools))
    assert not FORBIDDEN.search(text), FORBIDDEN.search(text)
    assert "{{" not in text and "{%" not in text


@pytest.mark.parametrize("stage", STAGES)
def test_has_tools_changes_prompt(stage):
    with_tools = prompts.render(stage, **_ctx(True))
    without = prompts.render(stage, **_ctx(False))
    assert with_tools != without
    assert "/work/out/output.json" in with_tools and "/work/out/output.json" not in without
    assert "/work/in/diff.patch" not in without
    assert "cannot run commands" in without


def test_prompt_content():
    hyp = prompts.render("hypothesise", **_ctx(True))
    assert "at most **5**" in hyp and "invariant" in hyp.lower() and "/work/in/pr.json" in hyp
    assert "`business-logic`" in hyp
    tri = prompts.render("triage", **_ctx(True))
    for term in ("authorisation", "workflow", "money", "tenant", "rate limits", "skip", "light", "full"):
        assert term in tri
    sv = prompts.render("static_verify", **_ctx(True))
    assert "H2" in sv and "false positive" in sv and "database constraints" in sv.lower()
    sk = prompts.render("skeptic", **_ctx(False))
    assert "When unsure, refute" in sk


def test_missing_variable_is_an_error():
    with pytest.raises(Exception):
        prompts.render("triage", repo="x")


def test_prior_findings_instruction_only_when_present():
    ctx = _ctx(True)
    assert "prior_findings.json" not in prompts.render("hypothesise", **ctx)
    ctx["context_files"] = [*ctx["context_files"], "prior_findings.json"]
    text = prompts.render("hypothesise", **ctx)
    assert "/work/in/prior_findings.json" in text and "Re-evaluate every one" in text
    assert not FORBIDDEN.search(text)

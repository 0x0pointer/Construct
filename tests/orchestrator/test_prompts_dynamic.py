import pytest

from prsec import prompts
from prsec.config import load_policy
from prsec.dynamic.catalog import describe
from prsec.models import Stage
from prsec.orchestrator import stages

from .test_prompts import FORBIDDEN, _ctx


def _dyn_ctx(has_tools: bool, **kw) -> dict:
    ctx = _ctx(has_tools)
    ctx.update(catalog=describe(), has_previous_envspec=False, app_dir="/work/app",
               context_files=["pr.json", "diff.patch", "envspec.json", "output_schema.json"])
    ctx.update(kw)
    return ctx


@pytest.mark.parametrize("stage", ["env", "dynamic"])
@pytest.mark.parametrize("has_tools", [True, False])
def test_dynamic_prompts_are_harness_neutral(stage, has_tools):
    text = prompts.render(stage, **_dyn_ctx(has_tools))
    assert not FORBIDDEN.search(text), FORBIDDEN.search(text)
    assert "{{" not in text
    assert "{%" not in text


def test_env_prompt_has_catalog_and_io():
    text = prompts.render("env", **_dyn_ctx(True))
    assert "| `postgres` |" in text
    assert "/work/out/output.json" in text
    assert "/work/in/envspec.json" in text
    assert "previous_envspec.json" not in text


def test_env_prompt_uses_previous_envspec_when_given():
    ctx = _dyn_ctx(True, has_previous_envspec=True)
    ctx["context_files"] = [*ctx["context_files"], "previous_envspec.json"]
    text = prompts.render("env", **ctx)
    assert "Start from `previous_envspec.json`" in text
    assert "/work/in/previous_envspec.json" in text


def test_dynamic_prompt_content():
    text = prompts.render("dynamic", **_dyn_ctx(True))
    for term in ("prsec-env up", "prsec-http", "prsec-canary", "prsec-poc validate", "prsec-poc run",
                 "fail on fixed code", "benign", "H2", "/work/app"):
        assert term in text, term


def test_dynamic_prompt_without_tools_says_blocked():
    text = prompts.render("dynamic", **_dyn_ctx(False))
    assert "`blocked`" in text
    assert "prsec-env" not in text


@pytest.mark.parametrize("stage,hyp", [(Stage.env, None), (Stage.dynamic, "H1")])
def test_build_task_renders_phase2_stages(stage, hyp):
    task, _ = stages.build_task(
        load_policy().model_copy(update={"experiments": []}), stage, 5, "acme/shop",
        context_files=["pr.json", "envspec.json"], hyp_id=hyp,
        prompt_ctx={"catalog": describe(), "has_previous_envspec": False, "app_dir": "/work/app", "bug_class": "sqli"},
    )
    assert task.task_id == stages.task_id(5, stage, hyp)
    assert task.prompt_md


def test_dynamic_prompt_lets_the_tools_install_and_run_the_app():
    text = prompts.render("dynamic", **_dyn_ctx(True))
    assert "writable copy under `/work/app`" in text
    assert "do not install anything" not in text


def test_env_prompt_stays_read_only():
    text = prompts.render("env", **_dyn_ctx(True, app_dir=""))
    assert "do not install anything" in text

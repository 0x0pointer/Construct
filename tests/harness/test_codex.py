from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from prsec.adapters.harness import claude_code, codex
from prsec.adapters.harness.base import GatewayConfig, HarnessAdapter, get_adapter
from prsec.adapters.harness.codex import CodexAdapter
from prsec.models import EventKind, Stage, StageTask, Usage

FIX = Path(__file__).parent / "fixtures" / "codex"
GW = GatewayConfig(base_url="http://llm-gateway:4000", api_key="sk-scan-7", model="agent-large")


def lines(name: str) -> list[str]:
    return (FIX / name).read_text().splitlines()


@pytest.fixture
def task(tmp_path: Path) -> StageTask:
    skills = tmp_path / "skills"
    (skills / "taint-analysis").mkdir(parents=True)
    (skills / "taint-analysis" / "SKILL.md").write_text("---\nname: taint-analysis\ndescription: d\n---\n")
    return StageTask(
        scan_id=7,
        stage=Stage.static_verify,
        task_id="7-static_verify-H1",
        harness="codex",
        prompt_md="x",
        skills=["taint-analysis", "absent"],
        output_schema={"type": "object"},
        workdir="/work/src",
        out_dir=str(tmp_path / "out"),
        skills_dir=str(skills),
    )


@pytest.fixture(autouse=True)
def fixed_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(codex, "resolve_cli", lambda cli: f"/opt/harness/bin/{cli}")
    monkeypatch.setattr(claude_code, "resolve_cli", lambda cli: f"/opt/harness/bin/{cli}")


def test_registered_and_protocol() -> None:
    a = get_adapter("codex")
    assert isinstance(a, CodexAdapter) and isinstance(a, HarnessAdapter)
    assert a.caps.native_skills and a.caps.resume and a.caps.json_events and not a.caps.max_turns


BASE_CFG = [
    "-c", "approval_policy=\"never\"",
    "-c", "check_for_update_on_startup=false",
    "-c", "analytics.enabled=false",
    "-c", "feedback.enabled=false",
    "-c", "project_doc_max_bytes=0",
]
GW_CFG = BASE_CFG + [
    "-c", "model=\"agent-large\"",
    "-c", "model_provider=\"prsec\"",
    "-c", "model_providers.prsec.name=\"PRSec LLM gateway\"",
    "-c", "model_providers.prsec.base_url=\"http://llm-gateway:4000/v1\"",
    "-c", "model_providers.prsec.env_key=\"PRSEC_CODEX_API_KEY\"",
    "-c", "model_providers.prsec.wire_api=\"responses\"",
]


def exec_opts(out: str, sandbox: str) -> list[str]:
    return [
        "--json", "--color", "never", "--skip-git-repo-check",
        "--sandbox", sandbox, "-C", out,
        "--output-last-message", f"{out}/.codex-last-message.txt",
    ]


def test_build_gateway(task: StageTask) -> None:
    prompt = "P" * 400_000
    inv = CodexAdapter().build(task, GW, prompt)
    out = task.out_dir
    assert inv.argv == ["/opt/harness/bin/codex", *GW_CFG, "exec", *exec_opts(out, "danger-full-access"), "--model", "agent-large", "-"]
    assert inv.stdin == prompt
    assert inv.cwd == out  # never the PR checkout: no repo AGENTS.md / .codex / .agents skills
    assert inv.env == {"HOME": f"{out}/.home", "CODEX_HOME": f"{out}/.home/.codex", "PRSEC_CODEX_API_KEY": "sk-scan-7"}
    assert Path(out, ".home", ".codex").is_dir()


def test_build_dev_mode_isolates_codex_home_but_keeps_login(task: StageTask, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    user = tmp_path / "user-codex"
    user.mkdir()
    (user / "auth.json").write_text("{}")
    (user / "config.toml").write_text("[mcp_servers.x]\n")
    monkeypatch.setenv("CODEX_HOME", str(user))
    inv = CodexAdapter().build(task, None, "hi")
    out = task.out_dir
    # workspace-write rooted at the out dir: the repository is readable but not writable
    assert inv.argv == ["/opt/harness/bin/codex", *BASE_CFG, "exec", *exec_opts(out, "workspace-write"), "-"]
    assert "/work/src" not in inv.argv
    isolated = Path(out, ".home", ".codex")
    assert inv.env == {"HOME": f"{out}/.home", "CODEX_HOME": str(isolated)}
    assert (isolated / "auth.json").resolve() == (user / "auth.json").resolve()
    assert not (isolated / "config.toml").exists()
    CodexAdapter().build_resume(task, None, "s", "again")  # idempotent


def test_build_resume(task: StageTask) -> None:
    a = CodexAdapter()
    inv = a.build_resume(task, GW, "0199a213-81c0", "repair it")
    assert inv is not None
    fresh = a.build(task, GW, "x").argv
    assert inv.argv == fresh[:-1] + ["resume", "0199a213-81c0", "-"]
    assert inv.argv.index("-c") < inv.argv.index("exec") < inv.argv.index("--json") < inv.argv.index("resume")
    assert inv.stdin == "repair it"
    assert inv.env["PRSEC_CODEX_API_KEY"] == "sk-scan-7"


def test_install_skills_native_locations(task: StageTask) -> None:
    CodexAdapter().install_skills(task)
    home = Path(task.out_dir) / ".home"
    for root in (home / ".agents" / "skills", home / ".codex" / "skills"):
        assert [p.name for p in root.iterdir()] == ["taint-analysis"]
        assert (root / "taint-analysis" / "SKILL.md").is_file()


def test_parse_success() -> None:
    a = CodexAdapter()
    ev = list(a.parse_events(lines("exec_success.jsonl")))
    assert a.session_id(ev) == "0199a213-81c0-7800-8aa1-bbab2a035a53"
    calls = [e for e in ev if e.kind == EventKind.tool_call]
    assert [c.tool for c in calls] == ["shell", "shell", "apply_patch", "mcp:docs/search"]
    assert calls[0].data == {"id": "item_1", "input": {"command": "bash -lc 'cat /work/in/diff.patch'"}}
    results = [e for e in ev if e.kind == EventKind.tool_result]
    assert results[0].text.startswith("diff --git") and results[0].data["exit_code"] == 0
    assert results[0].data["is_error"] is False
    assert results[1].data["is_error"] is True and results[1].data["status"] == "failed"
    assert results[2].text == "add /work/out/output.json"
    assert "none" in results[3].text
    assert [e.text for e in ev if e.kind == EventKind.message] == ["Wrote /work/out/output.json."]
    assert not any("Inspecting" in (e.text or "") for e in ev)  # reasoning dropped
    todos = [e for e in ev if e.data.get("subtype") == "todo_list"]
    assert len(todos) == 1  # item.started/updated for todo lists are skipped
    assert not [e for e in ev if e.kind == EventKind.error]


def test_usage() -> None:
    a = CodexAdapter()
    u = a.usage(list(a.parse_events(lines("exec_success.jsonl"))))
    assert u == Usage(tokens_in=24763 - 24448, tokens_out=122, tokens_cache_read=24448, usd=0.0, turns=1)
    both = a.usage(list(a.parse_events(lines("exec_success.jsonl") + lines("resume.jsonl"))))
    assert both.turns == 2 and both.tokens_cache_read == 24448 + 25000 and both.tokens_in == 315 + 5000


def test_parse_failed() -> None:
    a = CodexAdapter()
    ev = list(a.parse_events(lines("exec_failed.jsonl")))
    errs = [e.text for e in ev if e.kind == EventKind.error]
    assert len(errs) == 3
    assert errs[0].startswith("Reconnecting") and "not allowed" in errs[1] and "401" in errs[2]
    assert a.usage(ev) == Usage()
    assert a.session_id(ev) == "0199a214-0000-7000-8000-000000000001"


def test_parse_garbage_never_raises() -> None:
    a = CodexAdapter()
    ev = list(a.parse_events(lines("garbage.txt")))
    assert {e.text for e in ev if e.data.get("unparsed")} >= {"Reading prompt from stdin...", "not json {", "[1, 2, 3]"}
    assert a.session_id(ev) is None
    assert a.usage(ev).turns == 1  # bogus usage payload still counts the completed turn, with zero tokens
    assert a.usage(ev).tokens_in == 0


def test_version(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        subprocess, "run", lambda argv, **kw: subprocess.CompletedProcess(argv, 0, "codex-cli 0.98.0\n", "")
    )
    assert CodexAdapter().version() == "0.98.0"
    monkeypatch.setattr(subprocess, "run", lambda argv, **kw: subprocess.CompletedProcess(argv, 127, "", "nope"))
    assert CodexAdapter().version() is None

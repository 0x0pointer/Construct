from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from prsec.adapters.harness import base, claude_code
from prsec.adapters.harness.base import GatewayConfig, HarnessAdapter, get_adapter
from prsec.adapters.harness.claude_code import ClaudeCodeAdapter
from prsec.models import EventKind, Limits, Stage, StageTask

FIX = Path(__file__).parent / "fixtures" / "claude_code"
GW = GatewayConfig(base_url="http://llm-gateway:4000/", api_key="sk-scan-42", model="agent-large")


def lines(name: str) -> list[str]:
    return (FIX / name).read_text().splitlines()


@pytest.fixture
def task(tmp_path: Path) -> StageTask:
    skills = tmp_path / "skills"
    for name in ("taint-analysis", "business-logic"):
        (skills / name / "scripts").mkdir(parents=True)
        (skills / name / "SKILL.md").write_text(f"---\nname: {name}\ndescription: {name} method\n---\n# {name}\n")
        (skills / name / "scripts" / "helper.sh").write_text("echo hi\n")
    (skills / "no-skill-md").mkdir()
    return StageTask(
        scan_id=42,
        stage=Stage.hypothesise,
        task_id="42-hypothesise",
        harness="claude-code",
        prompt_md="x",
        skills=["taint-analysis", "business-logic", "no-skill-md", "missing"],
        output_schema={"type": "object"},
        output_path=str(tmp_path / "out" / "hypothesise.json"),
        workdir="/work/src",
        in_dir="/work/in",
        out_dir=str(tmp_path / "out"),
        skills_dir=str(skills),
        limits=Limits(max_turns=30, usd_budget=2.5),
    )


@pytest.fixture(autouse=True)
def fixed_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(claude_code, "resolve_cli", lambda cli: f"/opt/harness/bin/{cli}")
    monkeypatch.setattr(base, "resolve_cli", lambda cli: f"/opt/harness/bin/{cli}")


def test_registered_and_protocol() -> None:
    a = get_adapter("claude-code")
    assert isinstance(a, ClaudeCodeAdapter)
    assert isinstance(a, HarnessAdapter)
    assert a.caps.native_skills and a.caps.resume and a.caps.json_events and a.caps.max_turns


COMMON = [
    "/opt/harness/bin/claude", "-p", "--output-format", "stream-json", "--verbose",
    "--permission-mode", "dontAsk",
    "--tools", "Bash,Read,Write,Edit,Glob,Grep,Skill",
    "--allowedTools", "Bash,Read,Write,Edit,Glob,Grep,Skill",
    "--strict-mcp-config",
    "--setting-sources", "",
]


def isolation(out: str) -> list[str]:
    return ["--plugin-dir", f"{out}/.home/prsec"]


def test_build_gateway(task: StageTask) -> None:
    inv = ClaudeCodeAdapter().build(task, GW, "PROMPT " * 50_000)
    out = task.out_dir
    assert inv.argv == COMMON + isolation(out) + [
        "--add-dir", "/work/in", out,
        "--model", "agent-large",
        "--max-turns", "30",
        "--max-budget-usd", "2.5",
    ]
    assert inv.cwd == "/work/src"
    assert inv.stdin == "PROMPT " * 50_000  # long prompts go via stdin, never argv
    assert inv.env == {
        "DISABLE_TELEMETRY": "1",
        "DISABLE_ERROR_REPORTING": "1",
        "DISABLE_AUTOUPDATER": "1",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "CLAUDE_CODE_DISABLE_CLAUDE_MDS": "1",
        "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1",
        "HOME": f"{out}/.home",
        "CLAUDE_CONFIG_DIR": f"{out}/.home/.claude",
        "ANTHROPIC_BASE_URL": "http://llm-gateway:4000",
        "ANTHROPIC_AUTH_TOKEN": "sk-scan-42",
        "ANTHROPIC_API_KEY": "",
        "ANTHROPIC_MODEL": "agent-large",
        "ANTHROPIC_SMALL_FAST_MODEL": "agent-large",
        "ANTHROPIC_DEFAULT_HAIKU_MODEL": "agent-large",
        "ANTHROPIC_DEFAULT_SONNET_MODEL": "agent-large",
        "ANTHROPIC_DEFAULT_OPUS_MODEL": "agent-large",
        "CLAUDE_CODE_SUBAGENT_MODEL": "agent-large",
    }


def test_build_dev_mode_keeps_login(task: StageTask) -> None:
    task.limits = Limits()  # no max_turns
    inv = ClaudeCodeAdapter().build(task, None, "hello")
    out = task.out_dir
    # login only: no user/project settings, CLAUDE.md, hooks, plugins or personal skills
    assert inv.argv == COMMON + isolation(out) + ["--add-dir", "/work/in", out, "--max-budget-usd", "3"]
    assert "HOME" not in inv.env and "CLAUDE_CONFIG_DIR" not in inv.env
    assert inv.env["CLAUDE_CODE_DISABLE_CLAUDE_MDS"] == "1"
    assert not any(k.startswith("ANTHROPIC_") for k in inv.env)
    assert "--model" not in inv.argv


def test_build_resume(task: StageTask) -> None:
    a = ClaudeCodeAdapter()
    inv = a.build_resume(task, GW, "sess-1", "fix the schema errors")
    assert inv is not None
    assert inv.argv == a.build(task, GW, "p").argv + ["--resume", "sess-1"]
    assert inv.stdin == "fix the schema errors"
    assert inv.env == a.build(task, GW, "p").env
    dev = a.build_resume(task, None, "sess-1", "again")
    assert dev is not None and dev.argv[-2:] == ["--resume", "sess-1"] and "HOME" not in dev.env


def test_install_skills_into_writable_home(task: StageTask) -> None:
    ClaudeCodeAdapter().install_skills(task)
    plugin = Path(task.out_dir) / ".home" / "prsec"
    assert json.loads((plugin / ".claude-plugin" / "plugin.json").read_text())["name"] == "prsec"
    root = plugin / "skills"
    assert sorted(p.name for p in root.iterdir()) == ["business-logic", "taint-analysis"]
    assert (root / "taint-analysis" / "SKILL.md").read_text().startswith("---\nname: taint-analysis")
    assert (root / "taint-analysis" / "scripts" / "helper.sh").is_file()
    ClaudeCodeAdapter().install_skills(task)  # idempotent
    assert (root / "business-logic" / "SKILL.md").is_file()


def test_parse_real_tool_use_transcript() -> None:
    a = ClaudeCodeAdapter()
    ev = list(a.parse_events(lines("tool_use.jsonl")))
    kinds = [e.kind for e in ev]
    assert kinds[0] == EventKind.system and ev[0].data["subtype"] == "init"
    assert ev[0].data["skills"] == ["prsec-fixture"]
    calls = [e for e in ev if e.kind == EventKind.tool_call]
    assert [c.tool for c in calls] == ["Bash", "Write"]
    assert calls[0].data["input"]["command"] == "ls"
    assert calls[1].data["input"]["file_path"] == "/work/out/output.json"
    results = [e for e in ev if e.kind == EventKind.tool_result]
    assert results[0].text == "app.py" and results[0].data["tool_use_id"] == calls[0].data["id"]
    assert results[0].data["is_error"] is False
    assert [e.text for e in ev if e.kind == EventKind.message] == ["DONE"]
    assert ev[1].ts is not None
    assert a.session_id(ev) == "fc01e8fd-5d44-4cbf-9f24-a7ff0504a6d1"
    assert not [e for e in ev if e.kind == EventKind.error]


def test_usage_from_result_event() -> None:
    a = ClaudeCodeAdapter()
    u = a.usage(list(a.parse_events(lines("tool_use.jsonl"))))
    assert (u.tokens_in, u.tokens_out, u.tokens_cache_read) == (4 + 15130, 225, 26272)
    assert u.usd == pytest.approx(0.00340162)
    assert u.turns == 3
    hi = a.usage(list(a.parse_events(lines("say_hi.jsonl"))))
    assert (hi.tokens_in, hi.tokens_out, hi.turns) == (2 + 17177, 14, 1)
    assert hi.usd == pytest.approx(0.1400744)


def test_usage_aggregates_across_runs_and_falls_back_without_result() -> None:
    a = ClaudeCodeAdapter()
    both = list(a.parse_events(lines("tool_use.jsonl") + lines("resume.jsonl")))
    one = a.usage(list(a.parse_events(lines("tool_use.jsonl"))))
    two = a.usage(list(a.parse_events(lines("resume.jsonl"))))
    assert a.usage(both) == one + two
    # killed before the result line: per-message usage, de-duplicated by message id
    truncated = [l for l in lines("tool_use.jsonl") if '"type":"result"' not in l]
    u = a.usage(list(a.parse_events(truncated)))
    assert u.turns == 2 and u.tokens_out > 0 and u.usd == 0


def test_parse_gateway_error_transcript() -> None:
    a = ClaudeCodeAdapter()
    ev = list(a.parse_events(lines("gateway_unreachable.jsonl")))
    assert ev[0].data["model"] == "agent-large"
    retries = [e for e in ev if e.data.get("subtype") == "api_retry"]
    assert len(retries) == 10 and retries[0].data["attempt"] == 1
    errors = [e for e in ev if e.kind == EventKind.error]
    # synthetic assistant message flagged error=server_error, then result is_error=true
    assert [e.text for e in errors][0] == "server_error"
    assert "ECONNREFUSED" in (errors[-1].text or "") and errors[-1].data["terminal_reason"] == "api_error"
    assert a.usage(ev).tokens_in == 0


def test_parse_garbage_never_raises() -> None:
    a = ClaudeCodeAdapter()
    ev = list(a.parse_events(lines("garbage.txt") + ["", "   "]))
    unparsed = [e for e in ev if e.data.get("unparsed")]
    assert {e.text for e in unparsed} >= {"Reading prompt from stdin...", "not json {", "[1, 2, 3]", '"just a string"'}
    assert a.session_id(ev) is None
    u = a.usage(ev)
    assert u.tokens_in == 0 and u.usd == 0


def test_resume_fixture_keeps_session() -> None:
    a = ClaudeCodeAdapter()
    ev = list(a.parse_events(lines("resume.jsonl")))
    assert a.session_id(ev) == "fc01e8fd-5d44-4cbf-9f24-a7ff0504a6d1"


def test_version(monkeypatch: pytest.MonkeyPatch) -> None:
    def ok(argv, **kw):
        assert argv == ["/opt/harness/bin/claude", "--version"] and kw["timeout"] == 10
        return subprocess.CompletedProcess(argv, 0, "2.1.311 (Claude Code)\n", "")

    monkeypatch.setattr(subprocess, "run", ok)
    assert ClaudeCodeAdapter().version() == "2.1.311"

    def missing(argv, **kw):
        raise FileNotFoundError(argv[0])

    monkeypatch.setattr(subprocess, "run", missing)
    assert ClaudeCodeAdapter().version() is None

    def hang(argv, **kw):
        raise subprocess.TimeoutExpired(argv, 10)

    monkeypatch.setattr(subprocess, "run", hang)
    assert ClaudeCodeAdapter().version() is None


def test_resolve_cli_prefers_harness_volume(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.undo()  # restore the real resolve_cli
    from prsec.adapters.harness.claude_code import resolve_cli

    bindir = tmp_path / "bin"
    bindir.mkdir()
    exe = bindir / "claude"
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    monkeypatch.setenv("PRSEC_HARNESS_HOME", str(tmp_path))
    assert resolve_cli("claude") == str(exe)
    monkeypatch.setenv("PRSEC_HARNESS_HOME", str(tmp_path / "nope"))
    monkeypatch.setenv("PATH", str(bindir))
    assert resolve_cli("claude") == str(exe)
    monkeypatch.setenv("PATH", "")
    assert resolve_cli("claude") == "claude"

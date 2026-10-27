"""Deterministic stand-in for a harness CLI (claude, codex, opencode, pi).

Installed as `$PRSEC_HARNESS_HOME/bin/<cli>` by the conformance suite. It behaves like the real
CLI only as far as the adapter contract goes:

- reads the prompt from stdin (the adapters' delivery channel) and finds the output path in it;
- discovers skills the way the real CLI does (per-CLI rules below) and reads the fixture skill;
- reports which project files (CLAUDE.md, AGENTS.md, settings) the real CLI would load from its cwd;
- replays a captured native event stream on stdout (resume fixture when resumed);
- writes the output file according to `SCENARIO=<name>` in the prompt.

Every call is appended to $PRSEC_STUB_LOG as one JSON line for the test to assert on.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path

# cli -> (fixture dir, first-run stream, resume stream, session id in both)
STREAMS = {
    "claude": ("claude_code", "tool_use.jsonl", "resume.jsonl", "fc01e8fd-5d44-4cbf-9f24-a7ff0504a6d1"),
    "codex": ("codex", "exec_success.jsonl", "resume.jsonl", "0199a213-81c0-7800-8aa1-bbab2a035a53"),
    "opencode": ("opencode", "run_tool_write.jsonl", "resume.jsonl", "ses_e8286f379ffeuPWV1FaMXOg3MR"),
    "pi": ("pi", "run_tool_write.jsonl", "resume.jsonl", "01a17d7f-4f6a-7083-8e88-d48f55ccd91f"),
}
SKILL = "conformance-fixture"
TOKEN_RE = re.compile(r"CONFORMANCE_TOKEN=([\w-]+)")
PARENT_SESSION_VARS = ("CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CLAUDE_CODE_SESSION_ID")


def _flag_values(argv: list[str], flag: str) -> list[str]:
    """Values of a repeatable flag; `--add-dir a b --x` yields [a, b]."""
    out: list[str] = []
    i = 0
    while i < len(argv):
        if argv[i] == flag:
            i += 1
            while i < len(argv) and not argv[i].startswith("-"):
                out.append(argv[i])
                i += 1
                if flag != "--add-dir":
                    break
            continue
        i += 1
    return out


def _claude_sources(argv: list[str]) -> set[str]:
    if "--setting-sources" not in argv:
        return {"user", "project", "local"}
    value = argv[argv.index("--setting-sources") + 1]
    return {v.strip() for v in value.split(",") if v.strip()}


def _codex_root(argv: list[str]) -> Path:
    return Path(argv[argv.index("-C") + 1]) if "-C" in argv else Path.cwd()


def skill_dirs(cli: str, argv: list[str], env: dict[str, str]) -> list[Path]:
    """Where the real CLI looks for `<name>/SKILL.md`; project (PR checkout) locations first."""
    home = Path(env.get("HOME", "/nonexistent"))
    cwd = Path.cwd()
    if cli == "claude":
        sources = _claude_sources(argv)
        dirs = []
        if "project" in sources:
            dirs += [cwd / ".claude" / "skills"] + [Path(d) / ".claude" / "skills" for d in _flag_values(argv, "--add-dir")]
        dirs += [Path(d) / "skills" for d in _flag_values(argv, "--plugin-dir")]
        if "user" in sources:
            if env.get("CLAUDE_CONFIG_DIR"):
                dirs.append(Path(env["CLAUDE_CONFIG_DIR"]) / "skills")
            dirs.append(home / ".claude" / "skills")
        return dirs
    if cli == "codex":
        dirs = [_codex_root(argv) / ".agents" / "skills", home / ".agents" / "skills"]  # repo scope, user scope
        if env.get("CODEX_HOME"):
            dirs.append(Path(env["CODEX_HOME"]) / "skills")
        return dirs
    if cli == "opencode":
        dirs = []
        if not env.get("OPENCODE_DISABLE_PROJECT_CONFIG"):
            dirs.append(cwd / ".opencode" / "skills")
        if not env.get("OPENCODE_DISABLE_CLAUDE_CODE"):
            dirs.append(cwd / ".claude" / "skills")
        if env.get("OPENCODE_CONFIG_DIR"):
            dirs.append(Path(env["OPENCODE_CONFIG_DIR"]) / "skills")
        return dirs
    if cli == "pi":
        if "--no-skills" not in argv:
            return [cwd / ".pi" / "skills", home / ".pi" / "agent" / "skills"]
        return [Path(d).parent for d in _flag_values(argv, "--skill")]
    return []


def project_files(cli: str, argv: list[str], env: dict[str, str]) -> list[str]:
    """Instruction/config files from the working tree the real CLI would load (should be none)."""
    cwd = Path.cwd()
    cands: list[Path] = []
    if cli == "claude":
        if not env.get("CLAUDE_CODE_DISABLE_CLAUDE_MDS"):
            cands.append(cwd / "CLAUDE.md")
        if "project" in _claude_sources(argv):
            cands.append(cwd / ".claude" / "settings.json")
    elif cli == "codex":
        if "project_doc_max_bytes=0" not in argv:
            cands.append(_codex_root(argv) / "AGENTS.md")
    elif cli == "opencode":
        if not env.get("OPENCODE_DISABLE_PROJECT_CONFIG"):
            cands += [cwd / "AGENTS.md", cwd / "opencode.json"]
            if not env.get("OPENCODE_DISABLE_CLAUDE_CODE"):
                cands.append(cwd / "CLAUDE.md")
    elif cli == "pi":
        for d in [cwd, *cwd.parents]:
            cands += [d / "AGENTS.md", d / "CLAUDE.md"]
    return [str(c) for c in cands if c.is_file()]


def find_skill(cli: str, argv: list[str], env: dict[str, str]) -> Path | None:
    for d in skill_dirs(cli, argv, env):
        if (d / SKILL / "SKILL.md").is_file():
            return d / SKILL / "SKILL.md"
    return None


def _visible_to_cli(stub_var: str, argv: list[str], env: dict[str, str]) -> bool:
    """Whether the value the test planted in `stub_var` reaches the harness (argv, env, pi's models.json).

    Only this boolean is logged; the value itself never goes into the call log.
    """
    needle = env.get(stub_var, "")
    if not needle:
        return False
    hay = [v for k, v in env.items() if not k.startswith("PRSEC_STUB_")] + argv
    if any(needle in h for h in hay):
        return True
    agent_dir = env.get("PI_CODING_AGENT_DIR")  # pi reads provider config from a file
    models = Path(agent_dir) / "models.json" if agent_dir else None
    return bool(models and models.is_file() and needle in models.read_text())


def main() -> int:
    cli = sys.argv[1]
    argv = sys.argv[2:]
    if argv == ["--version"]:
        print(f"9.9.9 ({cli} conformance stub)")
        return 0
    env = dict(os.environ)
    prompt = sys.stdin.read() if not sys.stdin.isatty() else ""
    log_path = Path(env["PRSEC_STUB_LOG"])
    calls = log_path.read_text().splitlines() if log_path.exists() else []
    call_no = len(calls) + 1

    fixture_dir, first, resumed_stream, session = STREAMS[cli]
    resumed = session in argv
    m = re.search(r"JSON document to `([^`]+)`", prompt)
    output_path = m.group(1) if m else None
    sm = re.search(r"SCENARIO=(\w+)", prompt)
    scenario = sm.group(1) if sm else "ok"
    skill = find_skill(cli, argv, env)
    token = None
    if skill:
        tm = TOKEN_RE.search(skill.read_text())
        token = tm.group(1) if tm else None

    record = {
        "cli": cli, "call": call_no, "argv": argv, "cwd": os.getcwd(), "pid": os.getpid(), "prompt": prompt,
        "output_path": output_path, "scenario": scenario, "resumed": resumed,
        "skill_path": str(skill) if skill else None, "skill_token": token,
        "gateway_key_visible": _visible_to_cli("PRSEC_STUB_GATEWAY_KEY", argv, env),
        "gateway_url_visible": _visible_to_cli("PRSEC_STUB_GATEWAY_URL", argv, env),
        "parent_session_vars": [v for v in PARENT_SESSION_VARS if v in env],
        "home": env.get("HOME"),
        "project_files": project_files(cli, argv, env),
    }
    with log_path.open("a") as f:
        f.write(json.dumps(record) + "\n")

    stream = Path(env["PRSEC_STUB_FIXTURES"]) / fixture_dir / (resumed_stream if resumed else first)
    for line in stream.read_text().splitlines():
        print(line, flush=True)

    if scenario == "hang":
        time.sleep(600)
        return 0
    if scenario == "crash":
        print("stub: simulated crash", file=sys.stderr)
        return 3
    if output_path is None:
        print("stub: no output path in prompt", file=sys.stderr)
        return 4

    fixture_line = ""
    rm = re.search(r"\*\*Repository\*\* \(read-only\): `([^`]+)`", prompt)
    app = Path(rm.group(1) if rm else os.getcwd()) / "app.py"
    if app.is_file():
        fixture_line = app.read_text().splitlines()[0]
    good = {"skill_token": token or "", "answer": "DONE", "fixture_line": fixture_line}
    bad = {"skill_token": 42}
    doc = bad if scenario == "repair" and call_no == 1 else good
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(json.dumps(doc))
    return 0


if __name__ == "__main__":
    sys.exit(main())

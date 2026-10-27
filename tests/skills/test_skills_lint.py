from __future__ import annotations

from pathlib import Path

import pytest

from prsec import skills_lint
from prsec.skills_lint import lint_tree, main

GOOD_BODY = (
    "# Good skill\n\n"
    "Read the diff and write the stage JSON with verbatim citations. "
    "See [the reference](references/notes.md) and `references/notes.md`.\n"
    "Run `prsec-cite check out.json` when a shell is available.\n"
)


def write_skill(root: Path, name: str, *, frontmatter: str | None = None, body: str = GOOD_BODY) -> Path:
    d = root / name
    (d / "references").mkdir(parents=True, exist_ok=True)
    (d / "references" / "notes.md").write_text("# Notes\n\nPlain methodology.\n")
    fm = frontmatter if frontmatter is not None else f"---\nname: {name}\ndescription: Does one thing well.\n---\n"
    (d / "SKILL.md").write_text(fm + body)
    return d


def codes(issues) -> list[str]:
    return [i.code for i in issues if i.level == "error"]


def test_good_skill_passes(tmp_path: Path) -> None:
    write_skill(tmp_path, "good")
    assert codes(lint_tree(tmp_path)) == []
    assert main([str(tmp_path)]) == 0


def test_single_skill_dir_is_accepted(tmp_path: Path) -> None:
    d = write_skill(tmp_path, "solo")
    assert main([str(d)]) == 0


def test_missing_frontmatter(tmp_path: Path) -> None:
    write_skill(tmp_path, "nofm", frontmatter="")
    assert codes(lint_tree(tmp_path)) == ["frontmatter"]


def test_name_must_match_dir(tmp_path: Path) -> None:
    write_skill(tmp_path, "alpha", frontmatter="---\nname: beta\ndescription: x\n---\n")
    issues = lint_tree(tmp_path)
    assert codes(issues) == ["name"]
    assert issues[0].line == 2


def test_name_must_be_kebab(tmp_path: Path) -> None:
    write_skill(tmp_path, "Bad_Name", frontmatter="---\nname: Bad_Name\ndescription: x\n---\n")
    assert "name" in codes(lint_tree(tmp_path))


def test_description_required_and_bounded(tmp_path: Path) -> None:
    write_skill(tmp_path, "nodesc", frontmatter="---\nname: nodesc\n---\n")
    write_skill(tmp_path, "longdesc", frontmatter=f"---\nname: longdesc\ndescription: {'a' * 1025}\n---\n")
    write_skill(tmp_path, "okdesc", frontmatter=f"---\nname: okdesc\ndescription: {'a' * 1024}\n---\n")
    issues = [i for i in lint_tree(tmp_path) if i.level == "error"]
    by_skill = {i.path.parent.name for i in issues}
    assert by_skill == {"nodesc", "longdesc"}
    assert all(i.code == "description" for i in issues)


def test_multiline_description_rejected(tmp_path: Path) -> None:
    write_skill(tmp_path, "block", frontmatter="---\nname: block\ndescription: >\n  folded\n---\n")
    assert codes(lint_tree(tmp_path)) == ["description"]


def test_invalid_yaml(tmp_path: Path) -> None:
    write_skill(tmp_path, "badyaml", frontmatter="---\nname: [unclosed\n---\n")
    assert codes(lint_tree(tmp_path)) == ["frontmatter"]


def test_empty_body_and_oversize(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write_skill(tmp_path, "empty", body="tiny\n")
    assert codes(lint_tree(tmp_path)) == ["size"]
    monkeypatch.setattr(skills_lint, "SKILL_MD_MAX_BYTES", 50)
    write_skill(tmp_path, "empty", body=GOOD_BODY)
    assert codes(lint_tree(tmp_path)) == ["size"]


def test_broken_links(tmp_path: Path) -> None:
    body = GOOD_BODY + "\nBroken [x](references/missing.md), `references/gone.md`, [abs](/etc/hosts), [up](../../outside.md).\n"
    body += "Fine: [web](https://example.com), [anchor](#top).\n"
    write_skill(tmp_path, "links", body=body)
    issues = [i for i in lint_tree(tmp_path) if i.level == "error"]
    assert [i.code for i in issues] == ["link"] * 4
    assert {i.line for i in issues} == {10}


def test_links_inside_code_fences_ignored(tmp_path: Path) -> None:
    write_skill(tmp_path, "fenced", body=GOOD_BODY + "\n```\n[x](nope.md)\n```\n")
    assert codes(lint_tree(tmp_path)) == []


BAD_LINES = [
    ("Spawn a helper with the Task tool.", "harness:task-tool"),
    ("Delegate to a subagent.", "harness:subagent"),
    ("Hand off to a sub-agent.", "harness:subagent"),
    ("/web-exploit next", "harness:slash-command"),
    ("- /business-logic", "harness:slash-command"),
    ("Track work with TodoWrite.", "harness:todo-tool"),
    ("Works best in Claude Code.", "harness:claude-code"),
    ("Run it with Codex.", "harness:codex"),
    ("OpenCode supports this.", "harness:opencode"),
    ("Use the pi agent for that.", "harness:pi-agent"),
    ("Call mcp__scanner__run first.", "harness:mcp-tool"),
    ("Ask with AskUserQuestion.", "harness:ask-user"),
    ("Fetch docs with WebFetch.", "harness:web-tool"),
    ("Replay it in Burp.", "harness:burp"),
    ("Run tools from Kali.", "harness:kali"),
]


@pytest.mark.parametrize(("line", "code"), BAD_LINES)
def test_harness_language_rejected(tmp_path: Path, line: str, code: str) -> None:
    write_skill(tmp_path, "bad", body=GOOD_BODY + "\n" + line + "\n")
    issues = [i for i in lint_tree(tmp_path) if i.level == "error"]
    assert [i.code for i in issues] == [code]
    assert issues[0].line == 10
    assert issues[0].format(tmp_path).startswith("bad/SKILL.md:10: error [")


@pytest.mark.parametrize(
    "line",
    [
        "The path /api/orders is public.",
        "Files under src/app/ are routes.",
        "Use math.pi for the radius.",
        "Taint flows into the sink.",
    ],
)
def test_harness_language_no_false_positives(tmp_path: Path, line: str) -> None:
    write_skill(tmp_path, "ok", body=GOOD_BODY + "\n" + line + "\n")
    assert codes(lint_tree(tmp_path)) == []


def test_reference_files_are_checked(tmp_path: Path) -> None:
    d = write_skill(tmp_path, "refs")
    (d / "references" / "notes.md").write_text("# Notes\n\nOpen it in Burp.\n")
    issues = [i for i in lint_tree(tmp_path) if i.level == "error"]
    assert [(i.path.name, i.line, i.code) for i in issues] == [("notes.md", 3, "harness:burp")]


def test_lint_allow_escape(tmp_path: Path) -> None:
    body = GOOD_BODY + "\nNever say Burp here. <!-- lint-allow: example of banned word -->\n"
    body += "<!-- lint-allow: next line quotes a banned tool -->\nDo not use the Task tool.\n"
    write_skill(tmp_path, "allowed", body=body)
    assert codes(lint_tree(tmp_path)) == []


def test_lint_allow_requires_reason(tmp_path: Path) -> None:
    write_skill(tmp_path, "noreason", body=GOOD_BODY + "\nUse Kali. <!-- lint-allow: -->\n")
    assert sorted(codes(lint_tree(tmp_path))) == ["harness:kali", "lint-allow"]


def test_bug_classes_file(tmp_path: Path) -> None:
    d = write_skill(tmp_path, "static-validation")
    (d / "references" / "sqli.md").write_text("# SQLi\n")
    (d / "references" / "notaclass.md").write_text("# Nope\n")
    (tmp_path / "bug-classes.yaml").write_text(
        "classes:\n  sqli: {aliases: [sql-injection]}\n  notes: {}\n  Bad_Class: {aliases: [sql-injection]}\n"
    )
    issues = [i for i in lint_tree(tmp_path) if i.code == "bug-classes"]
    msgs = " | ".join(i.message for i in issues)
    assert "notaclass.md" in msgs
    assert "kebab-case" in msgs
    assert "maps to both" in msgs


def test_main_output_and_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    write_skill(tmp_path, "bad", body=GOOD_BODY + "\nUse a subagent.\n")
    assert main([str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "bad/SKILL.md:10: error [harness:subagent]" in out
    assert "1 error(s)" in out
    assert main([str(tmp_path / "nope")]) == 2


def test_strict_promotes_warnings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(skills_lint, "SKILL_MD_WARN_BYTES", 10)
    write_skill(tmp_path, "big")
    assert main([str(tmp_path)]) == 0
    assert main([str(tmp_path), "--strict"]) == 1

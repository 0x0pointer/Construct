"""Skills linter: keeps prsec-skills harness-neutral and structurally sound.

Usage: prsec-skills-lint <dir> [--strict] [--quiet]

<dir> is either a skills repo root (every direct child holding a SKILL.md is a skill)
or a single skill directory. Every *.md file below <dir> is checked for harness-specific
language and broken relative links. A line can opt out of the harness-language check with
an inline `<!-- lint-allow: reason -->` (on the line itself, or alone on the line above).
"""
from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Literal
from urllib.parse import unquote

import yaml

NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
MAX_DESCRIPTION = 1024
SKILL_MD_WARN_BYTES = 40_000
SKILL_MD_MAX_BYTES = 100_000
REFERENCE_WARN_BYTES = 60_000
MIN_BODY_CHARS = 100
BUG_CLASSES_FILE = "bug-classes.yaml"

_I = re.IGNORECASE

HARNESS_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("task-tool", re.compile(r"\bTask\s+tool\b", _I)),
    ("subagent", re.compile(r"\bsub-?agents?\b", _I)),
    ("slash-command", re.compile(r"^\s*(?:[-*>]\s+|\d+\.\s+)?/[a-z][a-z0-9-]*(?=$|[\s`.,:;)])")),
    ("slash-command", re.compile(r"\bslash[\s-]commands?\b", _I)),
    ("todo-tool", re.compile(r"\bTodo(?:Write|Read)\b")),
    ("claude-code", re.compile(r"\bclaude[\s-]code\b", _I)),
    ("codex", re.compile(r"\bcodex\b", _I)),
    ("opencode", re.compile(r"\bopen-?code\b", _I)),
    ("pi-agent", re.compile(r"\bpi\b[\s-]+(?:coding[\s-]+)?(?:agent|harness|cli)\b", _I)),
    ("mcp-tool", re.compile(r"\bmcp__\w*|\bMCP\s+tools?\b", _I)),
    ("ask-user", re.compile(r"\bAskUserQuestion\b")),
    ("web-tool", re.compile(r"\bWeb(?:Fetch|Search)\b")),
    ("burp", re.compile(r"\bburp\b", _I)),
    ("kali", re.compile(r"\bkali\b", _I)),
    ("prompt-args", re.compile(r"\$ARGUMENTS\b")),
    ("harness-dir", re.compile(r"(?:^|[\s`(])\.(?:claude|codex|opencode)/", _I)),
]

ALLOW_RE = re.compile(r"<!--\s*lint-allow:(.*?)-->")
LINK_RE = re.compile(r"!?\[[^\]]*\]\(\s*(<[^>]*>|[^)\s]+)(?:\s+\"[^\"]*\")?\s*\)")
CODE_REF_RE = re.compile(r"`((?:references|scripts|assets)/[A-Za-z0-9_.\-/]+)`")
SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*:")
FENCE_RE = re.compile(r"^\s*(```|~~~)")


@dataclass(frozen=True)
class Issue:
    path: Path
    line: int
    level: Literal["error", "warning"]
    code: str
    message: str

    def format(self, root: Path | None = None) -> str:
        shown = self.path
        if root is not None:
            try:
                shown = self.path.relative_to(root)
            except ValueError:
                pass
        return f"{shown}:{self.line}: {self.level} [{self.code}] {self.message}"


def _err(path: Path, line: int, code: str, msg: str) -> Issue:
    return Issue(path, line, "error", code, msg)


def _warn(path: Path, line: int, code: str, msg: str) -> Issue:
    return Issue(path, line, "warning", code, msg)


# ------------------------------------------------------------------ frontmatter


def split_frontmatter(text: str) -> tuple[str, str, int] | None:
    """(frontmatter, body, body_start_line) or None if the file has no frontmatter block."""
    lines = text.splitlines(keepends=True)
    if not lines or lines[0].strip() != "---":
        return None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            return "".join(lines[1:i]), "".join(lines[i + 1 :]), i + 2
    return None


def lint_frontmatter(skill_md: Path, text: str) -> list[Issue]:
    issues: list[Issue] = []
    split = split_frontmatter(text)
    if split is None:
        return [_err(skill_md, 1, "frontmatter", "SKILL.md must start with a '---' YAML frontmatter block")]
    fm_text, body, _ = split
    try:
        fm = yaml.safe_load(fm_text) or {}
    except yaml.YAMLError as e:
        return [_err(skill_md, 1, "frontmatter", f"invalid YAML frontmatter: {e}")]
    if not isinstance(fm, dict):
        return [_err(skill_md, 1, "frontmatter", "frontmatter must be a YAML mapping")]

    def line_of(key: str) -> int:
        for i, ln in enumerate(fm_text.splitlines(), start=2):
            if ln.startswith(f"{key}:"):
                return i
        return 1

    dir_name = skill_md.parent.name
    name = fm.get("name")
    if not isinstance(name, str) or not name.strip():
        issues.append(_err(skill_md, 1, "name", "frontmatter 'name' is required"))
    else:
        if name != dir_name:
            issues.append(_err(skill_md, line_of("name"), "name", f"name {name!r} must match directory {dir_name!r}"))
        if not NAME_RE.match(name):
            issues.append(_err(skill_md, line_of("name"), "name", f"name {name!r} must be kebab-case"))

    desc = fm.get("description")
    dline = line_of("description")
    if not isinstance(desc, str) or not desc.strip():
        issues.append(_err(skill_md, dline, "description", "frontmatter 'description' is required"))
    else:
        if len(desc) > MAX_DESCRIPTION:
            issues.append(
                _err(skill_md, dline, "description", f"description is {len(desc)} chars (max {MAX_DESCRIPTION})")
            )
        raw = next((ln for ln in fm_text.splitlines() if ln.startswith("description:")), "")
        inline = raw.split(":", 1)[1].strip() if ":" in raw else ""
        if not inline or inline[0] in "|>":
            issues.append(
                _err(
                    skill_md,
                    dline,
                    "description",
                    "description must be a single-line scalar (the fallback skills index reads one line)",
                )
            )

    if len(body.strip()) < MIN_BODY_CHARS:
        issues.append(_err(skill_md, 1, "size", f"SKILL.md body is nearly empty (< {MIN_BODY_CHARS} chars)"))
    return issues


# ------------------------------------------------------------------ markdown


def _allowed_lines(lines: list[str], path: Path) -> tuple[set[int], list[Issue]]:
    allowed: set[int] = set()
    issues: list[Issue] = []
    for i, ln in enumerate(lines, start=1):
        m = ALLOW_RE.search(ln)
        if not m:
            continue
        if not m.group(1).strip():
            issues.append(_err(path, i, "lint-allow", "lint-allow needs a reason: <!-- lint-allow: why -->"))
            continue
        allowed.add(i)
        if ALLOW_RE.sub("", ln).strip() == "":
            allowed.add(i + 1)
    return allowed, issues


def lint_harness_language(path: Path, text: str) -> list[Issue]:
    lines = text.splitlines()
    allowed, issues = _allowed_lines(lines, path)
    for i, ln in enumerate(lines, start=1):
        if i in allowed:
            continue
        seen: set[str] = set()
        for code, pat in HARNESS_PATTERNS:
            m = pat.search(ln)
            if m and code not in seen:
                seen.add(code)
                issues.append(
                    _err(path, i, f"harness:{code}", f"harness-specific language {m.group(0).strip()!r}")
                )
    return issues


def _skill_dir_of(path: Path, root: Path) -> Path:
    for d in [path.parent, *path.parent.parents]:
        if (d / "SKILL.md").is_file():
            return d
        if d == root:
            break
    return path.parent


def _iter_outside_fences(lines: list[str]) -> Iterator[tuple[int, str]]:
    in_fence = False
    for i, ln in enumerate(lines, start=1):
        if FENCE_RE.match(ln):
            in_fence = not in_fence
            continue
        if not in_fence:
            yield i, ln


def lint_links(path: Path, text: str, root: Path) -> list[Issue]:
    issues: list[Issue] = []
    root_r = root.resolve()
    skill_dir = _skill_dir_of(path, root)
    for i, ln in _iter_outside_fences(text.splitlines()):
        for m in LINK_RE.finditer(ln):
            target = m.group(1).strip("<>")
            if not target or target.startswith("#") or SCHEME_RE.match(target):
                continue
            rel = unquote(target.split("#", 1)[0])
            if not rel:
                continue
            if rel.startswith("/"):
                issues.append(_err(path, i, "link", f"absolute link {target!r}; use a path relative to this file"))
                continue
            resolved = (path.parent / rel).resolve()
            if not resolved.is_relative_to(root_r):
                issues.append(_err(path, i, "link", f"link {target!r} escapes the skills directory"))
            elif not resolved.exists():
                issues.append(_err(path, i, "link", f"broken relative link {target!r}"))
        for m in CODE_REF_RE.finditer(ln):
            ref = m.group(1).rstrip("/.")
            if not any((base / ref).exists() for base in (path.parent, skill_dir)):
                issues.append(_err(path, i, "link", f"referenced file `{ref}` does not exist"))
    return issues


# ------------------------------------------------------------------ bug classes


def load_bug_classes(root: Path) -> dict[str, dict] | None:
    f = root / BUG_CLASSES_FILE
    if not f.is_file():
        return None
    data = yaml.safe_load(f.read_text()) or {}
    return data.get("classes") or {}


def bug_class_aliases(root: Path) -> dict[str, str]:
    """alias-or-canonical -> canonical bug_class, from <root>/bug-classes.yaml."""
    out: dict[str, str] = {}
    for name, meta in (load_bug_classes(root) or {}).items():
        out[name] = name
        for alias in (meta or {}).get("aliases", []) or []:
            out[alias] = name
    return out


def lint_bug_classes(root: Path) -> list[Issue]:
    f = root / BUG_CLASSES_FILE
    try:
        classes = load_bug_classes(root)
    except yaml.YAMLError as e:
        return [_err(f, 1, "bug-classes", f"invalid YAML: {e}")]
    if classes is None:
        return []
    issues: list[Issue] = []
    seen: dict[str, str] = {}
    for name, meta in classes.items():
        if not NAME_RE.match(str(name)):
            issues.append(_err(f, 1, "bug-classes", f"bug class {name!r} must be kebab-case"))
        for alias in [name, *((meta or {}).get("aliases", []) or [])]:
            if alias in seen and seen[alias] != name:
                issues.append(_err(f, 1, "bug-classes", f"{alias!r} maps to both {seen[alias]!r} and {name!r}"))
            seen[alias] = name
    refs = root / "static-validation" / "references"
    if refs.is_dir():
        for ref in sorted(refs.glob("*.md")):
            if ref.stem.lower() == "readme":
                continue
            if ref.stem not in classes:
                issues.append(
                    _err(ref, 1, "bug-classes", f"reference {ref.name} is not a canonical bug class in {BUG_CLASSES_FILE}")
                )
    return issues


# ------------------------------------------------------------------ drivers


def lint_skill(skill_dir: Path, root: Path | None = None) -> list[Issue]:
    root = root or skill_dir
    skill_md = skill_dir / "SKILL.md"
    if not skill_md.is_file():
        return [_err(skill_dir, 1, "missing", "skill directory has no SKILL.md")]
    text = skill_md.read_text(encoding="utf-8")
    issues = lint_frontmatter(skill_md, text)
    size = len(text.encode())
    if size > SKILL_MD_MAX_BYTES:
        issues.append(_err(skill_md, 1, "size", f"SKILL.md is {size} bytes (max {SKILL_MD_MAX_BYTES}); move detail to references/"))
    elif size > SKILL_MD_WARN_BYTES:
        issues.append(_warn(skill_md, 1, "size", f"SKILL.md is {size} bytes; consider moving detail to references/"))
    return issues


def lint_markdown(path: Path, root: Path) -> list[Issue]:
    text = path.read_text(encoding="utf-8")
    issues = lint_harness_language(path, text) + lint_links(path, text, root)
    if path.name != "SKILL.md" and len(text.encode()) > REFERENCE_WARN_BYTES:
        issues.append(_warn(path, 1, "size", f"{path.name} is {len(text.encode())} bytes; consider splitting"))
    return issues


def skill_dirs(root: Path) -> list[Path]:
    if (root / "SKILL.md").is_file():
        return [root]
    return sorted(d for d in root.iterdir() if d.is_dir() and (d / "SKILL.md").is_file())


def lint_tree(root: Path) -> list[Issue]:
    root = root.resolve()
    issues: list[Issue] = []
    for d in skill_dirs(root):
        issues += lint_skill(d, root)
    for md in sorted(root.rglob("*.md")):
        if any(part.startswith(".") for part in md.relative_to(root).parts):
            continue
        issues += lint_markdown(md, root)
    issues += lint_bug_classes(root)
    return sorted(issues, key=lambda x: (str(x.path), x.line, x.code))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="prsec-skills-lint", description="Lint a PRSec skills directory.")
    ap.add_argument("dir", type=Path)
    ap.add_argument("--strict", action="store_true", help="treat warnings as errors")
    ap.add_argument("--quiet", action="store_true", help="only print errors")
    args = ap.parse_args(argv)
    root: Path = args.dir
    if not root.is_dir():
        print(f"prsec-skills-lint: not a directory: {root}", file=sys.stderr)
        return 2
    issues = lint_tree(root)
    if args.strict:
        issues = [Issue(i.path, i.line, "error", i.code, i.message) for i in issues]
    errors = [i for i in issues if i.level == "error"]
    warnings = [i for i in issues if i.level == "warning"]
    for i in issues:
        if i.level == "error" or not args.quiet:
            print(i.format(root.resolve()))
    print(f"{len(errors)} error(s), {len(warnings)} warning(s) in {len(skill_dirs(root))} skill(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())

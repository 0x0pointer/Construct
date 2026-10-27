"""Deterministic pre-triage skip-list (plan §3.1a).

Only obvious noise is skipped: docs, styling/assets, lockfiles and version-only
manifest bumps, generated code, and diffs that only touch comments/whitespace.
Anything uncertain goes to the LLM triage stage. False "llm" is cheap; a false
"skip" hides a vulnerability, so every rule errs towards "llm".
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Literal

Decision = tuple[Literal["skip", "llm"], str | None]

# ------------------------------------------------------------------ categories

# .mdx compiles to JS (imports components) and .txt is often build logic (CMakeLists.txt) or prompt /
# template text, so neither is docs by extension; .txt only counts for well-known doc names.
_DOC_EXT = {".md", ".rst", ".adoc", ".asciidoc"}
_DOC_NAMES = re.compile(
    r"^(README|LICEN[CS]E|COPYING|NOTICE|AUTHORS|CONTRIBUTORS|CHANGELOG|CHANGES|HISTORY)([._-][\w.-]*)?$", re.I
)
_NOT_DOC_TXT = re.compile(r"^(requirements|constraints)[\w.-]*\.txt$", re.I)

_ASSET_EXT = {
    ".css", ".scss", ".sass", ".less", ".styl",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tif", ".tiff", ".avif",  # not .svg: it can carry script
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".mp3", ".mp4", ".webm", ".wav", ".ogg",
}

_LOCKFILES = {
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock",
    "poetry.lock", "pipfile.lock", "pdm.lock", "uv.lock", "go.sum", "cargo.lock", "gemfile.lock",
    "composer.lock", "packages.lock.json", "gradle.lockfile", "mix.lock", "pubspec.lock", "podfile.lock",
    "flake.lock",
}

_GENERATED_GLOBS = (
    "*/generated/*", "generated/*", "*/__generated__/*", "__generated__/*", "*/gen/proto/*",
    "*.pb.go", "*_pb2.py", "*_pb2_grpc.py", "*_pb2.pyi", "*.pb.ts", "*_pb.js", "*_pb.d.ts", "*.pb.swift",
    "*.min.js", "*.min.css", "*.js.map", "*.css.map", "*.g.dart", "*.freezed.dart", "*.designer.cs",
    "*.snap",
)

# --------------------------------------------------------- version-only bumps

_VERSION = r"""[\^~=<>!*]*\s*v?\d[\w.\-+*]*|\*|latest"""
_MANIFEST_LINE: dict[str, re.Pattern[str]] = {
    "package.json": re.compile(rf"""^\s*"(?P<name>[^"]+)"\s*:\s*"(?:{_VERSION})"\s*,?\s*$"""),
    "composer.json": re.compile(rf"""^\s*"(?P<name>[^"]+)"\s*:\s*"(?:{_VERSION})"\s*,?\s*$"""),
    "requirements": re.compile(r"""^\s*(?P<name>[A-Za-z0-9_.\-]+(\[[\w,\-]+\])?)\s*(==|>=|<=|~=|!=|>|<)\s*[\w.*+\-,<>=!]+\s*$"""),
    "go.mod": re.compile(r"""^\s*(require\s+)?(?P<name>[\w.\-]+(/[\w.\-~]+)+)\s+v[\w.\-+]+(\s*//\s*indirect)?\s*$"""),
    "toml": re.compile(
        rf"""^\s*(?:"(?P<qname>[\w.\-]+)\s*(?:==|>=|<=|~=|\^|~|>|<)[^"]*"\s*,?|(?P<name>[\w.\-]+)\s*=\s*"(?:{_VERSION})")\s*$"""
    ),
}

# ------------------------------------------------------------ comment syntax

_HASH = ("#",)
_SLASH = ("//", "/*", "*/")
_COMMENT_PREFIX: dict[str, tuple[str, ...]] = {
    **dict.fromkeys([".py", ".rb", ".sh", ".bash", ".zsh", ".pl", ".r", ".yaml", ".yml", ".toml", ".cfg",
                     ".ini", ".conf", ".properties", ".ex", ".exs", ".tf", ".hcl", ".nix"], _HASH),
    **dict.fromkeys([".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".java", ".kt", ".kts", ".scala", ".go",
                     ".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".swift", ".rs", ".dart", ".groovy", ".gradle",
                     ".proto", ".vue", ".svelte"], _SLASH),
    ".php": _SLASH + _HASH,
    **dict.fromkeys([".sql", ".lua", ".hs"], ("--",)),
    **dict.fromkeys([".html", ".htm", ".xml"], ("<!--", "-->")),
}
_COMMENT_PREFIX[".tf"] = _HASH + _SLASH
_COMMENT_PREFIX[".hcl"] = _HASH + _SLASH
_NOT_COMMENT = ("#[", "#!", "#include", "#define", "#if", "#pragma")  # attributes / preprocessor / shebang
_INDENT_SENSITIVE = {".py", ".yaml", ".yml", ".haml", ".pug", ".nim", ".coffee"}


@dataclass
class FileDiff:
    path: str
    removed: list[str] = field(default_factory=list)
    added: list[str] = field(default_factory=list)
    has_hunks: bool = False
    binary: bool = False
    # per hunk, the old and the new side in order (context lines on both), so moves are visible
    hunks: list[tuple[list[str], list[str]]] = field(default_factory=list)


def parse_diff(diff: str) -> dict[str, FileDiff]:
    """Split a unified diff into per-file added/removed lines (keyed by new path, old path for deletions)."""
    files: dict[str, FileDiff] = {}
    cur: FileDiff | None = None
    old_path = new_path = None
    in_hunk = False
    for line in diff.splitlines():
        if line.startswith("diff --git "):
            m = re.match(r"diff --git a/(.+?) b/(.+)$", line)
            old_path, new_path = (m.group(1), m.group(2)) if m else (None, None)
            cur = FileDiff(new_path or "") if new_path else None
            if cur:
                files[cur.path] = cur
            in_hunk = False
            continue
        if cur is None:
            continue
        if not in_hunk and line.startswith("+++ "):
            target = line[4:].strip()
            if target == "/dev/null" and old_path:
                files.pop(cur.path, None)
                cur.path = old_path
                files[cur.path] = cur
            continue
        if not in_hunk and (line.startswith("--- ")):
            continue
        if line.startswith("Binary files ") or line.startswith("GIT binary patch"):
            cur.binary = True
            continue
        if line.startswith("@@"):
            in_hunk = True
            cur.has_hunks = True
            cur.hunks.append(([], []))
            continue
        if not in_hunk:
            continue
        old_side, new_side = cur.hunks[-1]
        if line.startswith("+"):
            cur.added.append(line[1:])
            new_side.append(line[1:])
        elif line.startswith("-"):
            cur.removed.append(line[1:])
            old_side.append(line[1:])
        elif line.startswith(" ") or line == "":
            old_side.append(line[1:])
            new_side.append(line[1:])
    return files


def _norm(path: str) -> str:
    p = path.strip().replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p.lstrip("/")


def category(path: str) -> str | None:
    """Noise category of a path, or None if it may carry logic."""
    p = _norm(path)
    name = PurePosixPath(p).name
    lname = name.lower()
    ext = PurePosixPath(lname).suffix
    if any(fnmatch.fnmatch(p, g) for g in _GENERATED_GLOBS):
        return "generated"
    if lname in _LOCKFILES:
        return "lockfile"
    if ext in _ASSET_EXT:
        return "asset"
    if _DOC_NAMES.match(name) or ext in _DOC_EXT:
        return "docs"
    return None


def _manifest_kind(path: str) -> str | None:
    name = PurePosixPath(_norm(path)).name.lower()
    if name in ("package.json", "composer.json", "go.mod"):
        return name
    if _NOT_DOC_TXT.match(name):
        return "requirements"
    if name in ("pyproject.toml", "cargo.toml"):
        return "toml"
    return None


def is_version_bump(path: str, fd: FileDiff) -> bool:
    """True if every changed line re-pins an already-listed dependency (no additions/removals)."""
    kind = _manifest_kind(path)
    if kind is None or not fd.has_hunks:
        return False
    pat = _MANIFEST_LINE[kind]

    def names(lines: list[str]) -> list[str] | None:
        out = []
        for line in lines:
            if not line.strip():
                continue
            m = pat.match(line)
            if not m:
                return None
            out.append((m.groupdict().get("qname") or m.group("name")).lower())
        return out

    removed, added = names(fd.removed), names(fd.added)
    return bool(removed) and removed is not None and added is not None and sorted(removed) == sorted(added)


def _is_comment(line: str, prefixes: tuple[str, ...]) -> bool:
    s = line.strip()
    if not s:
        return True
    if s.startswith(_NOT_COMMENT):
        return False
    return any(s.startswith(p) for p in prefixes)


def _code_lines(lines: list[str], prefixes: tuple[str, ...], indent: bool) -> list[str]:
    """Non-comment lines in order. Block-comment bodies only count as comments after their `/*` was
    seen in the same hunk: a hunk starting mid-comment looks like code (a false 'llm' is cheap)."""
    out = []
    in_block = False
    for line in lines:
        s = line.strip()
        if in_block:
            in_block = "*/" not in s
            continue
        if "/*" in prefixes and s.startswith("/*"):
            in_block = "*/" not in s[2:]
            continue
        if _is_comment(line, prefixes):
            continue
        out.append(line.rstrip() if indent else " ".join(line.split()))
    return out


def is_comment_or_whitespace_only(path: str, fd: FileDiff) -> bool:
    """Every hunk reads the same, line for line and in order, once comments and whitespace are
    dropped. Comparing per hunk with context (not the file's removed vs added lines) keeps a moved
    statement, e.g. an authorization check moved below the write, out of this category."""
    ext = PurePosixPath(_norm(path).lower()).suffix
    prefixes = _COMMENT_PREFIX.get(ext)
    if prefixes is None or fd.binary or not fd.hunks:
        return False
    indent = ext in _INDENT_SENSITIVE
    return all(_code_lines(old, prefixes, indent) == _code_lines(new, prefixes, indent) for old, new in fd.hunks)


def classify(changed_files: list[str], diff: str) -> Decision:
    """('skip', reason) for obvious noise, else ('llm', None)."""
    per_file = parse_diff(diff)
    files = sorted({_norm(f) for f in changed_files} | set(per_file))
    if not files:
        return "skip", "empty_diff"
    counts: dict[str, int] = {}
    for f in files:
        cat = category(f)
        if cat is None:
            fd = per_file.get(f)
            if fd is None:
                return "llm", None
            if is_version_bump(f, fd):
                cat = "version_bump"
            elif is_comment_or_whitespace_only(f, fd):
                cat = "comments_whitespace"
            else:
                return "llm", None
        counts[cat] = counts.get(cat, 0) + 1
    return "skip", "noise_only:" + ",".join(f"{k}={v}" for k, v in sorted(counts.items()))

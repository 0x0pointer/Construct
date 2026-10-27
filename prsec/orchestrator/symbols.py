"""Best-effort enclosing function/method name for a line, used for stable fingerprints."""
from __future__ import annotations

import re
from pathlib import Path

_MAX_SCAN = 400
_KEYWORDS = {"if", "for", "while", "switch", "catch", "return", "else", "elif", "with", "new", "function", "await", "sizeof"}

_PY_DEF = re.compile(r"^(?P<ind>\s*)(?:async\s+)?def\s+(?P<name>\w+)\s*\(")
_PY_CLASS = re.compile(r"^(?P<ind>\s*)class\s+(?P<name>\w+)")
_GO_FUNC = re.compile(r"^func\s+(?:\(\s*\w*\s*\*?(?P<recv>\w+)[^)]*\)\s*)?(?P<name>\w+)\s*[\[(]")
_RB_DEF = re.compile(r"^\s*def\s+(?:self\.)?(?P<name>\w+[?!]?)")
_GENERIC = [
    re.compile(r"\bfunction\s*\*?\s+(?P<name>\w+)\s*\("),
    re.compile(r"\b(?:fun|fn)\s+(?:<[^>]*>\s*)?(?:\w+\.)?(?P<name>\w+)\s*[<(]"),
    re.compile(r"\b(?:const|let|var)\s+(?P<name>\w+)\s*=\s*(?:async\s+)?(?:function\b|\([^)]*\)\s*(?::[^=]+)?=>|\w+\s*=>)"),
    re.compile(r"^\s*(?P<name>\w+)\s*[:=]\s*(?:async\s+)?(?:function\b|\([^)]*\)\s*=>)"),
    re.compile(
        r"^\s*(?:(?:public|private|protected|internal|static|final|abstract|override|virtual|async|synchronized|export|default)\s+)+"
        r"(?:[\w<>\[\],.?]+\s+)?(?P<name>\w+)\s*\([^;]*$"
    ),
    re.compile(r"^\s*(?:async\s+)?(?P<name>\w+)\s*\([^)]*\)\s*(?::\s*[\w<>\[\],.| ]+)?\s*\{\s*$"),
]


def _python(lines: list[str], idx: int) -> str | None:
    target = len(lines[idx]) - len(lines[idx].lstrip())
    name = None
    def_ind = None
    for i in range(idx, max(-1, idx - _MAX_SCAN), -1):
        line = lines[i]
        if not line.strip():
            continue
        ind = len(line) - len(line.lstrip())
        if name is None:
            m = _PY_DEF.match(line)
            if m and (i == idx or ind < target):
                name, def_ind = m.group("name"), ind
            continue
        m = _PY_CLASS.match(line)
        if m and ind < def_ind:
            return f"{m.group('name')}.{name}"
        if ind == 0:
            break
    return name


def _other(lines: list[str], idx: int) -> str | None:
    for i in range(idx, max(-1, idx - _MAX_SCAN), -1):
        line = lines[i]
        m = _GO_FUNC.match(line)
        if m:
            return f"{m.group('recv')}.{m.group('name')}" if m.group("recv") else m.group("name")
        m = _RB_DEF.match(line)
        if m:
            return m.group("name")
        for pat in _GENERIC:
            m = pat.search(line)
            if m and m.group("name") not in _KEYWORDS:
                return m.group("name")
    return None


def enclosing_symbol(src_root: Path, file: str, line: int) -> str | None:
    try:
        path = (src_root / file).resolve()
        if not path.is_relative_to(src_root.resolve()):
            return None
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return None
    if not lines or line < 1:
        return None
    idx = min(line, len(lines)) - 1
    return _python(lines, idx) if file.endswith(".py") else _other(lines, idx)

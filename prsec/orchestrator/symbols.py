"""Best-effort enclosing function/method name for a line, used for stable fingerprints."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Callable

_MAX_SCAN = 400
_KEYWORDS = {"if", "for", "while", "switch", "catch", "return", "else", "elif", "with", "new", "function", "await", "sizeof"}

_PY_DEF = re.compile(r"^(?P<ind>\s*)(?:async\s+)?def\s+(?P<name>\w+)\s*\(")
_PY_CLASS = re.compile(r"^(?P<ind>\s*)class\s+(?P<name>\w+)")
# The receiver's contents are parsed by `_go_receiver`, not by the regex: one regex for both is
# ambiguous (receiver name vs type) and backtracks super-linearly.
_GO_FUNC = re.compile(r"^func\s+(?:\((?P<recv>[^)]*)\)\s*)?(?P<name>\w+)\s*[\[(]")
_WORD = re.compile(r"\w*")
_RB_DEF = re.compile(r"^\s*def\s+(?:self\.)?(?P<name>\w+[?!]?)")
# `const f = <value>`: the declaration and its function value are matched separately (see `_js_function_decl`).
_JS_DECL = re.compile(r"\b(?:const|let|var)\s+(?P<name>\w+)\s*=\s*")
_JS_FUNCTION_VALUE = re.compile(r"(?:async\s+)?(?:function\b|\([^)]*\)\s*(?::[^=]+)?=>|\w+\s*=>)")
# `name(args): Type {`: the call head and the rest of the line are matched separately (see `_method_decl`).
_METHOD_HEAD = re.compile(r"^\s*(?:async\s+)?(?P<name>\w+)\s*\([^)]*\)")
# Optional `: Type` then `{` ending the line. The type is either non-blank, or blank but holding at
# least one plain space (the type characters include a space); possessive quantifiers keep it linear.
_METHOD_TAIL = re.compile(r"\s*+(?::(?:\s*+[\w<>\[\],.|][\w<>\[\],.| ]*+|[^\S ]*+ ))?\s*\{\s*$")


def _go_receiver(recv: str) -> str | None:
    """Receiver type of `(r *T)` / `(*T)` / `(r T)`, as `\\s*\\w*\\s*\\*?(\\w+)` captures it: for an unnamed
    `(T)` that is T's last character, kept as is so existing fingerprints stay stable."""
    rest = recv.lstrip()
    first = _WORD.match(rest).group()  # type: ignore[union-attr]
    rest = rest[len(first):].lstrip()
    second = _WORD.match(rest.removeprefix("*")).group()  # type: ignore[union-attr]
    return second or first[-1:] or None


def _go_name(m: re.Match[str]) -> str | None:
    """`Recv.Name` for a method, `Name` for a function, None for a receiver that is not one."""
    if m.group("recv") is None:
        return m.group("name")
    recv = _go_receiver(m.group("recv"))
    return f"{recv}.{m.group('name')}" if recv else None


def _js_function_decl(line: str) -> re.Match[str] | None:
    """First `const|let|var <name> = <function value>` in the line."""
    for m in _JS_DECL.finditer(line):
        if _JS_FUNCTION_VALUE.match(line, m.end()):
            return m
    return None


def _method_decl(line: str) -> re.Match[str] | None:
    m = _METHOD_HEAD.match(line)
    return m if m and _METHOD_TAIL.match(line, m.end()) else None


_GENERIC: list[Callable[[str], re.Match[str] | None]] = [
    re.compile(r"\bfunction(?:\s*\*)?\s+(?P<name>\w+)\s*\(").search,
    re.compile(r"\b(?:fun|fn)\s+(?:<[^>]*>\s*)?(?:\w+\.)?(?P<name>\w+)\s*[<(]").search,
    _js_function_decl,
    re.compile(r"^\s*(?P<name>\w+)\s*[:=]\s*(?:async\s+)?(?:function\b|\([^)]*\)\s*=>)").search,
    re.compile(
        r"^\s*(?:(?:public|private|protected|internal|static|final|abstract|override|virtual|async|synchronized|export|default)\s+)+"
        r"(?:[\w<>\[\],.?]+\s+)?(?P<name>\w+)\s*\([^;]*$"
    ).search,
    _method_decl,
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
        go_name = _go_name(m) if m else None
        if go_name:
            return go_name
        m = _RB_DEF.match(line)
        if m:
            return m.group("name")
        for search in _GENERIC:
            m = search(line)
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

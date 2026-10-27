"""Deterministic citation verifier: every cited file:line must exist and the quote must match the code."""
from __future__ import annotations

import re
from pathlib import Path, PurePath, PurePosixPath
from typing import Iterable

from rapidfuzz import fuzz

from prsec.models import StageTask
from prsec.stages.outputs import Citation

MIN_SCORE = 85.0
CONTEXT_LINES = 2
# A quote must cover most of at least one real code line, so a generic token ("return", "self.")
# cannot vouch for an invented location. Lines shorter than MIN_LINE_CHARS ("}", "")
# never count as covered.
LINE_COVERAGE = 0.8
MIN_LINE_CHARS = 3
# Where the repository is mounted inside the workbench; agents may cite absolute container paths.
CONTAINER_WORKDIR = PurePosixPath(StageTask.model_fields["workdir"].default)
_WS = re.compile(r"\s+")


def normalise(text: str) -> str:
    return _WS.sub(" ", text).strip()


def _relative_to_any(path: PurePath, roots: Iterable[PurePath]) -> PurePath | None:
    for r in roots:
        try:
            return path.relative_to(r)
        except ValueError:
            continue
    return None


def repo_relative(file: str, src_root: Path | None = None) -> str:
    """Repo-relative form of a cited path (strips the container workdir or src_root prefix, './')."""
    p = PurePosixPath(file.replace("\\", "/"))
    if p.is_absolute():
        roots: list[PurePath] = [CONTAINER_WORKDIR]
        if src_root is not None:
            roots += [src_root, src_root.resolve()]
        rel = _relative_to_any(p, roots)
        if rel is None:
            return file
        p = PurePosixPath(rel.as_posix())
    return p.as_posix().removeprefix("./") if p.as_posix() != "." else "."


def resolve(src_root: Path, file: str) -> Path | None:
    """Resolve a repo-relative (or absolute-under-root, or container `/work/src/...`) path; None if it escapes src_root."""
    root = src_root.resolve()
    candidate = Path(file)
    if candidate.is_absolute():
        rel = _relative_to_any(candidate, [src_root, root, CONTAINER_WORKDIR])
        if rel is None:
            return None
        candidate = Path(rel)
    path = (root / candidate).resolve()
    return path if path.is_relative_to(root) and path != root else None


def _read_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


def verify_citation(c: Citation, src_root: Path) -> str | None:
    path = resolve(src_root, c.file)
    if path is None:
        return f"{c.file}: path escapes the repository root"
    if not path.is_file():
        return f"{c.file}: file does not exist"
    try:
        lines = _read_lines(path)
    except OSError as e:
        return f"{c.file}: unreadable ({e.strerror})"
    if not 1 <= c.line <= len(lines):
        return f"{c.file}:{c.line}: line out of range (file has {len(lines)} lines)"
    if c.end_line is not None and not c.line <= c.end_line <= len(lines):
        return f"{c.file}:{c.line}-{c.end_line}: end_line out of range (file has {len(lines)} lines)"

    quote = normalise(c.quote)
    if len(quote) < 3:
        return f"{c.file}:{c.line}: quote is empty or too short to verify"
    end = c.end_line or c.line + max(c.quote.strip().count("\n"), 0)
    lo = max(c.line - 1 - CONTEXT_LINES, 0)
    hi = min(end + CONTEXT_LINES, len(lines))
    window = normalise(" ".join(lines[lo:hi]))
    # partial_ratio aligns the shorter string inside the longer one; a quote longer than
    # the window must not "match" merely because the window is contained in it.
    score = fuzz.partial_ratio(quote, window) if len(quote) <= len(window) else fuzz.ratio(quote, window)
    if score < MIN_SCORE:
        return f"{c.file}:{c.line}: quote does not match the code at that location (similarity {score:.0f} < {MIN_SCORE:.0f})"
    if not any(_covers(quote, normalise(line)) for line in lines[lo:hi]):
        return f"{c.file}:{c.line}: quote must reproduce at least one full line of the cited code, not a fragment"
    return None


def _covers(quote: str, line: str) -> bool:
    """True if `quote` reproduces (most of) the code line `line`."""
    if len(line.replace(" ", "")) < MIN_LINE_CHARS:
        return False
    if len(line) <= len(quote):
        return fuzz.partial_ratio(line, quote) >= MIN_SCORE
    return len(quote) >= LINE_COVERAGE * len(line) and fuzz.partial_ratio(quote, line) >= MIN_SCORE


def verify_all(cits: Iterable[Citation], src_root: Path) -> list[str]:
    return [err for c in cits if (err := verify_citation(c, src_root)) is not None]


def snippet(src_root: Path, file: str, line: int, end_line: int | None = None) -> str:
    """Code at file:line[-end_line] from the trusted snapshot; empty string if it cannot be resolved."""
    path = resolve(src_root, file)
    if path is None or not path.is_file():
        return ""
    try:
        lines = _read_lines(path)
    except OSError:
        return ""
    start = max(line, 1)
    stop = min(end_line or line, len(lines))
    return "\n".join(lines[start - 1 : stop])

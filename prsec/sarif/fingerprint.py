"""Stable finding fingerprints (`partialFingerprints["prsec/v1"]`).

Identity = bug_class + sink file + sink symbol + entry point. Line numbers and
code text are deliberately excluded, so a finding keeps its fingerprint across
line moves, reformatting and refactors that keep the enclosing symbol and route.

Trade-offs:
- Renaming the sink function/method, moving it to another file, or changing the
  route changes the fingerprint (the finding re-appears as new; the old one goes
  stale). This is preferred over content hashing, which breaks on any edit.
- Two distinct bugs of the same class in the same symbol reached via the same
  entry point collapse into one finding. When the symbol is unknown, everything
  of that class in the file and route collapses; acceptable for PR-level triage.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import PurePosixPath

VERSION = "prsec/v1"

_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT", "ANY", "ALL"}
_PARAM_SEGMENT = re.compile(
    r"""^(
        :[^/]+                      # :id
      | \{[^/]*\}                   # {id} / {id:int}
      | <[^/]*>                     # <int:id> (flask)
      | \[[^/]*\]                   # [id] (next.js)
      | \d+                         # 123
      | [0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}  # uuid
      | [0-9a-fA-F]{24,}            # object ids / hashes
    )$""",
    re.VERBOSE,
)


def normalise_file(path: str) -> str:
    p = path.strip().replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    p = p.lstrip("/")
    parts = PurePosixPath(p).parts if p else ()
    p = "/".join(x for x in parts if x not in ("", "."))
    stem, dot, ext = p.rpartition(".")
    if dot and stem and "/" not in ext:
        p = f"{stem}.{ext.lower()}"
    return p


def normalise_symbol(symbol: str | None) -> str:
    """`OrderService.create( self, req )` -> `OrderService.create`."""
    if not symbol:
        return ""
    s = symbol.strip()
    s = re.sub(r"^(async\s+)?(def|function|func|fn)\s+", "", s)
    s = s.split("(", 1)[0]
    s = s.split("<", 1)[0]  # generics
    s = s.replace("::", ".").replace("#", ".").replace("->", ".")
    s = re.sub(r"\s+", "", s)
    return s.strip(".")


def normalise_entry_point(entry_point: str | None) -> str:
    """`post /orders/123?x=1` -> `POST /orders/{}`; non-HTTP entry points are whitespace-normalised."""
    if not entry_point:
        return ""
    ep = " ".join(entry_point.split())
    method, _, rest = ep.partition(" ")
    if method.upper() in _HTTP_METHODS and rest.startswith("/"):
        return f"{method.upper()} {_normalise_route(rest)}"
    if ep.startswith("/"):
        return _normalise_route(ep)
    return ep


def _normalise_route(route: str) -> str:
    path = route.split(" ", 1)[0].split("?", 1)[0].split("#", 1)[0]
    segs = [s for s in path.split("/") if s]
    out = ["{}" if _PARAM_SEGMENT.match(s) else s for s in segs]
    return "/" + "/".join(out)


def fingerprint(bug_class: str, sink_file: str, sink_symbol: str | None, entry_point: str | None) -> str:
    material = "|".join(
        [
            VERSION,
            bug_class.strip().lower(),
            normalise_file(sink_file),
            normalise_symbol(sink_symbol),
            normalise_entry_point(entry_point),
        ]
    )
    return hashlib.sha256(material.encode()).hexdigest()[:32]

"""prsec-cite: let an agent self-check the citations in its output before handing it in.

    prsec-cite check <json-file> [--root /work/src]

Every object carrying file/line/quote keys (at any depth) is verified against the repo.
Exit 0 = all citations verified, 1 = at least one failed, 2 = usage / unreadable input.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Iterator

from pydantic import ValidationError

from prsec.citations import verify_citation
from prsec.stages.outputs import Citation

DEFAULT_ROOT = "/work/src"


def find_citations(node: Any, path: str = "$") -> Iterator[tuple[str, Any]]:
    if isinstance(node, dict):
        if {"file", "line", "quote"} <= node.keys():
            yield path, node
        for k, v in node.items():
            yield from find_citations(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from find_citations(v, f"{path}[{i}]")


def check(doc: Any, root: Path) -> tuple[list[str], int]:
    """Returns (report lines, failure count)."""
    report: list[str] = []
    failures = 0
    for jpath, raw in find_citations(doc):
        try:
            cit = Citation.model_validate(raw)
        except ValidationError as e:
            failures += 1
            msgs = "; ".join(f"{'.'.join(map(str, err['loc']))}: {err['msg']}" for err in e.errors())
            report.append(f"FAIL {jpath}: malformed citation ({msgs})")
            continue
        err = verify_citation(cit, root)
        where = f"{cit.file}:{cit.line}" + (f"-{cit.end_line}" if cit.end_line else "")
        if err:
            failures += 1
            report.append(f"FAIL {jpath} {where}: {err}")
        else:
            report.append(f"OK   {jpath} {where}")
    return report, failures


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="prsec-cite", description="Verify file/line/quote citations against the repo.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    chk = sub.add_parser("check", help="verify every citation in a JSON document")
    chk.add_argument("file", type=Path)
    chk.add_argument("--root", type=Path, default=Path(os.environ.get("PRSEC_CITE_ROOT", DEFAULT_ROOT)))
    args = ap.parse_args(argv)

    try:
        doc = json.loads(args.file.read_text())
    except (OSError, ValueError) as e:
        print(f"prsec-cite: cannot read {args.file}: {e}", file=sys.stderr)
        return 2
    if not args.root.is_dir():
        print(f"prsec-cite: repo root {args.root} is not a directory", file=sys.stderr)
        return 2

    report, failures = check(doc, args.root)
    for line in report:
        print(line)
    total = len(report)
    if total == 0:
        print("no citations found (objects with file/line/quote)")
    print(f"{total - failures}/{total} citations verified")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

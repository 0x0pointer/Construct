"""Scripted stand-in for a harness CLI in the end-to-end pipeline test.

Installed as `<harness_root>/<adapter>/current/bin/<cli>`. Reads the prompt from stdin, works out
the stage from the output schema's title, replays a captured native stream, and writes a scripted
stage output for the `sqli-new-endpoint` eval case:

- H1 (`sql-injection`, an alias of sqli): the f-string query in search_orders -> confirmed, not refuted
- H2 (idor) on get_order: refuted by static_verify (the query binds user_id)
- H3: a hallucinated quote -> dropped by the deterministic citation check
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

STREAMS = {"claude": ("claude_code", "say_hi.jsonl"), "opencode": ("opencode", "run_tool_write.jsonl")}

SINK = {"file": "app.py", "line": 35, "end_line": 37,
        "quote": "f\"SELECT id, note, total FROM orders WHERE user_id = {g.user_id} AND note LIKE '%{q}%'\""}
SOURCE = {"file": "app.py", "line": 34, "quote": "q = request.args.get(\"q\", \"\")"}
GET_ORDER = {"file": "app.py", "line": 22, "end_line": 25,
             "quote": "\"SELECT id, note, total FROM orders WHERE id = ? AND user_id = ?\","}

HYPOTHESES = {
    "summary": "Adds GET /api/orders/search, which interpolates the q parameter into SQL.",
    "hypotheses": [
        {"id": "H1", "vuln_class": "technical", "bug_class": "sql-injection",
         "title": "SQL injection in order search", "description": "q is formatted into the SQL text.",
         "entry_point": "GET /api/orders/search", "source": SOURCE, "sink": SINK, "path": [],
         "assumed_guards": ["login_required"], "impact": "Read other users' orders.",
         "severity_guess": "high", "introduced_by_diff": True},
        {"id": "H2", "vuln_class": "technical", "bug_class": "idor",
         "title": "Order lookup by id", "description": "Possible missing ownership check.",
         "entry_point": "GET /api/orders/<id>", "sink": GET_ORDER, "impact": "Cross-user read.",
         "severity_guess": "medium", "introduced_by_diff": False},
        {"id": "H3", "vuln_class": "technical", "bug_class": "cmdi",
         "title": "Invented sink", "description": "Cites code that does not exist.",
         "entry_point": "GET /api/orders/search",
         "sink": {"file": "app.py", "line": 36, "quote": "this line is not in the file at all, honestly"},
         "impact": "n/a", "severity_guess": "high", "introduced_by_diff": True},
    ],
}


def stage_output(title: str, in_dir: Path | None) -> dict:
    hyp = json.loads((in_dir / "hypothesis.json").read_text()) if in_dir and (in_dir / "hypothesis.json").is_file() else {}
    if title == "TriageOutput":
        return {"decision": "full", "rationale": "New endpoint builds SQL from a query parameter.",
                "risk_tags": ["sqli"], "focus_files": ["app.py"]}
    if title == "HypothesesOutput":
        return HYPOTHESES
    if title == "StaticVerifyOutput":
        if hyp.get("id") == "H1":
            return {"hypothesis_id": "H1", "verdict": "confirmed_static", "reachable": "yes",
                    "reasoning": "Authenticated users reach the f-string query with an attacker-controlled q.",
                    "guards": [{"description": "login_required only authenticates", "effective": False}],
                    "citations": [SINK, SOURCE], "severity": "high",
                    "remediation": "Bind q as a parameter."}
        return {"hypothesis_id": hyp.get("id", "?"), "verdict": "refuted", "reachable": "yes",
                "reasoning": "The query binds both id and user_id.", "citations": [GET_ORDER], "severity": "info"}
    if title == "SkepticOutput":
        return {"hypothesis_id": hyp.get("id", "?"), "refuted": False, "confidence": "high",
                "reasoning": "The excerpt shows direct interpolation; no sanitiser applies."}
    raise SystemExit(f"unknown schema title {title!r}")


def main() -> int:
    cli, argv = sys.argv[1], sys.argv[2:]
    if argv == ["--version"]:
        print("9.9.9 (scripted)")
        return 0
    prompt = sys.stdin.read()
    out = re.search(r"JSON document to `([^`]+)`", prompt)
    schema = re.search(r"JSON Schema in `([^`]+)`", prompt)
    hyp = re.search(r"`([^`]+)/hypothesis\.json`", prompt)
    if not out or not schema:
        print("scripted harness: prompt lacks the output contract", file=sys.stderr)
        return 4
    for line in (Path(os.environ["PRSEC_E2E_FIXTURES"]) / STREAMS[cli][0] / STREAMS[cli][1]).read_text().splitlines():
        print(line, flush=True)
    title = json.loads(Path(schema.group(1)).read_text()).get("title", "")
    doc = stage_output(title, Path(hyp.group(1)) if hyp else None)
    Path(out.group(1)).write_text(json.dumps(doc))
    return 0


if __name__ == "__main__":
    sys.exit(main())

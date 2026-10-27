"""Findings -> SARIF 2.1.0."""
from __future__ import annotations

from importlib import metadata
from typing import Any
from urllib.parse import quote

from prsec.models import CodeLoc, Finding, PRInfo, Severity
from prsec.sarif.fingerprint import VERSION as FP_VERSION

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
SRCROOT = "SRCROOT"
_RESERVED_META = {"base_sha", "skills_version", "harnesses", "changed_files", "scan_id", "repo", "pr", "head_sha",
                  "complete", "errors"}

_LEVEL = {
    Severity.critical: "error",
    Severity.high: "error",
    Severity.medium: "warning",
    Severity.low: "note",
    Severity.info: "note",
}
# GitHub code scanning reads rule.properties["security-severity"] (CVSS-like 0-10).
_SECURITY_SEVERITY = {
    Severity.critical: 9.5,
    Severity.high: 8.0,
    Severity.medium: 5.5,
    Severity.low: 3.0,
    Severity.info: 0.0,
}


def tool_version() -> str:
    try:
        return metadata.version("prsec")
    except metadata.PackageNotFoundError:
        return "0.0.0"


def level_for(severity: Severity | str) -> str:
    return _LEVEL[Severity(severity)]


def _repo_uri(pr: PRInfo) -> str:
    if pr.scm == "github":
        return f"https://github.com/{pr.repo}"
    if pr.url and "/pull" in pr.url:
        return pr.url.split("/pull", 1)[0]
    return pr.url or f"urn:prsec:{pr.scm}:{pr.repo}"


def artifact_uri(path: str) -> str:
    """Repo path -> SARIF uri reference relative to SRCROOT (percent-encoded per segment)."""
    return quote(path.replace("\\", "/").lstrip("/"), safe="/")


def _location(loc: CodeLoc, message: str | None = None) -> dict[str, Any]:
    region: dict[str, Any] = {"startLine": max(loc.line, 1)}
    if loc.end_line and loc.end_line >= loc.line:
        region["endLine"] = loc.end_line
    if loc.snippet:
        region["snippet"] = {"text": loc.snippet}
    out: dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": {"uri": artifact_uri(loc.file), "uriBaseId": SRCROOT},
            "region": region,
        }
    }
    if message:
        out["message"] = {"text": message}
    return out


def _code_flow(f: Finding) -> dict[str, Any]:
    steps: list[tuple[CodeLoc, str, list[str]]] = []
    if f.source:
        steps.append((f.source, "source", ["source"]))
    steps.extend((p, f"step {i}", ["taint"]) for i, p in enumerate(f.path, 1))
    steps.append((f.sink, "sink", ["sink"]))
    return {
        "message": {"text": f.entry_point or f.title},
        "threadFlows": [
            {
                "locations": [
                    {"location": _location(loc, msg), "kinds": kinds, "executionOrder": i}
                    for i, (loc, msg, kinds) in enumerate(steps)
                ]
            }
        ],
    }


def _rule(bug_class: str, members: list[Finding]) -> dict[str, Any]:
    first = members[0]
    worst = max((Severity(m.severity) for m in members), key=lambda s: _SECURITY_SEVERITY[s])
    return {
        "id": bug_class,
        "name": "".join(p.capitalize() for p in bug_class.replace("_", "-").split("-")) or bug_class,
        "shortDescription": {"text": bug_class.replace("-", " ").replace("_", " ")},
        "fullDescription": {"text": f"PRSec {first.vuln_class.replace('_', ' ')} finding class '{bug_class}'"},
        "defaultConfiguration": {"level": level_for(worst)},
        "properties": {
            "vuln_class": first.vuln_class,
            "tags": ["security", first.vuln_class],
            "security-severity": f"{_SECURITY_SEVERITY[worst]:.1f}",
        },
    }


def _dynamic_summary(dyn: dict[str, Any] | None) -> dict[str, Any] | None:
    """Phase-2 summary of the stored DynamicEvidence; the full PoC and replays live at evidenceUri."""
    if not dyn:
        return None
    return {
        "outcome": dyn.get("outcome"),
        "reason": dyn.get("reason") or None,
        "entry": dyn.get("entry"),
        "head_runs": dyn.get("head_runs", 0),
        "head_fired": dyn.get("head_fired", 0),
        "base_fired": dyn.get("base_fired"),
        "evidenceUri": dyn.get("evidence_uri"),
    }


def _result(f: Finding, rule_index: int) -> dict[str, Any]:
    text = f.title if not f.description else f"{f.title}\n\n{f.description}"
    result: dict[str, Any] = {
        "ruleId": f.bug_class,
        "ruleIndex": rule_index,
        "level": level_for(f.severity),
        "message": {"text": text},
        "locations": [_location(f.sink)],
        "partialFingerprints": {FP_VERSION: f.fingerprint},
        "properties": {
            "label": str(f.label),
            "label_reason": f.label_reason,
            "severity": str(f.severity),
            "introduced": f.introduced,
            "entry_point": f.entry_point,
            "hypothesis_id": f.hypothesis_id,
            "evidenceUri": f.evidence_uri,
            "provenance": f.provenance,
            "guards": f.guards,
        },
    }
    if f.source or f.path:
        result["codeFlows"] = [_code_flow(f)]
    if f.remediation:
        # SARIF `fixes` require concrete artifactChanges; prose remediation goes in properties.
        result["properties"]["remediation"] = f.remediation
    dynamic = _dynamic_summary(f.dynamic)
    if dynamic:
        result["properties"]["dynamic"] = dynamic
    return result


def _invocation(run_meta: dict) -> dict[str, Any]:
    """run_meta["complete"] False (a required stage failed) means 'no results' is not 'no issues'."""
    ok = bool(run_meta.get("complete", True))
    inv: dict[str, Any] = {"executionSuccessful": ok}
    notes = [str(e) for e in run_meta.get("errors") or []]
    if notes:
        inv["toolExecutionNotifications"] = [{"level": "error", "message": {"text": t}} for t in notes]
    return inv


def build_sarif(pr: PRInfo, scan_id: int, findings: list[Finding], run_meta: dict) -> dict:
    by_class: dict[str, list[Finding]] = {}
    for f in findings:
        by_class.setdefault(f.bug_class, []).append(f)
    rule_ids = sorted(by_class)
    index = {rid: i for i, rid in enumerate(rule_ids)}

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "prsec",
                "version": tool_version(),
                "informationUri": "https://github.com/prsec/prsec",
                "rules": [_rule(rid, by_class[rid]) for rid in rule_ids],
            }
        },
        "originalUriBaseIds": {SRCROOT: {"description": {"text": f"{pr.repo}@{pr.head_sha}"}}},
        "versionControlProvenance": [
            {
                "repositoryUri": _repo_uri(pr),
                "revisionId": pr.head_sha,
                "branch": pr.head_ref,
                "mappedTo": {"uriBaseId": SRCROOT},
            }
        ],
        "invocations": [_invocation(run_meta)],
        "results": [_result(f, index[f.bug_class]) for f in findings],
        "properties": {
            "scan_id": scan_id,
            "repo": pr.repo,
            "pr": pr.number,
            "head_sha": pr.head_sha,
            "base_sha": run_meta.get("base_sha", pr.base_sha),
            "skills_version": run_meta.get("skills_version"),
            "harnesses": run_meta.get("harnesses", {}),
            **{k: v for k, v in run_meta.items() if k not in _RESERVED_META},
        },
    }
    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}


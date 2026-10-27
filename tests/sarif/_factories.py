from prsec.models import CodeLoc, Finding, PRInfo
from prsec.sarif.fingerprint import fingerprint


def pr(**kw) -> PRInfo:
    base = dict(repo="acme/shop", number=7, title="Add orders", base_ref="main", base_sha="b" * 40,
                head_ref="feat/orders", head_sha="a" * 40, changed_files=["app/orders.py"])
    return PRInfo(**{**base, **kw})


def finding(bug_class="sqli", severity="high", label="likely", sink_file="app/orders.py", symbol="find",
            entry="GET /orders/{id}", **kw) -> Finding:
    base = dict(
        fingerprint=fingerprint(bug_class, sink_file, symbol, entry),
        scan_id=1, repo="acme/shop", pr=7, head_sha="a" * 40, hypothesis_id="H1",
        vuln_class="technical", bug_class=bug_class, title=f"{bug_class} in {symbol}",
        description="User input reaches a query.", label=label, label_reason="static path confirmed",
        severity=severity, introduced=True, entry_point=entry,
        source=CodeLoc(file="app/api.py", line=10, snippet="oid = request.args['id']"),
        sink=CodeLoc(file=sink_file, line=42, end_line=43, snippet="cur.execute(f'... {oid}')"),
        path=[CodeLoc(file="app/svc.py", line=20)],
        guards=["none"], remediation="Use bound parameters.",
        provenance={"static_verify": {"harness": "claude-code", "model": "agent-large"}},
    )
    return Finding(**{**base, **kw})

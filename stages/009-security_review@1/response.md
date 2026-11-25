VERDICT: fail

BLOCKING FINDINGS: `prsec/dashboard/static/dashboard.js:149` — transient timeline poll failures permanently stop future polling.

# Security review

## Summary
- Findings: 0 security vulnerabilities; 1 blocking correctness finding; 0 non-blocking findings.
- The security-sensitive rendering paths still rely on Jinja autoescaping, the new client code fetches only same-origin URLs, and I did not find a reachable XSS/injection path from stored finding/event/triage data in the changed regions.
- The change does not fully preserve live timeline behavior: a transient poll failure stops future polling, violating the required retry edge case.

## Changed files, risk, and blast radius

| File | Risk | Blast radius |
| --- | --- | --- |
| `prsec/dashboard/main.py` | MEDIUM | Dashboard FastAPI app; new `/static` mount plus existing `/scans`, `/findings`, `/metrics` routes. External HTTP callers and tests. |
| `prsec/dashboard/static/dashboard.css` | LOW | Loaded by every page extending `base.html`; presentation only. |
| `prsec/dashboard/static/dashboard.js` | HIGH | Loaded by every dashboard page through `base.html`; controls async finding filters, triage partial POSTs, and scan timeline polling. |
| `prsec/dashboard/templates/_findings_table.html` | MEDIUM | `/findings` full page and `HX-Target: findings-table` partial responses; renders stored finding fields. |
| `prsec/dashboard/templates/_timeline_poller.html` | MEDIUM | `/scans/{id}` and `/scans/{id}/events`; controls live polling state. |
| `prsec/dashboard/templates/_triage.html` | MEDIUM | `/findings/{id}` and async triage save partials; renders/stores user triage text. |
| `prsec/dashboard/templates/base.html` | MEDIUM | Extended by 6 dashboard pages; replaces CDN HTMX with local assets. |
| `prsec/dashboard/templates/finding.html` | MEDIUM | `/findings/{id}`; renders stored finding, dynamic evidence, provenance, and occurrences. |
| `prsec/dashboard/templates/findings.html` | MEDIUM | `/findings`; filter form and partial-update target. |
| `prsec/dashboard/templates/metrics.html` | LOW | `/metrics`; presentation changes to aggregate tables. |
| `prsec/dashboard/templates/scan.html` | MEDIUM | `/scans/{id}`; renders scan metadata, agent runs, artifacts links, findings, and timeline. |
| `prsec/dashboard/templates/scans.html` | LOW | `/`; scan list presentation and filters. |
| `pyproject.toml` | MEDIUM | Package-data inclusion for static assets; affects installed dashboard availability. |
| `tests/dashboard/test_prsec_dashboard_routes.py` | LOW | Route/asset rendering tests only. |
| `tests/dashboard/test_prsec_dashboard_timeline.py` | LOW | Timeline server-rendering tests only. |

## Findings

### Blocking: transient timeline poll failures permanently stop polling

- File: `prsec/dashboard/static/dashboard.js:149`
- Impact: For a running scan, if `/scans/{id}/events` returns a transient non-2xx response or the fetch fails once, the `catch` block schedules `setupPoller(poller)` on the same poller. That poller already has `data-bound="true"`, so `setupPoller` immediately returns and no later poll is scheduled. The current timeline remains visible, but it never retries and never appends later events until the user manually reloads, violating the spec edge case "Poll network/server failure: Current timeline remains; retry later without clearing content or advancing cursor." This is not a security vulnerability, but it is a blocking behavior regression for live scan monitoring.
- Fix: In the failure path, schedule `pollTimeline(poller)` directly after the interval when the poller is still connected, or clear/reset the bound marker before re-entering `setupPoller`. Add a focused JS/browser test or equivalent unit test that forces one failed poll and verifies a subsequent retry is scheduled and uses the same cursor.

## Test coverage gaps

- No test executes `dashboard.js`; server tests verify attributes and partial HTML, but not the vanilla-JS behavior replacing HTMX.
- The required failure-retry edge case for timeline polling is untested and currently broken.
- Concurrent filter/triage request ordering, duplicate timeline row suppression in the browser, and same-origin URL refusal are not exercised by tests.
- Static assets are listed in package data, but I did not see a wheel/sdist build test proving they are included outside editable installs.

## Coverage limits

- I reviewed the full diff and traced changed dashboard routes/templates/client code only; I did not audit unrelated API, orchestrator, sandbox, or database code.
- I did not rerun the full test suite, per instruction. I used targeted code/history/caller inspection instead.
- I did not perform real-browser visual, accessibility, or mobile testing.
- For the HIGH-risk JavaScript, I modeled an authenticated dashboard user viewing malicious PR/agent/finding/event content. I checked the reachable path from database content through Jinja-rendered same-origin partials into `innerHTML`; because templates still autoescape text and the JS rejects cross-origin URLs and does not eval/import, I did not find a concrete XSS/exfiltration path in the changed regions.
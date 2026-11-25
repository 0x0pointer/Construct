Verdict: pass

Blocking findings: none

# Security review

## Summary
- Findings: 0 blocking, 1 non-blocking (test coverage only).
- Security result: I did not find a reachable XSS/injection, authorization, or business-logic regression in the changed dashboard templates. Jinja autoescaping remains in use, no `|safe`/inline event handlers/external asset URLs were added, and the removed HTMX CDN came from the original dashboard introduction commit (`e5013c8`), not a security fix.
- Spec result: 5/5 acceptance criteria appear met from the diff/code review.

## Changed files, risk, and blast radius

| File | Risk | Blast radius checked |
| --- | --- | --- |
| `prsec/dashboard/templates/base.html` | MEDIUM | Shared by 5 extending dashboard pages: `/`, `/scans/{id}`, `/findings`, `/findings/{id}`, `/metrics`. |
| `prsec/dashboard/templates/findings.html` | MEDIUM | 1 route (`GET /findings`), plus existing HX-compatible attributes. |
| `prsec/dashboard/templates/_findings_table.html` | MEDIUM | 2 references: full findings page include and HX partial from `GET /findings`. |
| `prsec/dashboard/templates/finding.html` | MEDIUM | 1 route (`GET /findings/{id}`) with untrusted finding/dynamic evidence text. |
| `prsec/dashboard/templates/_triage.html` | MEDIUM | 2 references: finding detail include and triage POST partial response. |
| `prsec/dashboard/templates/scan.html` | MEDIUM | 1 route (`GET /scans/{id}`) with scan/stage/finding/timeline data. |
| `prsec/dashboard/templates/scans.html` | MEDIUM | 1 route (`GET /`) with scan list/filter rendering. |
| `prsec/dashboard/templates/_timeline_poller.html` | LOW | 2 includes from timeline templates; copy/layout change only, server-built poll URL retained. |
| `prsec/dashboard/templates/metrics.html` | LOW | 1 route (`GET /metrics`); table/card wrappers around existing aggregate output. |
| `tests/dashboard/test_prsec_dashboard_routes.py` | LOW | Dashboard route regression tests. |

## Findings

### NB-1: External-asset regression test omits scan detail page
- Severity: non-blocking
- File/line: `tests/dashboard/test_prsec_dashboard_routes.py:80`
- The acceptance criteria name `/scans/{id}` as one of the pages that must not load external CSS/JS. The new regression test covers `/`, `/findings`, `/metrics`, and `/findings/{id}`, but not a seeded `/scans/{id}`. The current implementation appears covered indirectly by shared `base.html`, but the test would not catch a future scan-template-only external asset.
- Suggested fix: include a seeded scan detail path in `test_dashboard_pages_do_not_load_external_assets`.

## Test coverage gaps
- The external-asset test should include `/scans/{id}` as noted above.
- I did not find loosened checks in the brief. Existing route tests still cover filtering/HX partials, triage redirect/partial behavior, SARIF/evidence downloads, and escaping of hostile scan/finding/dynamic/timeline content.

## What I checked
- Read `/tmp/fabro/change.diff` in full and reviewed the approved spec/security considerations/review focus.
- Compared changed template regions against `origin/main`, checked blame/log history for the removed CDN script and noscript-only submit button, and searched changed templates for `|safe`, scripts, external URLs, inline event handlers, and `javascript:` URLs.
- Traced callers/blast radius through `prsec/dashboard/main.py` and template includes.

## Not covered
- I did not re-run the full dashboard test suite because the pipeline already did so and the review instructions asked not to repeat broad automated checks.
- I did not perform a pixel/manual browser review of visual quality, CSS browser compatibility, or narrow-screen rendering beyond reading the CSS/markup.
- I did not audit unchanged route/database/artifact-serving logic outside what the diff calls or relies on.
1. Intent
Restyle the FastAPI dashboard with a self-contained, modern visual system and local vanilla JavaScript. Remove the external HTMX CDN while preserving current behaviours: findings filtering, triage partial saves, live timeline polling, normal form/link fallbacks, and all displayed data. Prioritize `/findings` and `/findings/{id}` by making severity, status, evidence, code flow, triage, and occurrences easier to scan in a responsive layout.

2. Acceptance criteria
1. GET `/`, `/findings`, `/findings/{id}`, `/scans/{id}`, and `/metrics` renders only local `/static/dashboard.css` and `/static/dashboard.js`; no rendered CSS/JS asset references `http://`, `https://`, `htmx.org`, or `unpkg`.
2. `/findings` keeps filters, empty state, pagination, badges, repo/PR, sink, updated date, and finding links; filtering works as a normal GET without JS and as an in-place update with JS.
3. `/findings/{id}` shows a prominent summary plus description, label reasoning, optional remediation, code flow, guards, dynamic validation, triage, metadata, provenance, and occurrences; hostile finding/dynamic content remains escaped.
4. Triage save still works as the existing non-JS POST redirect and as an async same-page partial update.
5. `/scans/{id}` keeps triage, metadata, agents, timeline, stage runs, findings, SARIF links, and live polling/appending for running scans; polling stops when complete.
6. `/` and `/metrics` keep current filters, tables, pagination, rollups, formatting, empty states, and links.
7. No new Python, npm, CSS framework, font, icon, or JS-library dependency is added.

3. Boundaries
Always use existing `prsec.dashboard.main` FastAPI routes, `Jinja2Templates`, Jinja autoescaping, filters `usd`, `dur`, `pct`, `tojson_pretty`, `prsec.db.findings` helpers, and the existing async partial headers (`HX-Request`, `HX-Target`) for compatibility.
Never change database schema, API/orchestrator/sandbox code, SARIF/evidence storage, route URLs, auth assumptions, business logic, or artifact response types. Do not render artifacts as HTML.

4. Code map
- `prsec/dashboard/main.py`: mount `StaticFiles` for `prsec/dashboard/static`; keep route signatures and partial behaviour unchanged. Covered by dashboard route/timeline tests.
- `prsec/dashboard/static/dashboard.css` (new): responsive local styling for shell, nav, cards, filters, badges, tables, timeline, code blocks, finding detail, focus states, and mobile layouts.
- `prsec/dashboard/static/dashboard.js` (new): dependency-free progressive enhancement for GET filter forms/history, POST triage partials, timeline polling, OOB append/delete, duplicate timeline row suppression.
- `prsec/dashboard/templates/base.html`: remove external HTMX script; include local CSS/JS; keep nav/user/main structure.
- `prsec/dashboard/templates/findings.html`, `_findings_table.html`: add semantic classes/responsive table labels; preserve rows, filters, empty state, pagination, partial rendering.
- `prsec/dashboard/templates/finding.html`, `_triage.html`: reorganize into summary/cards; preserve all fields, links, forms, and escaping.
- `prsec/dashboard/templates/scans.html`, `scan.html`, `metrics.html`, `_timeline*.html`: apply shared styling/classes only; preserve data, links, polling attributes, and empty states.
- `pyproject.toml`: include `dashboard/static/*` in `tool.setuptools.package-data`.
- Tests to update/add: `tests/dashboard/test_prsec_dashboard_routes.py`, `tests/dashboard/test_prsec_dashboard_dynamic.py`, `tests/dashboard/test_prsec_dashboard_timeline.py`.

5. Edge cases
| Case | Expected behaviour |
| --- | --- |
| Empty scans/findings/metrics/timeline | Existing empty messages remain visible. |
| Malformed/missing query params or `page < 1` | Existing route normalization applies; pages and JS do not crash. |
| Oversized paths/snippets/titles/event data or hostile HTML | Text wraps or scrolls; Jinja escaping and `_kv` truncation remain effective. |
| Duplicate timeline events from retry/backlog | Client append skips already-present `data-id` rows. |
| Concurrent filter or triage submits | Latest completed same-target response replaces that target; non-JS fallback remains correct. |
| JS disabled/static JS fails | Links, GET filters, POST redirect, pagination, and manual scan reload work. |
| Poll network/server failure | Current timeline remains; retry later without clearing content or advancing cursor. |

6. Security considerations
Untrusted PR, agent, finding, dynamic, event, and triage text enters templates from the database. Keep it in escaped Jinja text contexts; do not add `|safe`. New JS may insert same-origin HTML partials returned by existing dashboard endpoints only; it must not eval code, fetch off-site URLs, or build off-site URLs from untrusted text. Removing the CDN reduces supply-chain risk. Auth/SSO assumptions are unchanged. Artifact routes must remain `text/plain` with `nosniff`.

7. Test plan
- Update `tests/dashboard/test_prsec_dashboard_routes.py::test_scans_list`: assert local CSS/JS links and existing scan/filter/formatting output; remove HTMX CDN assertion.
- Add `tests/dashboard/test_prsec_dashboard_routes.py::test_dashboard_assets_are_local_and_served`: representative pages contain no external CSS/JS or `htmx.org`/`unpkg`; `/static/dashboard.css` and `/static/dashboard.js` return 200 with correct content types.
- Update `tests/dashboard/test_prsec_dashboard_routes.py::test_findings_filters`: full and async filtered responses keep rows, empty state, pagination, enhancement hooks, and partials omit `<html`.
- Update `tests/dashboard/test_prsec_dashboard_routes.py::test_finding_detail_and_triage`: restyled summary/critical sections render; hostile snippets remain escaped; async triage partial and non-JS redirect still work.
- Keep/update `tests/dashboard/test_prsec_dashboard_dynamic.py::test_finding_page_dynamic_section_is_escaped`: dynamic evidence remains escaped in the restyled page.
- Keep/update `tests/dashboard/test_prsec_dashboard_timeline.py::{test_scan_page_polls_while_running,test_poll_returns_only_new_events_out_of_band,test_poll_stops_when_scan_finished}`: polling cursor, groups, OOB appends, and stop behaviour remain observable.
- Add `tests/dashboard/test_prsec_dashboard_routes.py::test_dashboard_static_js_has_no_external_dependency_bootstrap`: local JS contains no `import`, `eval`, `new Function`, `http://`, or `https://`.
- Existing dashboard route, dynamic, timeline, SARIF, local redirect, and run binding tests must keep passing.
Tests required: yes

8. Review focus
1. Real-browser visual hierarchy of the critical finding detail page.
2. Mobile layout and long-code overflow.
3. Vanilla JS parity with previous HTMX timeline/triage/filter behaviour.
4. Accessibility: focus, labels, contrast, heading order.
5. Static asset inclusion in built wheels/sdists, not only editable installs.

9. Assumptions
- “No external dependencies” means no CDN/framework/library assets and no new package dependencies; local vanilla JS is allowed to preserve dynamic behaviour.
- “Every browser” means progressive enhancement for current evergreen browsers plus functional no-JS fallbacks; legacy browsers may get simpler presentation but usable HTML/forms.
- The dashboard remains an internal SSO-protected read-mostly app; this change does not add CSRF or authorization controls.

10. Suspicious content
none

Size: standard
Risk level: medium
Reason: this touches all dashboard pages rendering untrusted data and replaces client-side update behaviour, so mistakes could introduce XSS regressions or break live triage/timeline workflows.
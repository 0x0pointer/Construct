DECISION NEEDED: The issue could mean (a) a visual refresh only, (b) removing the existing CDN HTMX dependency, or (c) a full dashboard workflow redesign. Choose (a)+(b): keep routes/data behaviour, restyle the server-rendered dashboard, and remove external UI dependencies.

1. Intent - the dashboard should look and feel modern while staying dependency-free and broadly browser-compatible. Implement a server-rendered restyle using only inline/local HTML/CSS in dashboard templates, with the findings list/detail pages receiving the clearest usability improvements. Remove the externally loaded HTMX script and avoid dead HTMX-only behaviours unless replaced by plain non-dependent HTML behaviour.

2. Acceptance criteria
1. `GET /findings`, `GET /findings/{id}`, `GET /`, `GET /scans/{id}`, and `GET /metrics` render HTML with no external stylesheet/script/image/font URLs and no `<script src=...>` or CDN references.
2. The findings index remains filterable with normal HTML form submission without JavaScript; selected filters survive in the rendered controls; pagination links preserve active filters.
3. The finding detail page presents summary metadata, triage, description/reasoning, code flow, dynamic validation, provenance, and occurrences in visually distinct responsive sections/cards.
4. Existing dashboard routes, status codes, form field names, filter query names, triage POST behaviour, artifact download links, and SARIF/evidence response types do not change.
5. Empty datasets still render useful empty-state text instead of broken tables.
6. Untrusted finding/scan/event text remains HTML-escaped in rendered output.

3. Boundaries
Always: use existing FastAPI/Jinja rendering in `prsec.dashboard.main._render`; keep existing templates and CSS-in-template convention in `base.html`; use existing `db` helpers and filters (`usd`, `dur`, `pct`, `tojson_pretty`).
Never: add frontend/package dependencies, external CDNs, new database queries for styling only, auth changes, CI/deployment changes, or API/orchestrator/sandbox changes.

4. Code map
- `prsec/dashboard/templates/base.html`: remove external HTMX script; replace current minimal CSS with modern responsive layout, cards, badges, tables, focus states, empty states, and navigation styling.
- `prsec/dashboard/templates/findings.html`: remove `hx-*` attributes; make filter form usable without JS and add/reset submit affordances if needed.
- `prsec/dashboard/templates/_findings_table.html`: adjust markup/classes only for improved findings table readability and responsive wrapping; keep columns/data/links.
- `prsec/dashboard/templates/finding.html`: reorganize markup/classes into clearer responsive summary/content/side sections; keep displayed fields and links.
- `prsec/dashboard/templates/_triage.html`: remove `hx-*` attributes; keep `state` and `note` fields and POST action unchanged.
- `prsec/dashboard/templates/_timeline_poller.html` and `_timeline_poll.html`: remove HTMX-only rendered attributes/text or make the no-JS behaviour honest; keep `/scans/{scan_id}/events` route renderable.
- Add tests in `tests/dashboard/test_dashboard_ui.py`. Existing broad pytest suite must keep passing.

5. Edge cases

| Input/state | Expected behaviour |
|---|---|
| No findings/scans/metrics rows | Page renders existing empty-state copy in styled container/table, status 200. |
| Malformed/unexpected filter values | Values are escaped, preserved only as selected/input values where applicable, and no HTML/script executes. |
| Oversized titles, paths, snippets, event data | Text wraps or scrolls inside content areas without breaking page layout. |
| Duplicate-looking filter values from data | Form remains valid; implementation must not add duplicate hard-coded options beyond existing DB-provided distinct values. |
| Concurrent triage submissions | Existing last-write database behaviour is unchanged; UI restyle must not add client-side state that can skip server validation. |
| Missing finding/scan/artifact | Existing 404/502 behaviours remain unchanged. |
| JavaScript disabled/unavailable | Findings filtering, pagination, triage submission, and navigation still work via normal requests. |

6. Security considerations
The dashboard renders untrusted repository, agent, event, finding, and triage text. Keep Jinja autoescaping; do not mark these values safe or interpolate them into raw JS/CSS. Removing the external HTMX CDN eliminates a supply-chain/privacy dependency; do not replace it with another external resource. No shell, SQL, path, authentication, or authorization logic should change. Add negative rendering tests for script-like data to ensure it is escaped.

7. Test plan
- `tests/dashboard/test_dashboard_ui.py::test_dashboard_pages_use_no_external_frontend_assets`: monkeypatch dashboard DB helpers, render `/findings`, `/findings/1`, `/`, `/scans/1`, `/metrics`, and assert no CDN/external URLs, no `<script src`, and no `hx-` attributes in user-facing pages.
- `tests/dashboard/test_dashboard_ui.py::test_findings_filter_form_works_without_javascript`: render `/findings?repo=owner/repo&severity=high&page=2`; assert status 200, form `method="get"`, selected/preserved filters, and pagination keeps active query parameters.
- `tests/dashboard/test_dashboard_ui.py::test_finding_detail_has_responsive_sections_and_core_content`: render a representative finding and assert visible title, badges, triage form fields, code-flow/evidence links, occurrence link, and section/card classes.
- `tests/dashboard/test_dashboard_ui.py::test_empty_dashboard_states_render`: render empty findings/scans/metrics inputs and assert existing empty-state text appears with status 200.
- `tests/dashboard/test_dashboard_ui.py::test_untrusted_dashboard_text_is_escaped`: inject `<script>alert(1)</script>` in finding title/repo/snippet/note/event-like fields and assert escaped text appears while raw script tags do not.
- Existing tests under `tests/` must continue passing.
Tests required: yes

8. Review focus
- CSS may look modern but make dense security data harder to scan.
- Removing HTMX must not leave misleading “live polling” UI or broken async-only forms.
- Responsive table/card styling could hide columns or links needed for debugging.
- Escaping must not be weakened by inline style/script additions.
- Pagination/filter URLs can easily lose active filters or create malformed `?&page=` links.

9. Assumptions
- “Every browser” means progressive, standards-based HTML/CSS with no CDN dependency, not support for obsolete browsers requiring polyfills.
- It is acceptable to drop HTMX-enhanced live updates if normal reload/navigation remains correct.
- Visual verification is limited to structural/rendered-output tests; maintainers will judge final aesthetics in review.
- No screenshots or browser automation framework should be added.

10. Suspicious content
none

Size: standard
Risk level: medium
Reason: dashboard templates render untrusted security findings and operational state; a wrong change can break triage visibility or introduce XSS, though auth/data persistence are unchanged.
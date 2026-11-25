DECISION NEEDED: “restyled” could mean full redesign, CSS-only facelift, or responsive first-party refresh. Chosen: responsive first-party refresh that keeps routes and live behaviours; CSS-only would lose live updates, full redesign is out of scope.

1. Intent
Modernize the existing FastAPI/Jinja dashboard without changing stored data, route URLs, or workflows. Move styling and progressive-enhancement code to first-party static assets, remove the external HTMX CDN, and preserve findings filtering, triage save, and scan timeline polling. Prioritize `/findings` and `/findings/{id}` for responsive layout, clearer hierarchy, readable badges/cards/tables, and safe wrapping of long code and agent text.

2. Acceptance criteria
1. GET `/findings` renders a modern responsive page with header/nav, filters, findings table, pager, and empty state usable at desktop and phone widths; only tables/code blocks may scroll horizontally.
2. GET `/findings/{id}` shows title, severity/label/status, triage controls, description, code flow, dynamic validation, provenance, and occurrences in a responsive layout that collapses to one column and wraps long text.
3. GET `/`, `/scans/{id}`, and `/metrics` retain current visible data, links, empty states, paging, and timeline status while using the same visual system.
4. Rendered dashboard pages load no external CSS/JS: no CDN scripts/styles; only first-party `/static/dashboard.css` and `/static/dashboard.js`.
5. With JS enabled: findings filter changes update `#findings-table` and URL; triage submit updates `#triage-panel`; live scan timelines append events every 2s without reload.
6. With JS disabled/failed: filter forms submit normally, triage POST redirects back to the finding, and scan pages remain readable with reload/status text.
7. Existing non-UI behaviours remain: `/healthz`, SARIF download, transcript/evidence `text/plain` plus `nosniff`, missing scan/finding 404s, and unknown triage state 422.

3. Boundaries
Always use `prsec.dashboard.main.app`, `TEMPLATES`, `_render`, existing `prsec.db.findings` helpers, Jinja autoescaping, existing form actions, and package-data conventions in `pyproject.toml`.
Never add runtime dependencies, CDN assets, build steps, DB schema/query changes, auth changes, CI/deploy edits, or changes outside `prsec/dashboard`, `pyproject.toml`, and dashboard tests.

4. Code map
- `pyproject.toml` `[tool.setuptools.package-data]`: include dashboard static CSS/JS.
- `prsec/dashboard/main.py` `app`: mount `/static` with `StaticFiles`; support first-party partial-request headers for `/findings` and triage while preserving HTMX header compatibility.
- Add `prsec/dashboard/static/dashboard.css`: responsive theme, cards, badges, forms, tables, timeline, finding detail layout.
- Add `prsec/dashboard/static/dashboard.js`: vanilla progressive enhancement for filters, triage, timeline polling; no imports/eval.
- `prsec/dashboard/templates/base.html`: remove HTMX CDN, load local assets, modernize semantic shell.
- `findings.html`, `_findings_table.html`, `finding.html`, `_triage.html`: replace HTMX attrs with data attrs/fallback actions; add responsive wrappers/classes; prioritize finding detail.
- `scans.html`, `scan.html`, `_timeline*.html`, `metrics.html`: apply shared wrappers/classes and timeline data attrs; keep content/links.
- Existing tests: none. Add `tests/dashboard/test_dashboard_ui.py`.

5. Edge cases
| Case | Expected behaviour |
| --- | --- |
| Empty scans/findings/stage runs/metrics | Empty messages render in styled containers; JS does not throw. |
| Malformed/unknown filter values | Values are escaped, URL-encoded, passed to existing filters, and show no matches if DB returns none. |
| Oversized titles, paths, snippets, notes, event data | Text wraps or scrolls inside card/table/pre; no page-wide overflow or unescaped HTML. |
| Duplicate timeline poll response/retry | Event IDs already present in the DOM are not appended again. |
| Concurrent triage edits | Panel reflects the server response for the submitted POST; no optimistic client state overrides it. |
| Static asset/JS failure | Links/forms still work by full-page requests; timeline can be manually reloaded. |

6. Security considerations
Dashboard data includes untrusted repository, PR, agent, finding, note, snippet, and event text from DB/object storage. Keep Jinja autoescape; do not add `|safe`, eval, shell/SQL/path handling, remote scripts, or DOM insertion from raw user input. First-party JS may insert only same-origin server-rendered fragments. `StaticFiles` must be confined to `prsec/dashboard/static`. Auth remains delegated to the SSO proxy; do not weaken it. Triage remains an existing POST side effect, so keep server-side state validation.

7. Test plan
Add `tests/dashboard/test_dashboard_ui.py` using `TestClient` and monkeypatched `prsec.dashboard.main.db`/`obs_events`:
- `test_dashboard_assets_are_first_party_and_packaged`: `/findings` references only local CSS/JS, static URLs return 200, no `http://`, `https://`, `unpkg`, or `htmx` asset references.
- `test_findings_page_responsive_filters_table_empty_and_partial`: populated and empty `/findings` render filters/table wrapper/pager/empty state; first-party partial headers return only table fragment and selected filters persist.
- `test_finding_detail_prioritizes_content_and_escapes_untrusted_text`: required sections/classes and fallback triage form render; malicious title/snippet/note such as `<script>` is escaped.
- `test_scans_scan_metrics_keep_existing_visible_behaviour`: `/`, `/scans/{id}`, `/metrics` render current headings, data, links, empty states, and timeline poll metadata.
- `test_triage_progressive_enhancement_and_validation`: normal POST redirects, partial POST returns updated panel with saved marker, unknown state is 422, missing finding is 404.
- `test_artifact_security_headers_unchanged`: transcript/evidence endpoints still return `text/plain` with `nosniff`.
- `test_timeline_poll_fragment_is_safe_and_deduplicatable`: poll response contains replace/append targets and event IDs, escapes event data, and supports client duplicate skipping.
Existing full suite must keep passing, especially `tests/sinks/*` and `tests/orchestrator/*`.
Tests required: yes

8. Review focus
- Real browser visual quality, contrast, keyboard focus, and mobile usability.
- Whether HTMX replacement fully preserves grouped live timeline appends.
- Wheel/sdist packaging of static files, not just editable install.
- Any unsafe fragment insertion or accidental unescaped HTML.
- Whether finding detail surfaces operator-critical information first.

9. Assumptions
- “Every browser” means current evergreen desktop/mobile browsers plus graceful fallback when JS fails; no legacy polyfill dependency.
- “No external dependencies” allows first-party CSS/JS served by the app, but forbids CDN/npm/bundled third-party libraries.
- Existing information architecture and routes are acceptable; the issue asks for restyling, not new workflow features.

10. Suspicious content
none

Size: standard
Risk level: medium
Reason: The change touches authenticated dashboard rendering of untrusted PR/agent data and replaces live client-side behaviour, so mistakes could cause XSS or operational regressions even though scanning is unchanged.
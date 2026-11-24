1. Summary
Restyle the PRSec/Construct dashboard so it is modern, readable, responsive, and self-contained. The finding detail page is the priority and must be reorganized around clear security-review sections without losing any existing data. Remove the remote HTMX CDN dependency and do not load styling, fonts, icons, JavaScript, or other assets from any remote/third-party online source.

2. Acceptance criteria
1. The full dashboard pages `/`, `/findings`, `/findings/{id}`, `/scans/{id}`, and `/metrics` render with a shared modern shell: branded top navigation, readable max-width content, page headers, card/panel sections, styled badges, styled forms, wrapped/scrollable tables, visible keyboard focus states, dark-mode CSS variables, and responsive layout below narrow widths.
2. `/findings/{id}` is substantially reorganized for readability: a hero/header with title and key badges; a responsive main/aside layout; distinct card sections for description, label reasoning, remediation, code flow, guards, dynamic validation, triage, provenance, metadata, and occurrences; and every value/link currently rendered by `finding.html` remains present when available.
3. Findings and scans filters keep working as plain GET forms with visible submit buttons. Existing query parameters still filter results, no-match results render a clear empty state, pagination remains usable, and the `/findings` partial response still works when requested with the existing `HX-Request`/`HX-Target` headers.
4. Triage, timeline, evidence/transcript, SARIF, metrics, scan detail, and health routes keep their server-side behavior. Triage POST still validates state server-side, redirects on normal POST, returns only the triage partial for HX requests, and returns 404/422 as today. Timeline event partials keep cursor behavior and append/swap hints for progressive enhancement.
5. No rendered dashboard template loads remote assets. Dashboard templates must not contain remote `<script src>`, `<link href>`, web font, icon, or stylesheet references such as `http://`, `https://`, `unpkg.com`, or `htmx.org`; `pyproject.toml` dependencies must not change for this restyle. If a frontend library is used, it must be bundled locally in this repository, served same-origin by the dashboard, pinned to a specific version in a comment or filename, and must not load additional remote assets.
6. Core dashboard use works without JavaScript: navigation uses links, filtering uses GET forms, triage uses POST forms, downloads use ordinary links, and scan/timeline pages remain meaningful. Any async behavior must be progressive enhancement using either small first-party vanilla JavaScript or a locally bundled same-origin frontend library; if it fails, the plain HTML path still works.
7. Escaping and trust boundaries are preserved. No dashboard template may introduce `|safe`, inline event-handler attributes, `javascript:` URLs, `eval`, `new Function`, or JavaScript interpolation of user-, agent-, PR-, header-, database-, or artifact-derived values into executable code.
8. Existing dashboard tests continue to pass after intentional assertion updates for the removed remote HTMX script, and new tests cover the restyled shell, finding detail layout, no-remote-asset rule, no-JavaScript fallbacks, empty states, optional/missing data, long values, and XSS regressions.

3. Scope
Files to change or add:
- `prsec/dashboard/templates/base.html`
- `prsec/dashboard/templates/finding.html`
- `prsec/dashboard/templates/findings.html`
- `prsec/dashboard/templates/_findings_table.html`
- `prsec/dashboard/templates/scans.html`
- `prsec/dashboard/templates/scan.html`
- `prsec/dashboard/templates/metrics.html`
- `prsec/dashboard/templates/_triage.html`
- `prsec/dashboard/templates/_timeline.html`, `_timeline_poller.html`, `_timeline_poll.html`, and `_timeline_macros.html` only as needed to replace remote-HTMX assumptions with same-origin progressive-enhancement hooks while preserving partial route behavior
- `prsec/dashboard/main.py` only if needed to serve locally bundled dashboard static assets
- `prsec/dashboard/static/**` only if a small local frontend library or local dashboard JS/CSS file is used
- `tests/dashboard/test_prsec_dashboard_routes.py`
- `tests/dashboard/test_prsec_dashboard_timeline.py`
- Add `tests/dashboard/test_prsec_dashboard_templates.py`

Out of scope:
- Database schema, database query semantics, and seed data changes except temporary test setup data
- API, worker, orchestrator, runner, dynamic validation, SARIF generation, skills, policy, and queue logic
- Authentication/authorization model changes
- CI, deployment, Helm, compose, Docker, and workflow changes
- Adding frontend package managers, build steps, remote external fonts/icons/images/scripts/styles, or new Python/project dependencies
- Large frontend frameworks or broad static asset pipelines. A small vendored frontend library is allowed only if it is committed locally, served same-origin, version-pinned, and simpler than reimplementing the needed progressive behavior.
- Broad refactors, route renames, or unrelated template/content changes

4. Design
Use the existing FastAPI + Jinja2 dashboard architecture and keep the UI self-contained. Prefer putting shared CSS and small progressive-enhancement JavaScript in `base.html`; if using a local bundled frontend library or local dashboard JS/CSS file, serve it from a dashboard-owned same-origin static path and keep the integration minimal. Do not introduce a package-manager or build-based asset pipeline. Build a simple design system from existing concepts (`panel`, `badge`, `grid2`, `kv`, `muted`, severity/status/triage classes) and extend it with clear dashboard classes such as a shell/topnav, page header, card, table wrapper, responsive grid, metadata list, flow list, empty state, and screen-reader/focus utilities.

Prioritize `finding.html`. Keep the same context variables (`f`, `data`, `flow`, `dyn`, `triage_states`) and all current links to scans, triage, evidence, dynamic evidence, transcripts, SARIF, and occurrences. Move presentation into semantic sections rather than inline styles where practical. Long text/code should wrap or scroll within cards/tables rather than expanding the page horizontally.

Remove the remote HTMX `<script>` from `base.html`. Forms and links must be correct without JavaScript first. If retaining async filters, triage partial replacement, or timeline polling in the browser, implement minimal progressive enhancement using either vanilla JavaScript or a locally bundled same-origin library. The enhancement must attach to explicit attributes/hooks, request only same-origin routes, send the existing HX compatibility headers only when requesting existing partial routes, update only known target elements, and handle failures by leaving the normal form/link path available. Do not use `eval`, dynamic script creation from remote URLs, inline event attributes, or untrusted values inside JavaScript templates.

5. Code quality requirements
- Follow the style and naming conventions of the surrounding Jinja templates and dashboard tests.
- Keep changes focused on dashboard presentation and progressive enhancement; do not refactor unrelated Python logic.
- Use existing partials (`_findings_table.html`, `_triage.html`, `_timeline*.html`) instead of duplicating large blocks.
- Use clear class and `data-*` names tied to dashboard concepts; remove obsolete remote-HTMX assumptions if they are replaced.
- Avoid dead CSS/JS, unused template fragments, speculative abstractions, and broad renames.
- Preserve route paths, form field names, query parameter names, table data, links, status/severity/triage values, and error behavior.
- Keep error handling and validation at the current Python route layer; templates must not hide 404/422 responses or client-side-bypass server validation.

6. Security considerations
Untrusted input rendered by these templates includes PR metadata, repository names, scan/finding data, agent outputs, SARIF-derived fields, code snippets, event messages/data, triage notes, request forwarded-user headers, filter query values, and artifact metadata. The change must preserve Jinja autoescaping and must not add `|safe`, inline event handlers, string-to-code execution, or JavaScript that converts untrusted values into executable HTML/script. Removing the remote HTMX CDN reduces third-party script supply-chain exposure. Any first-party JavaScript or locally bundled library integration must only request same-origin dashboard routes, update predetermined DOM targets, not make authorization decisions, not load additional remote code/assets, and degrade to normal full-page forms/links on failure. Authentication remains external behind the SSO proxy and must not be changed. Triage state changes must continue to depend on the existing POST route and server-side validation. Evidence and transcript responses must remain `text/plain` with `X-Content-Type-Options: nosniff`.

7. Edge cases
- Empty data: no scans, no findings, no matching filter results, no stage runs, no timeline events, no guards, no dynamic validation, no replay runs, no occurrences.
- Malformed or unexpected display values: missing optional fields, unknown severity/status/label/triage values, absent source/path/sink details, missing timestamps, missing costs, and missing artifact URIs.
- Oversized content: long titles, repository names, file paths, fingerprints, snippets, event messages, JSON/provenance, app logs, triage notes, filter values, and user headers must wrap or scroll without breaking layout.
- Duplicate/repeated content: repeated findings, repeated timeline groups, repeated badges, repeated filter values, and repeated partial updates must not create invalid IDs or unreadable output.
- Concurrent/state-changing input: multiple triage submissions must still be resolved by the existing server route; client-side enhancement must not bypass validation or force state out of order.
- Failure/no-enhancement modes: JavaScript disabled, fetch failure, partial endpoint error, blocked script, or stale timeline cursor must leave filtering, triage, navigation, and reloads usable through ordinary page loads.
- Security edge cases: malicious HTML/JS in finding titles/descriptions/snippets/events/triage notes/forwarded-user headers must render escaped; remote asset URLs must not be loaded from templates.

8. Test plan
Unit tests:
- Add `tests/dashboard/test_prsec_dashboard_templates.py::test_dashboard_templates_do_not_load_remote_assets`: read `prsec/dashboard/templates/*.html` and any dashboard static files added for this issue; assert there are no remote script/link/font/icon/stylesheet references (`http://`, `https://`, `unpkg.com`, `htmx.org`) in asset-loading contexts and no locally bundled library tries to load additional remote assets.
- Add `tests/dashboard/test_prsec_dashboard_templates.py::test_dashboard_templates_do_not_introduce_unsafe_rendering_hooks`: assert dashboard templates do not contain `|safe`, inline `on...=` event handlers, `javascript:` URLs, `eval(`, or `new Function`.
- Add `tests/dashboard/test_prsec_dashboard_templates.py::test_base_template_defines_self_contained_responsive_design`: assert `base.html` includes the shared shell/topnav/card/table/form/badge/focus/dark-mode/responsive CSS tokens and no remote script tag.

Integration tests:
- Update `tests/dashboard/test_prsec_dashboard_routes.py::test_scans_list`: remove the `htmx.org@2.0.4` expectation; assert the scans page renders the shared shell/navigation, visible GET filters, restyled table/card markup, seeded scan data, cost, duration, and filtered results.
- Add `tests/dashboard/test_prsec_dashboard_routes.py::test_dashboard_pages_share_restyled_shell`: request `/`, `/findings`, `/metrics`, and `/scans/{scan_id}`; assert status 200, shared shell/topnav/main classes are present, no remote asset strings are present, and key page-specific content still appears.
- Update `tests/dashboard/test_prsec_dashboard_routes.py::test_findings_filters` or add `test_findings_filters_remain_plain_get_and_partial_compatible`: assert `/findings` has a visible submit button, selected query filters limit rows, no-match filters show the empty state, pager links remain local, and an HX partial request still returns only the findings table without a full `<html>` document.
- Add `tests/dashboard/test_prsec_dashboard_routes.py::test_finding_detail_restyled_layout_preserves_sections`: request a seeded finding and assert the hero/layout/card classes are present and title, severity, label, status, repo/PR, description, label reasoning, remediation when present, code flow, guards, dynamic validation when present, triage, fingerprint, provenance, evidence links, scan links, and occurrences remain visible.
- Keep `tests/dashboard/test_prsec_dashboard_routes.py::test_finding_detail_and_triage` passing with updated markup assertions as needed: HX triage partial still works, normal POST redirects to `/findings/{id}`, invalid state returns 422, and missing finding returns 404.
- Keep `tests/dashboard/test_prsec_dashboard_routes.py::test_transcript_and_evidence_routes`, `test_metrics_page`, `test_sarif_download`, `test_local_path_refuses_off_site_redirects`, and `test_run_binds_loopback_unless_configured` passing.
- Update `tests/dashboard/test_prsec_dashboard_timeline.py::test_scan_page_polls_while_running` to assert the running scan page exposes first-party poll metadata/hooks and no remote HTMX script; keep asserting the poll URL cursor includes the latest event and known groups.
- Keep/update `tests/dashboard/test_prsec_dashboard_timeline.py::test_finished_scan_does_not_poll`, `test_poll_returns_only_new_events_out_of_band`, `test_poll_without_new_events_keeps_cursor`, `test_poll_stops_when_scan_finished`, `test_poll_continues_while_backlog_is_full`, and `test_scan_page_renders_timeline_escaped` so they still prove escaped rendering, cursor behavior, completion behavior, and partial append/swap behavior after any markup rename.

Regression tests:
- Add `tests/dashboard/test_prsec_dashboard_routes.py::test_dashboard_restyle_escapes_untrusted_finding_and_scan_content`: insert or patch a finding, scan event, triage note, and forwarded user header containing `<script>`, HTML attributes, and `javascript:` text; assert raw executable markup/attributes do not appear and escaped text appears on finding and scan pages.
- Add `tests/dashboard/test_prsec_dashboard_routes.py::test_finding_detail_handles_missing_optional_sections`: render a finding with no remediation, guards, dynamic validation, source/path details, occurrences beyond the current row, or evidence URI; assert 200, meaningful fallback/empty text, and no broken evidence/dynamic-evidence links.
- Add `tests/dashboard/test_prsec_dashboard_routes.py::test_long_dashboard_values_use_wrapping_layout`: render or patch long title, repo, file path, fingerprint, snippet, provenance, app log, and triage-note values; assert the values are present inside expected wrapping/scrolling elements/classes such as cards, table wrappers, `code`, `pre`, or flow items.
- Add or update a no-JavaScript fallback assertion in the route tests: forms have normal `method`/`action`, submit buttons are not inside `<noscript>`, and links/downloads are ordinary anchors.
Tests required: yes

9. Risks
- Visual quality is partly subjective; tests should verify structure, preserved content, and dependency/security rules rather than exact appearance.
- Removing the remote HTMX library can regress async filtering, triage partial updates, or timeline polling if the first-party enhancement or plain fallbacks are incomplete.
- Template restructuring can accidentally drop fields, links, empty states, escaping, or artifact download protections.
- Larger CSS changes can introduce mobile overflow, poor contrast, or unreadable long security-scan content.
- Static template tests can be brittle if they over-match non-asset text; keep them scoped to asset-loading and unsafe-rendering patterns.

10. Suspicious content
none

Risk level: medium
Reason: The change is mostly presentation, but it touches all dashboard templates that render untrusted security-scan data and removes/replaces a third-party JavaScript dependency used by existing progressive UI behavior.
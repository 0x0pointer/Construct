1. Summary
Restyle the PRSec/Construct dashboard to look more modern, readable, and responsive while staying self-contained. The finding detail page is the priority: it should present severity/status metadata, vulnerability narrative, code flow, validation evidence, triage, provenance, and occurrences in a clearer card-based layout. Remove the current remote HTMX CDN dependency and do not add any external CSS/JS/font/icon dependencies; keep dashboard behavior available through ordinary HTML forms and existing server routes.

2. Acceptance criteria
1. Full dashboard pages `/`, `/findings`, `/findings/{id}`, `/scans/{id}`, and `/metrics` render with a shared modern shell: prominent top navigation, constrained readable content width, card/panel styling, improved table/form/badge styling, dark-mode variables, visible keyboard focus states, and responsive behavior for narrow screens.
2. The finding detail page is substantially reorganized for readability: a hero/header area with title and key badges, a primary/secondary responsive layout, distinct sections for description, label reasoning, remediation, code flow, guards, dynamic validation, triage, provenance, and occurrences, and no loss of any data currently displayed.
3. The findings list remains usable and readable: filters still submit with plain GET, the submit control is visible without relying on `<noscript>`, existing filter query parameters still work, the HX partial response for the findings table still works if requested, and empty result sets still show a clear empty state.
4. Existing scan, metrics, timeline, transcript, evidence, SARIF, and triage routes keep their current server-side behavior and data. Current timeline polling and triage partial endpoints must not be removed; if asynchronous enhancement is kept, it must use only first-party vanilla JavaScript or existing server-rendered fragments, never a third-party library.
5. No rendered dashboard template loads remote assets. In `prsec/dashboard/templates/*.html`, there must be no `http://` or `https://` script/link/font/icon dependency, no `unpkg.com`, no `htmx.org`, and no new external asset references. `pyproject.toml` project dependencies must not change for the restyle.
6. All user-, agent-, PR-, database-, header-, and artifact-derived text remains HTML-escaped in templates. No new `|safe`, unescaped string concatenation, inline event-handler attributes, or JavaScript interpolation of untrusted values may be introduced.
7. The dashboard remains accessible without JavaScript for core actions: navigation uses links, filtering uses GET forms, triage uses POST forms with existing validation, evidence/transcript downloads remain plain text with `nosniff`, and pages are still meaningful if optional async polling is unavailable.
8. Existing dashboard tests continue to pass after updating assertions that expected the remote HTMX CDN, and new tests cover the restyled markup, no-remote-dependency rule, no-JS fallbacks, empty states, and XSS regressions.

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
- `prsec/dashboard/templates/_timeline.html`, `_timeline_poller.html`, `_timeline_poll.html`, `_timeline_macros.html` only if needed to remove remote-library assumptions or add restyle classes while preserving behavior
- `tests/dashboard/test_prsec_dashboard_routes.py`
- `tests/dashboard/test_prsec_dashboard_timeline.py` only for assertions affected by remote-library removal or class/name changes
- Add `tests/dashboard/test_prsec_dashboard_templates.py` if useful for template/static dependency checks

Out of scope:
- Database schema or query changes
- API, worker, orchestrator, runner, dynamic validation, SARIF generation, and policy logic
- Authentication/authorization model changes
- CI/deployment/Helm/compose changes
- Adding frontend build tooling, package managers, vendored libraries, web fonts, icon packs, images, or new Python/project dependencies
- Broad unrelated refactors or renaming routes

4. Design
Use the existing FastAPI + Jinja2 dashboard architecture. Keep styling self-contained in `base.html` via CSS custom properties and semantic utility classes; do not introduce a static asset pipeline. Build on existing conventions (`panel`, `badge`, `grid2`, `kv`, `muted`, severity/status classes) but improve them into a cohesive design system with clearer spacing, radius, shadows/borders, typography, focus states, responsive table wrappers, and dark-mode variables.

Prioritize `finding.html`: add semantic layout containers such as a page hero, metadata strip, content cards, a code-flow timeline/list, and a sidebar for triage/provenance/details. Keep every existing field and link, including evidence, dynamic evidence, replay details, fingerprint, scan links, and occurrences.

Remove the remote HTMX script from `base.html`. Preserve plain HTML fallbacks first: visible submit buttons, correct `method`/`action`, normal links, and reload guidance for live data. Existing server-side partial routes may remain. If the current async UX is retained, implement only the small needed behavior with first-party vanilla JavaScript in the dashboard templates and keep it progressive: failure or absence of JavaScript must fall back to full-page form submissions/reloads.

5. Code quality requirements
- Follow the style and naming conventions of the surrounding Jinja templates and dashboard code.
- Keep changes focused on dashboard presentation and progressive enhancement; do not refactor unrelated Python logic.
- Do not duplicate large template blocks; use existing partials (`_findings_table.html`, `_triage.html`, `_timeline*.html`) where they already separate concerns.
- Use clear class names tied to dashboard concepts, not vague or unused decorative names.
- Do not introduce dead CSS/JS or unused template fragments.
- Do not add speculative abstraction, build tooling, dependencies, or asset packaging changes.
- Preserve existing route names, form fields, query parameters, table data, and links.
- Keep error handling at the current Python route layer; templates should not hide 404/422 behavior or validation errors.

6. Security considerations
Untrusted input reaches these templates from PR/agent outputs, SARIF/finding data, scan events, triage notes, request headers used as user identity, query parameters used in filter forms, and artifact metadata. The change must preserve Jinja autoescaping and must not add `|safe`, inline event handlers, or JavaScript that interpolates untrusted strings into HTML. Removing the remote HTMX CDN reduces third-party script supply-chain exposure, but any first-party JavaScript must not evaluate strings, build selectors from untrusted data without validation, or change authorization decisions. Authentication remains external to the app behind the SSO proxy; this change must not broaden access or trust forwarded headers more than today. Triage state changes must continue to rely on the existing POST route and server-side state validation. Evidence and transcript routes must continue serving artifacts as `text/plain` with `X-Content-Type-Options: nosniff`.

7. Edge cases
- Empty lists: no scans, no findings, no stage runs, no timeline events, no guards, no dynamic validation, no occurrences.
- Malformed or unexpected display values: missing optional fields, unknown severity/status/label/triage class values, absent source/path/sink details, missing timestamps or costs.
- Oversized content: long titles, repository names, file paths, code snippets, event messages, JSON payloads, provenance, app logs, triage notes, and filter values must wrap or scroll without breaking layout.
- Duplicate/repeated content: repeated findings, repeated timeline groups, repeated badges, and repeated filter values must remain readable and not create invalid IDs when new IDs are introduced.
- Concurrent/state-changing input: two triage submissions must still be handled by the existing route; no client-side styling or async behavior may bypass server validation.
- Failure/no-enhancement modes: JavaScript disabled, async fetch failure, partial endpoint error, or blocked optional script must leave filtering/triage/navigation usable through normal page loads.
- Security edge cases: malicious HTML/JS in finding title, description, snippets, event data, triage note, or forwarded user header must render escaped; remote asset URLs must not be introduced.

8. Test plan
Unit tests:
- `tests/dashboard/test_prsec_dashboard_templates.py::test_dashboard_templates_do_not_load_remote_assets`: read `prsec/dashboard/templates/*.html` and assert there are no remote script/link/font/icon dependencies (`http://`, `https://`, `unpkg.com`, `htmx.org`) and no new external asset references.
- `tests/dashboard/test_prsec_dashboard_templates.py::test_base_template_contains_responsive_self_contained_design_tokens`: assert `base.html` defines the shared shell/classes, dark-mode variables, focus styles, responsive media rules, and table/form/badge/card styles used by the restyled templates.
- `tests/dashboard/test_prsec_dashboard_templates.py::test_pyproject_dependencies_unchanged_for_dashboard_restyle`: assert no frontend or new Python dependency was added for this issue, or cover this by reviewer diff if a static test is too brittle.

Integration tests:
- Update `tests/dashboard/test_prsec_dashboard_routes.py::test_scans_list`: remove the assertion for `htmx.org@2.0.4`; assert the scans page renders the new shell/navigation/table styling and still lists seeded scan data, cost, duration, and filters.
- Add `tests/dashboard/test_prsec_dashboard_routes.py::test_dashboard_pages_share_restyled_shell`: request `/`, `/findings`, `/metrics`, and `/scans/{scan_id}` from the seeded client; assert status 200, shared shell/topnav/main classes are present, no remote asset strings are present, and key page-specific content still appears.
- Update or add `tests/dashboard/test_prsec_dashboard_routes.py::test_findings_filters_remain_plain_get_and_partial_compatible`: assert `/findings` has a visible GET filter submit button, selected query filters still limit rows, empty filters/no-match filters show the empty state, and the existing HX request still returns only `_findings_table.html` without a full `<html>` document.
- Add `tests/dashboard/test_prsec_dashboard_routes.py::test_finding_detail_uses_priority_layout_and_preserves_sections`: request a seeded finding and assert the hero/layout/card classes are present; title, severity, label, status, repo/PR, description, label reasoning, code flow, guards, triage, fingerprint, provenance, scan links, and occurrences remain visible.
- Keep `tests/dashboard/test_prsec_dashboard_routes.py::test_finding_detail_and_triage` passing: triage form still posts through the existing route, HX partial triage still works if supported, invalid state returns 422, missing finding returns 404, and non-HX POST redirects to the finding detail page.
- Keep `tests/dashboard/test_prsec_dashboard_routes.py::test_transcript_and_evidence_routes` passing: evidence/transcript links still appear and responses remain plain text with protected artifact path handling.
- Keep `tests/dashboard/test_prsec_dashboard_timeline.py` passing except for deliberate assertion updates caused by removing the remote HTMX CDN. In particular, `test_scan_page_renders_timeline_escaped`, `test_scan_page_polls_while_running`, `test_finished_scan_does_not_poll`, `test_poll_returns_only_new_events_out_of_band`, `test_poll_without_new_events_keeps_cursor`, and `test_poll_stops_when_scan_finished` must still prove timeline escaping, cursor behavior, and partial route behavior.

Regression tests:
- Add `tests/dashboard/test_prsec_dashboard_routes.py::test_dashboard_restyle_escapes_untrusted_finding_content`: insert or patch a finding/scan event/triage note with `<script>`, HTML attributes, and `javascript:`-like text; assert raw tags/attributes do not appear and escaped text does appear on finding and scan pages.
- Add `tests/dashboard/test_prsec_dashboard_routes.py::test_finding_detail_handles_missing_optional_sections`: render a finding with no remediation, guards, dynamic validation, optional source/path fields, or evidence URI; assert the page returns 200, shows appropriate empty/fallback text, and does not produce broken links.
- Add `tests/dashboard/test_prsec_dashboard_routes.py::test_long_dashboard_values_wrap_without_losing_content`: render or patch long title/repo/file path/snippet/provenance values; assert they are present and contained in elements/classes intended to wrap or scroll (`code`, `pre`, table wrapper, or flow item classes).
- Existing dashboard/security regression tests that must keep passing: `test_local_path_refuses_off_site_redirects`, `test_run_binds_loopback_unless_configured`, `test_sarif_download`, `test_scan_detail`, `test_metrics_page`, and all dashboard timeline escaping/polling tests.
Tests required: yes

9. Risks
- Visual-only changes are hard to verify automatically; tests should assert structural/classes and preserved content, not subjective appearance.
- Removing the remote HTMX dependency could regress live timeline polling or partial triage/filter interactions if no first-party progressive replacement or plain fallback is provided.
- Template restructuring can accidentally drop fields, links, or escaping.
- Larger CSS changes can cause mobile overflow or dark-mode contrast regressions.
- Static tests for dependency strings can be brittle if legitimate non-asset URLs are later added to copy; keep them scoped to dashboard templates for this issue.

10. Suspicious content
none

Risk level: medium
Reason: The change is mostly presentation, but it touches all dashboard templates that render untrusted security-scan data and removes/replaces a third-party JavaScript dependency used by existing progressive UI behavior.
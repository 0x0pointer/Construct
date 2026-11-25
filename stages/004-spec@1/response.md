DECISION NEEDED: The issue could mean a full product redesign with new client-side behavior, or a focused server-rendered restyle that modernizes the current dashboard without new dependencies; choose the focused server-rendered restyle.

1. Intent - Restyle the PRSec dashboard to look modern, readable, and browser-friendly while keeping it self-contained. Focus on the findings list and finding detail pages; let scans/metrics inherit the shared visual system. Remove the default external HTMX CDN load and do not add any CSS/JS library, while preserving existing routes and non-JavaScript form behavior.

2. Acceptance criteria
1. `GET /findings` renders a styled findings page with a prominent page header, readable filter controls, an always-visible submit button, and the existing filtered/paginated results.
2. `GET /findings/{id}` renders a finding-focused layout: title/metadata summary first, severity/label/status badges, description/remediation/code-flow/guards/dynamic-validation/triage/provenance in distinct responsive cards, and all existing data and links still visible.
3. Dashboard pages (`/`, `/findings`, `/findings/{id}`, `/metrics`, `/scans/{id}`) load no external CSS or JavaScript by default: no `http(s)://` script or stylesheet URLs and no `unpkg.com`/CDN references in rendered HTML.
4. Existing dashboard behavior must not regress: filters, pagination, triage POST redirect/partial response, timeline event endpoints, SARIF/evidence downloads, and escaping of hostile finding/event content still work.
5. Scan and metrics pages remain simple debugging pages but inherit the shared styling: readable tables/cards, responsive wrapping, and no broken layout on narrow screens.

3. Boundaries
Always: use existing FastAPI/Jinja rendering in `prsec/dashboard/main.py`, existing templates in `prsec/dashboard/templates/`, current Jinja autoescaping, existing filters (`usd`, `dur`, `pct`, `tojson_pretty`), and existing route names/URLs. Prefer inline CSS in `base.html`; no build step.
Never: do not add package/npm/CDN dependencies, do not change database queries/schema, authentication assumptions, artifact serving, route signatures, or business logic. Do not restyle non-dashboard app components.

4. Code map
- `prsec/dashboard/templates/base.html`: remove the external HTMX `<script>` load; replace/extend inline CSS with a modern design system (layout shell, cards, badges, responsive tables, forms, code/pre wrapping, dark mode) used by all dashboard pages.
- `prsec/dashboard/templates/findings.html`: restyle page header/filter area; keep `GET /findings`; add a normal visible submit button so filters work without JavaScript; keep existing filter names and selected values.
- `prsec/dashboard/templates/_findings_table.html`: add responsive table/container markup and improved empty-state styling without changing columns, links, or pagination URLs.
- `prsec/dashboard/templates/finding.html`: reorganize existing finding detail content into summary/header and card sections; keep every existing field/link/form/dynamic evidence block and escaping.
- `prsec/dashboard/templates/_triage.html` and `_timeline_poller.html`: adjust styling/text only as needed for the no-default-JS experience; keep form action/method and existing HX-compatible attributes/endpoints if retained.
- Existing tests: `tests/dashboard/test_prsec_dashboard_routes.py`, `test_prsec_dashboard_dynamic.py`, and `test_prsec_dashboard_timeline.py` cover the routes, escaping, triage, dynamic evidence, and timeline behavior.

5. Edge cases
| Case | Expected behaviour |
| --- | --- |
| Empty findings/scans/metrics rows | Existing empty messages remain visible inside styled tables/cards. |
| Malformed/hostile HTML in titles, snippets, dynamic evidence, or events | Rendered as escaped text; no raw `<script>` execution surface is introduced. |
| Oversized titles, paths, snippets, JSON, or provenance | Content wraps or scrolls within cards/tables; page remains navigable on desktop and mobile. |
| Duplicate/unknown filter values from existing option sources | Rendering does not crash; selected values and normal filtering semantics stay unchanged. |
| Concurrent running scan while dashboard is viewed | Existing timeline route output and page rendering still work; without bundled JS the page remains refreshable/readable. |
| Failed/missing finding, scan, SARIF, transcript, or evidence | Existing 404/502 behavior and messages are unchanged. |

6. Security considerations
The dashboard renders untrusted scan/finding/event/artifact-derived text from the database and object store. Keep Jinja autoescaping; do not add `|safe`, inline event handlers, or string-built HTML/JS. Removing the CDN script reduces third-party supply-chain exposure. CSS class interpolation from existing status/severity/label strings must remain escaped and must not create script execution. No shell, SQL, path, prompt, authentication, or authorization logic should change.

7. Test plan
- Update `tests/dashboard/test_prsec_dashboard_routes.py::test_scans_list`: remove the `htmx.org@2.0.4` expectation; assert the page still renders scan data and shared styling markers.
- Add `tests/dashboard/test_prsec_dashboard_routes.py::test_dashboard_pages_do_not_load_external_assets`: GET `/`, `/findings`, `/metrics`, and a seeded `/findings/{id}`; assert no external script/stylesheet/CDN references and that inline styling/shared layout is present.
- Add `tests/dashboard/test_prsec_dashboard_routes.py::test_findings_page_is_usable_without_javascript`: assert `/findings` has method=get filters, a visible submit button not only inside `<noscript>`, selected filter values survive, and existing filtered GET behavior still works.
- Add/update `tests/dashboard/test_prsec_dashboard_routes.py::test_finding_detail_and_triage`: assert the finding detail contains the new summary/card layout markers while retaining source/sink snippets, provenance, triage, redirect, and HX partial behavior.
- Keep `tests/dashboard/test_prsec_dashboard_dynamic.py::test_finding_page_dynamic_section_is_escaped` and timeline escaping/polling tests passing; update only text/style assertions made obsolete by removing the bundled CDN script.
- Run `pytest tests/dashboard`.
Tests required: yes

8. Review focus
- The final pages may look different but not actually improve finding readability on small screens.
- Removing the CDN script may accidentally make a form depend on JavaScript or mislead users about live updates.
- New CSS may hide important debugging data, truncate without access, or break dark mode contrast.
- Template refactors may omit a finding field/link that existing tests do not assert.
- Any added raw HTML/CSS/JS handling could weaken escaping of untrusted scan data.

9. Assumptions
- A “modern look” means improved spacing, typography, cards, badges, responsive tables, and clearer hierarchy, not new workflows.
- Self-contained means no external CSS/JS loaded by default; existing server-side HX partial routes may remain for compatibility.
- Browser optimization means progressive, server-rendered HTML that works without JavaScript and degrades gracefully.
- Finding pages are the priority; scans and metrics receive shared styling but no workflow redesign.

10. Suspicious content
none

Size: standard
Risk level: medium
Reason: the change is mostly presentation, but the dashboard renders untrusted security-scan content and supports triage/debug workflows; mistakes could introduce XSS or hide/alter important findings.
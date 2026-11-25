Changed:
- Mounted `/static` in `prsec.dashboard.main`, replaced the HTMX CDN + inline styles with local `dashboard.css` and `dashboard.js`, and packaged static assets via `pyproject.toml`.
- Restyled dashboard templates for scans, findings, finding detail, scan detail, metrics, triage, and timeline with responsive/local classes only.
- Added dependency-free JS for progressive enhancement:
  - async GET filtering with history updates,
  - async triage partial saves,
  - scan timeline polling with OOB append/delete handling,
  - duplicate timeline row suppression by `data-id`.
- Preserved existing server routes, partial headers, escaping, redirects, artifact types, and current data displays.

Acceptance criteria / coverage:
- Local-only assets on `/`, `/findings`, `/findings/{id}`, `/scans/{id}`, `/metrics`:
  - `tests/dashboard/test_prsec_dashboard_routes.py::test_scans_list`
  - `tests/dashboard/test_prsec_dashboard_routes.py::test_dashboard_assets_are_local_and_served`
  - `tests/dashboard/test_prsec_dashboard_routes.py::test_dashboard_static_js_has_no_external_dependency_bootstrap`
- Findings filters, empty state, pagination, badges, links, full GET + async partial:
  - `tests/dashboard/test_prsec_dashboard_routes.py::test_findings_filters`
- Finding detail summary/sections, escaped hostile content, triage async + redirect fallback:
  - `tests/dashboard/test_prsec_dashboard_routes.py::test_finding_detail_and_triage`
  - `tests/dashboard/test_prsec_dashboard_dynamic.py::test_finding_page_dynamic_section_is_escaped`
- Scan page triage/metadata/agents/timeline/live polling behavior:
  - `tests/dashboard/test_prsec_dashboard_timeline.py::test_scan_page_polls_while_running`
  - `tests/dashboard/test_prsec_dashboard_timeline.py::test_poll_returns_only_new_events_out_of_band`
  - `tests/dashboard/test_prsec_dashboard_timeline.py::test_poll_stops_when_scan_finished`
- Existing dashboard behavior stayed green:
  - `pytest tests/dashboard/test_prsec_dashboard_routes.py tests/dashboard/test_prsec_dashboard_dynamic.py tests/dashboard/test_prsec_dashboard_timeline.py -q`
  - `pytest -m 'not docker and not k8s and not live_harness' -q`

Noticed, not touched:
- Existing pytest warnings about `pytest_asyncio` loop-scope config and Starlette’s `TestClient` deprecation.

STATUS: DONE
Implemented the approved dashboard restyle and removed the remote HTMX dependency.

What changed
- Restyled the shared dashboard shell in `base.html` with:
  - branded top nav
  - max-width layout
  - cards/panels
  - responsive tables/forms
  - visible focus states
  - dark-mode variables
  - responsive layout
- Reworked dashboard templates:
  - `findings.html` + `_findings_table.html`
  - `finding.html`
  - `scans.html`
  - `scan.html`
  - `metrics.html`
  - `_triage.html`
  - `_timeline.html`
  - `_timeline_poller.html`
- Replaced CDN HTMX usage with small first-party progressive enhancement in `base.html`:
  - same-origin partial GET refresh for findings filters
  - same-origin partial POST refresh for triage
  - same-origin timeline polling using existing partial routes and `hx-swap-oob` hints
  - plain HTML forms/links still work without JavaScript
- Kept existing route behavior intact; no Python dependency changes.

Test coverage by acceptance criterion
- AC1 shared shell/restyled pages:
  - `tests/dashboard/test_prsec_dashboard_routes.py::test_scans_list`
  - `tests/dashboard/test_prsec_dashboard_routes.py::test_dashboard_pages_share_restyled_shell`
  - `tests/dashboard/test_prsec_dashboard_templates.py::test_base_template_defines_self_contained_responsive_design`
- AC2 finding detail reorganization/preserved content:
  - `tests/dashboard/test_prsec_dashboard_routes.py::test_finding_detail_restyled_layout_preserves_sections`
  - `tests/dashboard/test_prsec_dashboard_routes.py::test_finding_detail_handles_missing_optional_sections`
  - `tests/dashboard/test_prsec_dashboard_routes.py::test_long_dashboard_values_use_wrapping_layout`
- AC3 findings/scans filters, empty state, partial compatibility:
  - `tests/dashboard/test_prsec_dashboard_routes.py::test_scans_list`
  - `tests/dashboard/test_prsec_dashboard_routes.py::test_findings_filters`
  - `tests/dashboard/test_prsec_dashboard_routes.py::test_findings_filters_remain_plain_get_and_partial_compatible`
- AC4 triage/timeline/server behavior preserved:
  - `tests/dashboard/test_prsec_dashboard_routes.py::test_finding_detail_and_triage`
  - `tests/dashboard/test_prsec_dashboard_timeline.py::test_scan_page_polls_while_running`
  - `tests/dashboard/test_prsec_dashboard_timeline.py::test_finished_scan_does_not_poll`
  - `tests/dashboard/test_prsec_dashboard_timeline.py::test_poll_returns_only_new_events_out_of_band`
  - `tests/dashboard/test_prsec_dashboard_timeline.py::test_poll_without_new_events_keeps_cursor`
  - `tests/dashboard/test_prsec_dashboard_timeline.py::test_poll_stops_when_scan_finished`
  - `tests/dashboard/test_prsec_dashboard_timeline.py::test_poll_continues_while_backlog_is_full`
- AC5 no remote assets:
  - `tests/dashboard/test_prsec_dashboard_templates.py::test_dashboard_templates_do_not_load_remote_assets`
  - `tests/dashboard/test_prsec_dashboard_routes.py::test_dashboard_pages_share_restyled_shell`
- AC6 no-JS fallback:
  - `tests/dashboard/test_prsec_dashboard_routes.py::test_findings_filters`
  - `tests/dashboard/test_prsec_dashboard_routes.py::test_findings_filters_remain_plain_get_and_partial_compatible`
  - `tests/dashboard/test_prsec_dashboard_routes.py::test_finding_detail_and_triage`
- AC7 escaping/trust boundaries:
  - `tests/dashboard/test_prsec_dashboard_templates.py::test_dashboard_templates_do_not_introduce_unsafe_rendering_hooks`
  - `tests/dashboard/test_prsec_dashboard_routes.py::test_dashboard_restyle_escapes_untrusted_finding_and_scan_content`
  - `tests/dashboard/test_prsec_dashboard_timeline.py::test_scan_page_renders_timeline_escaped`
- AC8 updated and new dashboard tests:
  - added `tests/dashboard/test_prsec_dashboard_templates.py`
  - updated `tests/dashboard/test_prsec_dashboard_routes.py`
  - updated `tests/dashboard/test_prsec_dashboard_timeline.py`

Tests run
- `pytest -q tests/dashboard/test_prsec_dashboard_templates.py tests/dashboard/test_prsec_dashboard_timeline.py tests/dashboard/test_prsec_dashboard_routes.py`
- `pytest -q -m 'not db and not docker and not k8s and not live_harness'`

Results
- Targeted dashboard tests: passed
- Required pytest command: passed
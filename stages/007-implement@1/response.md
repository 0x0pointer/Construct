Implemented the approved dashboard refresh spec in `prsec/dashboard` and dashboard tests.

What I changed
- Added first-party static assets:
  - `prsec/dashboard/static/dashboard.css`
  - `prsec/dashboard/static/dashboard.js`
- Mounted `/static` in `prsec.dashboard.main.app`, added first-party partial-request header support while keeping HTMX header compatibility for `/findings` and triage POSTs.
- Updated `pyproject.toml` package data so dashboard CSS/JS are included.
- Reworked dashboard templates to use the shared visual system and progressive enhancement without external assets:
  - `base.html`, `findings.html`, `_findings_table.html`, `finding.html`, `_triage.html`
  - `scans.html`, `scan.html`, `_timeline.html`, `_timeline_poll.html`, `_timeline_poller.html`, `metrics.html`
- Replaced HTMX-driven client behavior with first-party JS for:
  - findings filter partial updates + URL updates
  - triage panel partial updates
  - live scan timeline polling every 2s with duplicate-safe append behavior
- Added the spec’s UI coverage in `tests/dashboard/test_dashboard_ui.py`
- Updated existing dashboard tests that asserted old HTMX-specific markup to assert the new first-party behavior instead.

Acceptance criteria / coverage
1. `/findings` responsive modern page, filters/table/pager/empty state:
   - `tests/dashboard/test_dashboard_ui.py::test_findings_page_responsive_filters_table_empty_and_partial`
2. `/findings/{id}` responsive detail layout with operator-critical info first and escaped long/untrusted text:
   - `tests/dashboard/test_dashboard_ui.py::test_finding_detail_prioritizes_content_and_escapes_untrusted_text`
   - existing dynamic coverage still passes in `tests/dashboard/test_prsec_dashboard_dynamic.py`
3. `/`, `/scans/{id}`, `/metrics` keep current visible behavior with shared styling:
   - `tests/dashboard/test_dashboard_ui.py::test_scans_scan_metrics_keep_existing_visible_behaviour`
4. No external CSS/JS; only first-party dashboard assets:
   - `tests/dashboard/test_dashboard_ui.py::test_dashboard_assets_are_first_party_and_packaged`
5. JS-enabled progressive enhancement for findings filters, triage, and live timeline:
   - findings/triage partial behavior: `test_findings_page_responsive_filters_table_empty_and_partial`, `test_triage_progressive_enhancement_and_validation`
   - timeline poll metadata/fragment behavior: `test_timeline_poll_fragment_is_safe_and_deduplicatable`
   - existing timeline tests updated and passing in `tests/dashboard/test_prsec_dashboard_timeline.py`
6. JS-disabled fallback behavior:
   - full-page GET/POST forms asserted by `test_findings_page_responsive_filters_table_empty_and_partial` and `test_triage_progressive_enhancement_and_validation`
   - readable completed scan/timeline behavior covered by existing timeline tests
7. Existing non-UI behaviors unchanged:
   - artifact headers: `tests/dashboard/test_dashboard_ui.py::test_artifact_security_headers_unchanged`
   - existing dashboard route/timeline/dynamic tests still pass, including 404/422 coverage

Validation run
- `pytest tests/dashboard -q`
- `pytest -m 'not docker and not k8s and not live_harness' -q`

Observed passing in this session
- Dashboard test suite: passed
- Full required non-docker/non-k8s/non-live_harness suite: `1922 passed, 19 skipped, 18 deselected`

Noticed, not touched
- The suite emits an existing `pytest-asyncio` deprecation warning about `asyncio_default_fixture_loop_scope`.
- `fastapi.testclient` emits an existing Starlette deprecation warning about `httpx` usage.

STATUS: DONE
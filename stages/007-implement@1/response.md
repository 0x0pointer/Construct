Implemented the approved dashboard restyle as a self-contained server-rendered update.

What I changed
- Removed the default external HTMX CDN load from `prsec/dashboard/templates/base.html`.
- Reworked the shared inline CSS in `base.html` into a broader visual system: sticky header, cards, responsive table wrappers, filter/form styling, wrapping code/pre blocks, and dark-mode-friendly colors.
- Restyled `findings.html` with a prominent header, clearer filter controls, a normal visible submit button, and preserved existing GET/HX behavior.
- Restyled `_findings_table.html` with a card/table container and improved empty state, without changing columns, links, or pagination semantics.
- Reorganized `finding.html` into a finding-focused layout with:
  - summary hero/header first,
  - severity/label/status/triage badges,
  - distinct cards for description, remediation, code flow, guards, dynamic validation, triage, metadata, provenance, and occurrences.
- Updated `_triage.html` styling only; form action/method/HX behavior stayed intact.
- Updated `_timeline_poller.html` text so live scans remain readable without implying bundled JS auto-refresh.
- Lightly updated `scans.html`, `scan.html`, and `metrics.html` to inherit the shared styling and responsive table wrappers.

Tests added/updated
- `tests/dashboard/test_prsec_dashboard_routes.py::test_scans_list`
  - Covers acceptance criterion 5/shared styling on `/`.
  - Updated to remove the old HTMX CDN expectation and assert shared styling markers.
- `tests/dashboard/test_prsec_dashboard_routes.py::test_dashboard_pages_do_not_load_external_assets`
  - Covers acceptance criterion 3.
  - Verifies `/`, `/findings`, `/metrics`, and `/findings/{id}` render without external JS/CSS/CDN references.
- `tests/dashboard/test_prsec_dashboard_routes.py::test_findings_page_is_usable_without_javascript`
  - Covers acceptance criteria 1 and 4.
  - Verifies GET filters, visible submit button, selected filter persistence, and existing filtered behavior.
- `tests/dashboard/test_prsec_dashboard_routes.py::test_finding_detail_and_triage`
  - Covers acceptance criteria 2 and 4.
  - Verifies the new detail layout markers while preserving existing content, triage redirect behavior, and HX partial behavior.
- Existing tests kept passing for escaping and timeline behavior:
  - `tests/dashboard/test_prsec_dashboard_dynamic.py::test_finding_page_dynamic_section_is_escaped`
  - `tests/dashboard/test_prsec_dashboard_timeline.py` suite
  - These cover acceptance criterion 4, including hostile content escaping and timeline endpoints.

Validation run
- `pytest tests/dashboard -q`
- `pytest -m 'not docker and not k8s and not live_harness' -q`

Both passed in this session.

Noticed, not touched
- Pytest emits an existing `pytest_asyncio` configuration deprecation warning during test runs.

STATUS: DONE
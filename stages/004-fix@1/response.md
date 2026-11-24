Fixed the CI failures in the dashboard PR.

What I changed
- Added a small `_page_href()` helper in `prsec/dashboard/main.py` and used it to build scan/findings pagination links server-side.
- Updated:
  - `prsec/dashboard/templates/_findings_table.html`
  - `prsec/dashboard/templates/scans.html`
  to use prebuilt `prev_href` / `next_href` instead of Jinja’s `urlencode` filter.
- Updated `prsec/dashboard/templates/scan.html` so the scan detail page has an outer `class="page-header"` shell, with the hero layout nested inside it.

Why this fixes the failed checks
- Failed check: `test_findings_filters_remain_plain_get_and_partial_compatible`
  - Cause: the template used Jinja’s `urlencode` filter for pagination, which did not encode `/` in `repo=acme/shop` as `%2F`, so the rendered link didn’t match the intended plain-GET pagination semantics.
  - Fix: generate pagination URLs in Python with `urllib.parse.urlencode(...)`, which correctly emits `repo=acme%2Fshop`.

- Failed check: `test_dashboard_pages_share_restyled_shell`
  - Cause: the scan detail page used `class="page-header hero"` on the same element, so the expected shared shell marker `class="page-header"` was missing as an exact class attribute.
  - Fix: made the scan page use `<section class="page-header">` and moved the hero layout to an inner `<div class="hero">`, preserving the layout while matching the shared shell contract.

Validation
- Focused checks:
  - `pytest -q tests/dashboard/test_prsec_dashboard_templates.py tests/dashboard/test_prsec_dashboard_timeline.py`
  - Result: passed
- Requested broader suite:
  - `pytest -q -m 'not db and not docker and not k8s and not live_harness'`
  - Result: `1846 passed, 19 skipped, 96 deselected`

Short summary by failed check
- `test_findings_filters_remain_plain_get_and_partial_compatible`
  - Cause: pagination links were encoded incorrectly by the template.
  - Change: built pagination URLs in Python with correct percent-encoding.

- `test_dashboard_pages_share_restyled_shell`
  - Cause: scan detail page did not expose the shared `page-header` shell in the expected structure.
  - Change: wrapped the scan hero layout inside a plain `page-header` container.
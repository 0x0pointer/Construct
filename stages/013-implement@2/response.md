Implemented the review fix for the finding detail page.

What I changed:
- Split the combined finding-detail content block in `prsec/dashboard/templates/finding.html` into three distinct cards:
  - `Description`
  - `Label reasoning`
  - `Remediation`
- Kept the existing escaped values and fallback text, including `No remediation recorded.` when remediation is absent.
- Tightened the existing route regression test in `tests/dashboard/test_prsec_dashboard_routes.py` so it now asserts those three headings each appear as their own `.card` section.

Test coverage for the finding:
- Reviewer finding: missing distinct cards for description, label reasoning, and remediation
  - Covered by `tests/dashboard/test_prsec_dashboard_routes.py::test_finding_detail_restyled_layout_preserves_sections`

Validation:
- Ran: `pytest -q -m 'not db and not docker and not k8s and not live_harness'`
- Result: passed (`1846 passed, 19 skipped, 96 deselected`)
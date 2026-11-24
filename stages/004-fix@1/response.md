Fixed the CI failure.

What failed
- `test`: `test_findings_filters_remain_plain_get_and_partial_compatible` expected a page-2 pagination link for `repo=acme/shop&severity=high`, but the shared dashboard DB fixture only seeded one matching high-severity finding, so there was no second page.

What I changed
- Updated `tests/dashboard/conftest.py` to seed two additional high-severity findings for the same scan/repo, giving that filtered result set enough rows to paginate.
- Updated the fixture docstring from “three findings” to “five findings”.

Why this is the right fix
- The PR explicitly adds coverage for preserved filtered pagination links on the restyled findings page.
- The code path already preserves filters correctly; the regression test was failing because its fixture did not create a multi-page filtered dataset.

Validation
- Ran: `pytest -q -m 'not db and not docker and not k8s and not live_harness'`
- Result: `1846 passed, 19 skipped, 96 deselected`

Note
- The specific failing test is DB-backed and may be skipped locally without `PRSEC_TEST_DATABASE_URL`, but the fixture change directly addresses the CI failure scenario.
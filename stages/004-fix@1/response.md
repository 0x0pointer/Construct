Fixed the CI failures on the PR branch.

What I changed
- **Failed test (`test_sarif_download`)**
  - **Cause:** The seeded dashboard fixture now creates **5 findings**, and the SARIF download correctly includes all 5 results. The test still expected the old count of 3.
  - **Fix:** Updated `tests/dashboard/test_prsec_dashboard_routes.py` to assert against `len(seeded["findings"])` instead of a stale hard-coded value.

- **SonarCloud issue: duplicated `"/findings"` literal**
  - **Cause:** `prsec/dashboard/main.py` repeated the same route string in multiple places.
  - **Fix:** Added a `FINDINGS_PATH` constant and reused it for the route, `_local_path` fallback, and pagination links.

- **SonarCloud issue: deprecated CSS `word-break: break-word`**
  - **Cause:** `prsec/dashboard/templates/base.html` used a deprecated CSS value.
  - **Fix:** Removed `word-break: break-word` and kept `overflow-wrap: anywhere`, which already provides the desired wrapping behavior.

Validation
- Reproduced the failing test locally first.
- Ran targeted tests:
  - `pytest -q tests/dashboard/test_prsec_dashboard_routes.py`
- Ran the required full suite:
  - `pytest -q -m 'not docker and not k8s and not live_harness'`

Result
- Targeted dashboard tests: **passed**
- Full required pytest run: **1924 passed, 19 skipped, 18 deselected**
Implemented the approved dashboard-only observability spec.

What I changed
- Added stage phase/decision helpers in `prsec/dashboard/main.py`:
  - `STAGE_PHASES`
  - `_stage_decision_key(...)`
  - `_review_decision_rows(...)`
  - enriched scan stage runs/agent rows with phase + explicit decision keys
- Extended `prsec/db/findings.py::metrics()` to return:
  - `review_funnel`
  - `stage_decisions`
  using 30-day aggregates, canonical `Stage` ordering, and shadow-run exclusion matching existing per-stage metrics.
- Updated `prsec/dashboard/templates/metrics.html` to add:
  - `PR review funnel (30 days)`
  - `Decision outcomes by stage (30 days)`
  while preserving the existing precision, per-agent, harness, and stage/harness/model sections.
- Updated `prsec/dashboard/templates/scan.html` to add:
  - `Review decision path`
  before `Agents`, with explicit decisions for malformed/failed/missing outputs.
- Added/updated route tests in `tests/dashboard/test_prsec_dashboard_routes.py`.

Acceptance criteria coverage
1. `/metrics` review funnel:
   - `test_metrics_review_funnel_and_stage_decisions`
2. `/metrics` stage+decision outcomes table:
   - `test_metrics_review_funnel_and_stage_decisions`
3. Existing metrics sections still present:
   - `test_metrics_review_funnel_and_stage_decisions`
   - existing `test_metrics_per_agent_rollup`
   - existing `test_metrics_page`
4. `/scans/{scan_id}` review decision path in pipeline order, including fan-out visibility:
   - `test_scan_detail_review_decision_path`
5. Dashboard shell / local assets / GET behavior preserved:
   - existing `test_dashboard_pages_share_restyled_shell`
   - existing findings/scans route tests
6. Missing/failed/malformed outputs render explicit decisions instead of blanks/errors:
   - `test_metrics_review_funnel_and_stage_decisions` (`unknown`, `output_invalid`)
   - `test_scan_detail_review_decision_path` (`unknown`, `output_invalid`)
7. Escaping of untrusted content on `/metrics` and `/scans/{scan_id}`:
   - `test_dashboard_restyle_escapes_untrusted_finding_and_scan_content`

Tests run
- `pytest tests/dashboard/test_prsec_dashboard_routes.py::test_metrics_review_funnel_and_stage_decisions -q`
- `pytest tests/dashboard/test_prsec_dashboard_routes.py::test_scan_detail_review_decision_path -q`
- `pytest tests/dashboard/test_prsec_dashboard_routes.py::test_dashboard_restyle_escapes_untrusted_finding_and_scan_content -q`
- `pytest tests/dashboard/test_prsec_dashboard_routes.py -q`
- `pytest tests/dashboard -q`
- `pytest -m 'not docker and not k8s and not live_harness' -q`

Result seen in this session
- Full required suite passed: `1938 passed, 19 skipped, 18 deselected`

Noticed, not touched
- The test suite emits an existing `pytest_asyncio` deprecation warning about unset loop scope.
- FastAPI/Starlette emits an existing `TestClient` deprecation warning about `httpx`.

STATUS: DONE
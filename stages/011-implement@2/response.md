Changed:
- Fixed `prsec/db/findings.py` metrics SQL so skeptic decisions only map to `refuted`/`upheld` when `output.refuted` is a real JSON boolean; malformed values now fall through to `status` or `unknown`, matching the Python decision-key logic.
- Strengthened `tests/dashboard/test_prsec_dashboard_routes.py::test_metrics_review_funnel_and_stage_decisions` to seed a malformed skeptic output (`{"refuted": "false"}`), assert concrete funnel totals, assert exact per-stage aggregates for representative rows, and verify the malformed skeptic run is aggregated/rendered as `unknown`, not `upheld`/`refuted`.

Coverage for todo items:
1. Malformed skeptic SQL aggregation fix:
   - Covered by `tests/dashboard/test_prsec_dashboard_routes.py::test_metrics_review_funnel_and_stage_decisions`
   - Specifically asserts the skeptic row is `unknown` and no skeptic `upheld`/`refuted` row is produced for the malformed value.
2. Metrics test was too weak:
   - Same test now asserts exact numeric values for:
     - funnel totals: triggered/active/skipped/failed/fully reviewed/findings produced
     - findings label breakdown: reproduced/likely/inconclusive
     - stage decision aggregates: runs/failed/OK rate and representative averages

Tests run:
- `pytest tests/dashboard/test_prsec_dashboard_routes.py::test_metrics_review_funnel_and_stage_decisions -q`
- `pytest tests/dashboard/test_prsec_dashboard_routes.py::test_metrics_per_agent_rollup tests/dashboard/test_prsec_dashboard_routes.py::test_metrics_review_funnel_and_stage_decisions tests/dashboard/test_prsec_dashboard_routes.py::test_metrics_page -q`
- `pytest -m 'not docker and not k8s and not live_harness' -q`

Noticed, not touched:
- Pre-existing pytest deprecation warnings from `pytest_asyncio` and `fastapi/starlette` test client usage.

STATUS: DONE
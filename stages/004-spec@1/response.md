DECISION NEEDED: The issue could mean changing Construct’s PR-review decision rules or improving the dashboard’s explanation of current decisions; choose dashboard observability only, so users get clearer per-scan and aggregate decision breakdowns but scan outcomes/rules do not change.

1. Intent - Make the non-finding dashboard pages explain why Construct reviewed, skipped, escalated, verified, or reproduced a PR. Add a coherent “review funnel” and per-stage decision breakdown to `/metrics`, and add a concise ordered “review decision path” to `/scans/{scan_id}` using existing scan, stage_run, finding, and occurrence data. No pipeline, rule, or stored schema behaviour changes.

2. Acceptance criteria
1. `/metrics` renders a top-level “PR review funnel (30 days)” showing triggered scans, active scans, skipped scans, failed scans, fully reviewed scans, and findings produced with reproduced/likely/inconclusive counts.
2. `/metrics` renders “Decision outcomes by stage (30 days)” with one row per observed stage+decision, ordered by the `Stage` enum, including stage role, decision key, run count, OK rate, failed count, average duration, average cost, average tokens, and average turns.
3. `/metrics` still renders the existing precision-by-label, precision-by-bug-class, per-agent execution health, harness comparison, and by-stage/harness/model tables with their current meanings.
4. `/scans/{scan_id}` renders “Review decision path” in pipeline order, with human phase names and concise decision details from stage outputs; fan-out stages show each observed decision rather than hiding them.
5. Existing dashboard shell behaviour remains: `/`, `/findings`, `/metrics`, and `/scans/{scan_id}` use the local styled shell, do not load remote assets, and all plain GET filters/pagination still work.
6. Missing, failed, or malformed stage outputs render as explicit non-crashing decisions (`output_invalid`, other non-ok status, or `unknown`) instead of blank cells or server errors.
7. Untrusted PR, finding, triage, stage output, error, and forwarded-user content remains HTML-escaped on `/metrics` and `/scans/{scan_id}`.

3. Boundaries
Always: use `prsec.models.Stage` for canonical stage ordering; use existing `STAGE_ROLES`, `_stage_summary`, `_turns`, `_fmt_usd`, `_fmt_dur`, `_fmt_pct`, `_render`, `db._conn()`, and dashboard template components (`card`, `section-heading`, `table-wrap`, `badge`, `muted`, `wrap-anywhere`). Keep SQL parameterized or limited to fixed internal CASE expressions.
Never: do not change orchestrator decisions, prompt text, stage output schemas, database schema, queue behaviour, auth/SSO assumptions, CI/deploy files, dependencies, or the findings detail page beyond incidental shared styling.

4. Code map
- `prsec/dashboard/main.py`: add `STAGE_PHASES: dict[str, str]`; add `_stage_decision_key(stage: str | None, status: str | None, output: Any) -> str`; add `_review_decision_rows(stage_runs: list[dict[str, Any]]) -> list[dict[str, Any]]` returning rows with `stage`, `role`, `phase`, `status`, `decision`, `summary`, `errors`, `task_id`, `health`; update `_agent_pipeline` rows with `phase`; update `scan_detail()` to pass `decision_path`. Existing tests: `tests/dashboard/test_prsec_dashboard_routes.py::test_scan_detail_agent_observability`.
- `prsec/db/findings.py`: extend `metrics()` to return `review_funnel` and `stage_decisions`; derive stage decisions with the same stage-specific keys as `_stage_decision_key` using fixed SQL CASE logic, excluding shadow task ids where existing per-stage rollup excludes them. Existing tests: `tests/dashboard/test_prsec_dashboard_routes.py::test_metrics_per_agent_rollup`.
- `prsec/dashboard/templates/scan.html`: add the “Review decision path” card before “Agents”, rendering `decision_path` and empty state.
- `prsec/dashboard/templates/metrics.html`: reorganize headings into funnel, decision outcomes, review quality/findings, agent execution health, and harness comparison; retain existing tables and labels where acceptance criteria require them.
- `tests/dashboard/test_prsec_dashboard_routes.py`: add/update route assertions for the new rendered content and escaping.

5. Edge cases
| Input or state | Expected behaviour |
|---|---|
| No scans/stage runs/findings in 30 days | `/metrics` returns 200 with zero/empty-state rows, no divide-by-zero, percentages as `-`. |
| Stage output is `NULL`, scalar, list, or missing expected keys | Decision key is non-ok `status` when applicable, otherwise `unknown`; page returns 200. |
| Stage run status is non-ok with partial output | Decision table shows the extracted decision if available and non-zero failed count/OK rate; no crash. |
| Fan-out duplicate decisions for a scan/stage | Scan detail shows each run’s decision row; metrics aggregates duplicates into one stage+decision count. |
| Very long summary/reasoning/error text | Render escaped and wrapped/truncated only by existing layout; no raw JSON dump added to overview tables. |
| Concurrent scans still running | Counted as active in the funnel; scan detail continues existing timeline polling behaviour. |
| DB query returns null averages | Render as `-` or `0` consistently with existing filters; no exception. |

6. Security considerations
Dashboard data is untrusted because it includes PR text, agent output, timeline data, errors, model names, and forwarded identity headers. Templates must rely on Jinja autoescape and must not introduce `|safe`, inline event handlers, remote scripts, or `javascript:` URLs. New SQL must not include request-controlled identifiers; aggregate CASE expressions are fixed constants. No shell, filesystem path, prompt, authentication, authorization, or state-transition surfaces are changed. Main abuse risk is misleading operational/business metrics, so failed/malformed outputs must be visible rather than silently omitted.

7. Test plan
- Add `tests/dashboard/test_prsec_dashboard_routes.py::test_metrics_review_funnel_and_stage_decisions`: with seeded data plus representative `rules`, `triage`, `dynamic`, and failed/malformed stage runs, assert `/metrics` contains “PR review funnel (30 days)”, “Decision outcomes by stage (30 days)”, expected counts/decision keys (`scan`, `full`, `reproduced`, `output_invalid`), and existing “Precision by label”, “By agent”, and “Harness comparison”.
- Add `tests/dashboard/test_prsec_dashboard_routes.py::test_scan_detail_review_decision_path`: assert `/scans/{scan_id}` shows “Review decision path”, stage phase/role labels, `2 hypothesis(es): H1, H2`, failed static-verify status, and existing transcript/SARIF links.
- Add or extend `tests/dashboard/test_prsec_dashboard_routes.py::test_dashboard_restyle_escapes_untrusted_finding_and_scan_content`: insert hostile stage output decision/reasoning and verify `/metrics` and `/scans/{scan_id}` do not contain raw HTML, event handlers, or `javascript:` links but do contain escaped text.
- Update existing `test_metrics_per_agent_rollup` only if assertions need the new section names; keep `test_scans_list`, findings filter tests, shell tests, timeline tests, and template-safety tests passing.
Tests required: yes

8. Review focus
- Stage decision extraction in Python and SQL can drift; ensure the visible keys match for equivalent inputs.
- Funnel counts must not double-count findings or confuse active, skipped, failed, superseded, and done scans.
- Shadow stage runs must remain excluded from per-agent/stage metrics where existing behaviour excludes them.
- The page should explain decisions without dumping large or sensitive transcripts into aggregate views.
- New template text must not regress escaping or introduce unsafe rendering hooks.

9. Assumptions
- “Other pages” means `/metrics` and per-scan detail; `/findings` is already satisfactory and scan list only needs existing behaviour preserved.
- A 30-day window matches current metrics and should be used for all new aggregate sections.
- Stage output fields in `prsec.stages.outputs` are the source of decision semantics; no new data capture is required.
- Superseded scans count in triggered totals but are not “fully reviewed”.
- `accepted` findings remain excluded from precision, as today.

10. Suspicious content - none

Size: standard
Risk level: medium
Reason: The change renders and aggregates untrusted PR/agent data in review decision surfaces; wrong escaping or misleading metrics could affect security review decisions, although no auth or pipeline state is changed.
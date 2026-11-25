Verdict: fail

Blocking findings: prsec/db/findings.py:377 malformed skeptic outputs can be counted as real upheld/refuted decisions; tests/dashboard/test_prsec_dashboard_routes.py:123 required metrics test does not assert numeric aggregates or malformed-output drift.

# Security review

## Summary
- Security findings: 0 blocking, 0 non-blocking. I found no reachable XSS, SQL injection, auth, shell, filesystem, URL, prompt, or state-transition vulnerability introduced by the diff.
- Correctness/spec findings affecting security-relevant dashboard observability: 1 blocking. Test coverage findings: 1 blocking.
- Acceptance criteria: 6/7 appear met; AC6 is not fully met for malformed skeptic outputs in `/metrics` because SQL can classify malformed data as real decisions instead of `unknown`.

## Changed files reviewed

| File | Risk | Blast radius |
|---|---:|---|
| `prsec/dashboard/main.py` | MEDIUM | Route helpers only. `_stage_decision_key` has 2 internal callers; `_review_decision_rows` has 1 caller (`scan_detail`); `metrics()` route has 1 DB call. |
| `prsec/db/findings.py` | MEDIUM | `metrics()` has 2 callers (`/metrics` and `tests/sinks/test_prsec_findings_db.py`). New SQL reads `scans`, `finding_occurrences`, and `stage_runs`; no request-controlled SQL identifiers. |
| `prsec/dashboard/templates/metrics.html` | MEDIUM | Rendered by `/metrics`; displays untrusted DB/model data but uses Jinja autoescape. |
| `prsec/dashboard/templates/scan.html` | MEDIUM | Rendered by `/scans/{scan_id}`; displays untrusted scan/stage/error data but uses Jinja autoescape. |
| `tests/dashboard/test_prsec_dashboard_routes.py` | LOW | Test-only changes. |

## Findings

### Blocking: malformed skeptic outputs are misclassified in aggregate metrics
`prsec/db/findings.py:377` maps any JSON object containing `refuted` through `output->>'refuted'`. That treats a malformed JSON string like `{"refuted": "false"}` as the real `upheld` decision, while `_stage_decision_key()` only accepts a JSON boolean and would return `unknown`; other malformed values can produce a NULL/blank decision. This violates the spec requirement that malformed stage outputs render as explicit non-crashing decisions and the review focus that Python and SQL decision keys must not drift. Fix by requiring `jsonb_typeof(output->'refuted') = 'boolean'` before the skeptic CASE, with malformed/missing values falling through to non-ok status or `unknown`.

### Blocking: required metrics assertions are too weak
`tests/dashboard/test_prsec_dashboard_routes.py:123` adds the required `/metrics` test, but it only checks headings and decision-key substrings. It would still pass if the funnel counts, run counts, failed counts, OK rates, or label counts were wrong, and it does not cover the malformed skeptic SQL/Python drift above. Fix by asserting concrete expected numeric counts for the seeded funnel/stage-decision rows and by adding a malformed skeptic-output case that must aggregate/render as `unknown`.

## Test coverage gaps
- `/metrics` does not assert exact funnel totals or per-stage aggregate totals/rates/cost/token/turn values despite the spec test plan requiring expected counts.
- No regression test covers malformed `skeptic.refuted` values (`"false"`, `null`, or non-boolean) in aggregate metrics.

## What I did not cover
- I did not re-run the full test suite; `/tmp/fabro/verify.log` already shows it passed.
- I did not audit unchanged dashboard pages, auth/SSO assumptions, orchestrator decision rules, or storage schema beyond the changed call paths and one-hop dependencies required for this diff.
- I did not perform HIGH-risk adversarial modeling because no changed file met the skill's HIGH triggers and no reachable injection/auth/state-transition red flag was found.
Changed:
- Removed the `.fabro/scripts/fabro-run-titles` application-change filter so successful `IssueToPR` PRs always get the idempotent Codespaces comment, matching the approved spec.
- Updated `.fabro/README.md` to document the same always-comment behavior.
- Replaced the old docs-only regression in `tests/fabro/test_run_titles.py` with a stronger one that proves non-application-only PRs still get the Codespaces comment.

Acceptance criteria coverage:
- AC1: `tests/fabro/test_run_titles.py::test_sweep_comments_once_for_successful_issue_run`, `tests/fabro/test_run_titles.py::test_sweep_comments_for_non_application_changes_too`
- AC2: `tests/fabro/test_run_titles.py::test_codespace_url_uses_repo_id_and_encodes_ref`, `tests/fabro/test_run_titles.py::test_codespace_comment_body_has_marker_and_badge`
- AC3: `tests/fabro/test_run_titles.py::test_sweep_comments_once_for_successful_issue_run`, `tests/fabro/test_run_titles.py::test_existing_marker_prevents_duplicate_comment`
- AC4: `tests/fabro/test_run_titles.py::test_existing_title_cases_still_match`, `tests/fabro/test_run_titles.py::test_sweep_still_tidies_nothing_to_do_runs`, `tests/fabro/test_run_titles.py::test_sweep_does_not_comment_for_failed_or_fixci_runs`
- AC5: `tests/fabro/test_run_titles.py::test_sweep_retries_when_pr_missing_or_github_fails`
- AC6: `tests/fabro/test_devcontainer.py::test_devcontainer_uses_fabro_image_and_starts_test_db`
- Backward-compatible state edge case: `tests/fabro/test_run_titles.py::test_old_string_state_is_backward_compatible`

Tests run:
- `pytest tests/fabro/test_run_titles.py::test_sweep_comments_for_non_application_changes_too -q`
- `pytest tests/fabro/test_run_titles.py::test_sweep_comments_once_for_successful_issue_run -q`
- `pytest tests/fabro/test_devcontainer.py -q`
- `pytest tests/fabro/test_run_titles.py -q`
- `pytest -m 'not docker and not k8s and not live_harness' -q`

Noticed, not touched:
- Existing pytest warnings about `pytest_asyncio` loop-scope config and a Starlette/httpx deprecation.

STATUS: DONE
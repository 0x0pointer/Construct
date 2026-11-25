Changed:
- Added `.fabro/scripts/comment-codespace`, an executable Python hook that:
  - builds the Codespaces URL/body with a hidden marker,
  - finds the open same-repo PR for `fabro/run/<run-id>`,
  - paginates PR comments to avoid duplicates,
  - retries PR lookup briefly after `run_complete`,
  - warns and exits 0 on missing token, invalid ref, missing PR, or GitHub/API errors.
- Added a non-blocking `run_complete` hook to `.fabro/workflows/issue-to-pr/workflow.toml`.
- Documented the new fail-open Codespaces PR comment in `.fabro/README.md`.
- Added `tests/fabro/test_comment_codespace.py`.

Acceptance criteria coverage:
1. Successful run adds one Codespaces badge comment:
   - `tests/fabro/test_comment_codespace.py::test_codespace_url_encodes_run_branch`
   - `tests/fabro/test_comment_codespace.py::test_main_posts_comment_for_matching_open_pr`
2. Re-running does not add a duplicate comment:
   - `tests/fabro/test_comment_codespace.py::test_main_skips_existing_marker_on_later_comment_page`
3. Missing PR/token/API error warns and exits successfully:
   - `tests/fabro/test_comment_codespace.py::test_main_ignores_fork_and_wrong_branch_prs`
   - `tests/fabro/test_comment_codespace.py::test_main_fails_open_without_token_or_on_api_error`
4. Existing issue-to-pr PR settings remain enabled/draft and hook is non-blocking/sandboxed:
   - `tests/fabro/test_comment_codespace.py::test_issue_to_pr_workflow_has_nonblocking_codespace_hook`

Validation run:
- `pytest tests/fabro/test_comment_codespace.py -q`
- `python -m py_compile .fabro/scripts/comment-codespace`
- `python .fabro/scripts/sync-pipeline --check`
- `pytest -m 'not docker and not k8s and not live_harness' -q`

Noticed, not touched:
- Existing pytest warnings about `pytest_asyncio` loop-scope config and a FastAPI/Starlette deprecation warning.

STATUS: DONE
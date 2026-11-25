Implemented the missing Fabro Codespaces hook pieces that the fix pass reported:

- Added `.fabro/scripts/comment-codespace`
  - Validates `owner/repo/ref`
  - Requires `ref` to be `fabro/run/...`
  - Finds the matching open same-repo PR
  - Pages PR comments for the hidden marker to stay idempotent
  - Posts one Codespaces badge comment
  - Fails open with warnings and without leaking `GITHUB_TOKEN`
- Updated `.fabro/workflows/issue-to-pr/workflow.toml`
  - Added a non-blocking `run_complete` sandbox hook:
    - `id = "codespace-comment"`
    - `event = "run_complete"`
    - `blocking = false`
    - `sandbox = true`
    - script invocation for `fabro/run/$FABRO_RUN_ID`

Test coverage for the reported todo items:
- `test_codespace_url_encodes_run_branch` — badge body, marker, encoded Codespaces URL
- `test_main_posts_comment_for_matching_open_pr` — posts one comment to the matching PR
- `test_main_skips_existing_marker_on_later_comment_page` — paginates and avoids duplicates
- `test_main_ignores_fork_and_wrong_branch_prs` — ignores fork/wrong-ref PRs
- `test_main_fails_open_without_token_or_on_api_error` — fail-open warning behavior, no token leak
- `test_issue_to_pr_workflow_has_nonblocking_codespace_hook` — workflow hook config and existing draft-PR settings

What I ran and saw pass:
- `pytest tests/fabro/test_comment_codespace.py -q`
- `python -m py_compile .fabro/scripts/comment-codespace`
- `python .fabro/scripts/sync-pipeline --check`
- `pytest -m 'not docker and not k8s and not live_harness' -q`

Noticed, not touched:
- `.fabro/README.md` was not updated in this fix pass because the reported failures only concerned the missing script and workflow hook.

STATUS: DONE
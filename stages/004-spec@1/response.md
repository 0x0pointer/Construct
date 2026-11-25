1. Intent
Add a Fabro issue-to-PR success hook that posts a GitHub Codespaces launch button on the draft PR Fabro just created. Keep Fabro's existing automatic draft PR creation; after run completion, locate the open PR whose head is `fabro/run/$FABRO_RUN_ID` in `0x0pointer/Construct` and add one idempotent comment with a Codespaces badge link for that branch.

2. Acceptance criteria
1. After a successful `issue-to-pr` Fabro run creates its draft PR, the PR conversation contains a comment with an "Open in GitHub Codespaces" badge linking to `https://codespaces.new/0x0pointer/Construct?quickstart=1&ref=fabro%2Frun%2F<run-id>`.
2. Re-running the success hook for the same PR does not add a second Codespaces comment.
3. If the matching PR cannot be found, `GITHUB_TOKEN` is absent, or GitHub returns an error, the hook logs a warning, exits successfully, and does not turn an otherwise successful run into a failed run.
4. Existing behaviour remains: `[run.pull_request]` is still enabled, PRs are still drafts, issue labels are still released by the existing `release` node, and the fix-ci workflow is unchanged.

3. Boundaries
Always: use stdlib `json`, `os`, `urllib.parse`, `urllib.request`; follow the existing hidden-marker/idempotent-comment pattern from `.fabro/workflows/fix-ci/workflow.fabro`; use the existing `GITHUB_TOKEN` permissions (`issues`, `contents`, `pull_requests` write). This is a Fabro-pipeline change, so only the `.fabro` files named below are in scope despite the usual application-code protection.
Never: do not replace Fabro auto-PR creation, enable auto-merge, broaden GitHub permissions, add dependencies, touch `.github/`, `deploy/`, or `prsec` product code, or post on fork PRs/branches that are not the current `fabro/run/<run-id>` branch.

4. Code map
- `.fabro/scripts/comment-codespace`: new executable Python script with `MARKER`, `codespace_url(owner, repo, ref) -> str`, `comment_body(owner, repo, ref) -> str`, and `main(argv: list[str] | None = None) -> int`; finds the matching open same-repo PR, checks existing comments for the marker, posts the Codespaces comment, and fails open with warnings.
- `.fabro/workflows/issue-to-pr/workflow.toml`: add a non-blocking `[[run.hooks]]` entry `id = "codespace-comment"`, `event = "run_complete"`, `sandbox = true`, invoking the new script for `0x0pointer/Construct` and branch `fabro/run/$FABRO_RUN_ID`.
- `.fabro/README.md`: document that successful issue-to-PR runs add a Codespaces test button comment, and that failures to comment do not block the PR.
- Existing tests: none currently cover `.fabro` scripts or hooks.

5. Edge cases
| Input/state | Expected behaviour |
|---|---|
| Missing token or empty run id/branch | Print warning, no POST, exit 0. |
| Malformed owner/repo/ref or ref not starting `fabro/run/` | Refuse to post, print warning, exit 0. |
| Matching PR list empty or only fork/wrong-branch PRs | No comment, warning, exit 0. |
| Existing marker in any fetched comment page | No duplicate comment, exit 0. |
| More than 100 comments | Paginate enough to find an existing marker before posting. |
| Two hook processes run concurrently | Best-effort idempotence: both check for marker; an exact race may duplicate a harmless comment but must not fail the run. |
| GitHub GET/POST failure | Warning without token/body leakage, exit 0. |

6. Security considerations
The hook uses an injected GitHub token and writes untrusted-visible PR comments. Validate owner/repo and branch, restrict posting to an open PR whose head repo is exactly `0x0pointer/Construct` and head ref equals `fabro/run/$FABRO_RUN_ID`, JSON-encode request bodies, URL-encode the ref, and never log tokens. Avoid shelling out in the script; the only shell interpolation is the fixed hook command expanding `FABRO_RUN_ID`. The hook is fail-open so a GitHub outage cannot block a reviewed code PR; the tradeoff is possible missing comment, covered by warnings/tests.

7. Test plan
- Add `tests/fabro/test_comment_codespace.py::test_codespace_url_encodes_run_branch`: asserts the generated body has the badge, marker, and encoded run-branch URL.
- Add `test_main_posts_comment_for_matching_open_pr`: fake GitHub API returns one same-repo open PR and no comments; assert one POST to `/issues/<number>/comments` with marker and badge.
- Add `test_main_skips_existing_marker_on_later_comment_page`: fake paginated comments with marker on page 2; assert no POST.
- Add `test_main_ignores_fork_and_wrong_branch_prs`: fake PRs from a fork/wrong ref; assert no POST and exit 0.
- Add `test_main_fails_open_without_token_or_on_api_error`: missing token and raised API error both return 0, warn, and do not leak the token.
- Add `test_issue_to_pr_workflow_has_nonblocking_codespace_hook`: parse TOML and assert hook id/event/script/blocking=false/sandbox=true, and `[run.pull_request] enabled=true draft=true`.
- Existing checks that must keep passing: `python -m py_compile .fabro/scripts/comment-codespace`, `python .fabro/scripts/sync-pipeline --check` with no extra repos, and the repository test command.
Tests required: yes

8. Review focus
- Whether `run_complete` runs after Fabro's auto-PR exists; otherwise the hook may need polling.
- Whether the hook command's `$FABRO_RUN_ID` expansion works in Fabro hook shells.
- Correct GitHub pagination and same-repo PR filtering.
- Warning paths must not fail the run or leak tokens/comment JSON.
- This protected `.fabro` change may require maintainer handling outside the normal issue-to-PR guard.

9. Assumptions
- Fabro `run_complete` hooks fire after auto-PR publication, or close enough that a short lookup/poll can find it.
- `codespaces.new/0x0pointer/Construct?quickstart=1&ref=<encoded-branch>` is the desired GitHub Codespaces entry point.
- A PR comment with the official Codespaces badge satisfies the requested "button".
- Missing comment is less harmful than failing an otherwise valid PR after it was created.

10. Suspicious content
none

Size: standard
Risk level: medium
Reason: the change uses a GitHub write token and modifies release automation comments; a bug could spam PRs, miss comments, or affect successful Fabro runs, but it is limited to the origin repository and PR comments.
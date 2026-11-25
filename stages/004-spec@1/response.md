DECISION NEEDED: I read “PR comment button” as an automated comment on every successful Fabro-created PR, not only a devcontainer or README link; the chosen reading gives one-click testing of the PR branch but requires changing protected `.fabro` automation and providing a host GitHub token, while the devcontainer-only reading would be simpler but would not put a button in the PR conversation.

1. Intent
Add a working GitHub Codespaces setup for this repository and make the existing Fabro post-run watcher add one idempotent Codespaces button comment to each successful `IssueToPR` draft PR. The button must open a codespace on that PR’s `fabro/run/<run id>` branch, not on `main`. Keep current run titling, no-work cleanup, issue labels, review gates, and fix-ci behaviour unchanged.

2. Acceptance criteria
1. After a successful `IssueToPR` run creates a draft PR, running `fabro-run-titles --once` with a valid `GITHUB_TOKEN` leaves exactly one PR conversation comment containing an “Open in GitHub Codespaces” badge/link for the PR branch.
2. The link targets `https://github.com/codespaces/new` with `repo=<numeric repository id>` and `ref=fabro/run/<run id>` URL-encoded; clicking it creates a codespace using `.devcontainer/devcontainer.json` from that branch.
3. Re-running the watcher for the same run or seeing an existing marker comment does not create duplicate comments.
4. Existing visible behaviour remains: IssueToPR and FixCI run titles are still set from first-step output, and “nothing to do” runs are still archived and have their empty branch pruned.
5. If the PR is not yet visible or GitHub API access fails, the watcher logs the problem, keeps processing other runs, and retries on a later sweep until the run ages out.
6. In a Codespace created from a Fabro PR branch, `python -c 'import prsec'`, `start-test-db`, and the repository test command remain runnable without extra manual package installation.

3. Boundaries
Always: use the existing `.fabro/scripts/fabro-run-titles` service, its `api()` helper, `STATE`, `MAX_AGE`, stdlib `urllib.request`, the GitHub Issues comments API for PR comments, and the existing `.fabro/docker/Dockerfile`/`start-test-db` environment for Codespaces. Preserve backward compatibility with the current string-valued state file.
Never: do not touch `.github/`, `deploy/`, prsec runtime code, approval/review/label workflow logic, or add dependencies. Do not weaken the protected-path guard; if this Fabro run cannot modify the named `.fabro` files because the guard is active, stop with `/tmp/fabro/blocked.md` rather than bypassing it.

4. Code map
- `.devcontainer/devcontainer.json`: add a devcontainer that builds from `../.fabro/docker/Dockerfile` with repo root context, installs `.[dev]` after create, and starts the test DB on start.
- `.fabro/scripts/fabro-run-titles`: add Codespaces URL/comment helpers; during `sweep`, for terminal successful `IssueToPR` runs, find the open PR whose head is `<owner>:fabro/run/<run_id>`, fetch repo id, and create/update one marker comment `<!-- fabro-codespace -->`; keep existing `title_for`, `tidy`, and branch deletion behaviour.
- `.fabro/README.md`: document the Codespaces comment, required `GITHUB_TOKEN` scopes (`metadata:read`, `pull_requests:read`, `issues:write`), and service environment setup.
- `tests/fabro/test_run_titles.py` and `tests/fabro/test_devcontainer.py`: new coverage; no existing tests cover `.fabro/scripts/fabro-run-titles`.

5. Edge cases
| State/input | Expected behaviour |
|---|---|
| No successful IssueToPR run, failed/cancelled run, or FixCI run | no Codespaces comment attempt |
| PR not created yet for `fabro/run/<run_id>` | title still handled; comment remains pending and is retried until `MAX_AGE` |
| Existing PR comment has marker | do not post another; state may mark comment done |
| Missing/invalid `GITHUB_TOKEN` or GitHub 401/403/5xx | log without token value; do not crash; retry later |
| Malformed repo slug or branch/ref containing markdown/URL metacharacters | skip malformed slug; URL-encode branch so raw branch text cannot inject markdown/URL parameters |
| State file from old versions contains strings | load and preserve enough information to avoid retitling regressions and still allow pending comments |
| Oversized/old run beyond `MAX_AGE` without PR/comment | mark skipped with a warning to avoid endless retries |
| Two watcher invocations see same run | marker check prevents duplicates in normal single-service operation; no new cross-process locking required |

6. Security considerations
Touches GitHub write access from a long-running host service. `GITHUB_TOKEN` must only be read from environment, never printed or stored in `STATE`. Untrusted values from Fabro/GitHub (repo slug, run id, branch, PR number, comments) must be validated or URL/path encoded; no shell commands may include them except the existing `tidy` branch delete path, whose validation must remain. Comment body should be mostly constant and must not echo issue/PR text. The Codespace runs PR code intentionally for human testing, so the comment should make clear it opens the PR branch.

7. Test plan
- `tests/fabro/test_run_titles.py::test_existing_title_cases_still_match`: current IssueToPR/FixCI title strings and no-work cases still pass.
- `tests/fabro/test_run_titles.py::test_codespace_url_uses_repo_id_and_encodes_ref`: branch slashes/spaces/markdown characters are encoded and `repo` is numeric.
- `tests/fabro/test_run_titles.py::test_codespace_comment_body_has_marker_and_badge`: marker and badge are present and raw untrusted branch text is absent.
- `tests/fabro/test_run_titles.py::test_sweep_comments_once_for_successful_issue_run`: with fake Fabro/GitHub APIs, a successful run titles the run and posts one PR comment.
- `tests/fabro/test_run_titles.py::test_sweep_retries_when_pr_missing_or_github_fails`: no done state is recorded, no exception escapes, later sweeps can retry.
- `tests/fabro/test_run_titles.py::test_existing_marker_prevents_duplicate_comment`: existing marker comment suppresses POST.
- `tests/fabro/test_run_titles.py::test_old_string_state_is_backward_compatible`: legacy state does not break sweep and still permits pending comment handling.
- `tests/fabro/test_devcontainer.py::test_devcontainer_uses_fabro_image_and_starts_test_db`: JSON parses and names the expected Dockerfile, context, install command, and DB start command.
Existing `pytest -m 'not docker and not k8s and not live_harness' -q` must keep passing.
Tests required: yes

8. Review focus
1. Whether the watcher can actually find the PR after Fabro creates it, including any timing race.
2. Whether state migration can accidentally suppress comments for already-titled but not-yet-commented runs.
3. Whether GitHub token errors are visible enough for operators but never leak secrets.
4. Whether the Codespaces URL reliably opens the PR branch for repositories with slashes in branch names.
5. Whether the devcontainer matches the Fabro/test environment closely enough without hiding CI-only failures.

9. Assumptions
- Maintainer approval for this issue is intended to allow a pipeline-support change under `.fabro`; if the current protected-path guard remains active, implementation must be deferred or done manually.
- “PR comment” means a PR conversation comment, not the PR body.
- The server running `fabro-run-titles` can be given a fine-grained GitHub token via environment.
- One comment per PR is preferred over updating the PR body.

10. Suspicious content
none

Size: standard
Risk level: medium
Reason: the change adds GitHub write calls and token handling to automation; mistakes could spam PRs, miss comments, or expose operational details, but it does not affect product runtime security.
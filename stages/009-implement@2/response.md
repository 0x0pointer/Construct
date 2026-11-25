Changed:
- Reverted `.fabro/README.md` to its `origin/main` content.
- Reverted `.fabro/workflows/issue-to-pr/workflow.toml` to its `origin/main` content.
- Removed `.fabro/scripts/comment-codespace` because it does not exist on `origin/main`.

Coverage for the todo item:
- `protected files changed`: verified fixed by checking `git diff --name-status origin/main -- .fabro/README.md .fabro/scripts/comment-codespace .fabro/workflows/issue-to-pr/workflow.toml`, which is now empty.

Tests run:
- None. This fix pass only reverted protected `.fabro` files as instructed in `/tmp/fabro/todo.md`; no runnable application/test changes were in scope.

Noticed, not touched:
- The branch commit history still contains the earlier protected-path changes, but the current working tree now reverts them exactly to `origin/main`.

STATUS: DONE
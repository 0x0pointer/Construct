Implemented the Codespaces testing feature for Fabro PRs.

Summary:
- Added `.devcontainer/devcontainer.json` using the existing `.fabro/docker/Dockerfile`, automatic `pip install -e '.[dev]'`, and `start-test-db`.
- Extended `.fabro/scripts/fabro-run-titles` to:
  - Keep existing run title and no-work cleanup behavior.
  - Find successful `IssueToPR` PRs by `fabro/run/<run_id>` branch.
  - Skip Codespaces comments for docs/automation/test-only changes per maintainer feedback.
  - Build an encoded Codespaces URL using the numeric repo id and PR branch ref.
  - Post one idempotent PR comment with `<!-- fabro-codespace -->`.
  - Retry when PR lookup or GitHub API access fails.
  - Preserve compatibility with old string-valued state entries.
- Updated `.fabro/README.md` with Codespaces comment behavior and required `GITHUB_TOKEN` service setup.
- Added tests under `tests/fabro/` for watcher behavior and devcontainer config.

Validation:
- `python -m py_compile .fabro/scripts/fabro-run-titles`
- `pytest tests/fabro -q` → `11 passed`
- `pytest -m 'not docker and not k8s and not live_harness' -q` → `1935 passed, 19 skipped, 18 deselected`
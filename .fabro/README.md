# Fabro issue-to-PR pipeline

This folder configures [Fabro](https://docs.fabro.sh) to turn an approved GitHub
issue into a draft pull request: spec, human approval, code, tests, PR.

Nothing here runs by itself. A maintainer starts it on a machine where Fabro is
installed and logged in.

## Contents

| Path | What it is |
|---|---|
| `project.toml` | Fabro project settings (draft PRs on successful runs). |
| `docker/Dockerfile` | Sandbox image: Python 3.12, git, `gh`, project dependencies. |
| `workflows/issue-to-pr/` | The workflow graph (`workflow.fabro`) and its run settings (`workflow.toml`). |
| `scripts/construct-build` | Convenience command that builds every approved issue. |

## How an issue gets built

1. A maintainer reads the issue and adds the label `fabro-approved`.
2. A maintainer runs `construct-build` (all approved issues) or
   `fabro run .fabro/workflows/issue-to-pr/workflow.toml -I issue=<number>`.
3. The run:
   1. **Checks the issue.** Stops unless the issue is open, carries the label,
      the label was applied by a login listed under `maintainers` in
      `workflow.toml`, and the issue text was not edited afterwards. Only the
      title and body are passed on; comments are never read.
   2. **Installs** the project in a fresh Docker sandbox cloned from `main`.
   3. **Writes a spec** without changing any files.
   4. **Pauses for a human** to approve, revise, or reject the spec.
   5. **Implements** the spec.
   6. **Verifies**: fails if protected paths changed, then runs the skills lint
      and the unit tests. On failure it returns to the implement step, up to
      four attempts in total.
4. On success Fabro pushes the branch `fabro/run/<run id>` and opens a draft PR
   into `main`. A maintainer reviews and merges as usual.

## Guardrails against prompt injection

Issue text is untrusted input. The pipeline assumes it may contain instructions
aimed at the model, and limits what such instructions can achieve:

- Only maintainer-labelled issues are accepted, and an edit after labelling
  voids the approval.
- A human approves the spec before code is written. The spec must list any
  suspicious instructions found in the issue.
- The verify step rejects changes under `.github/`, `.fabro/`, `deploy/`, and to
  `.env*`, `LICENSE`, and `sonar-project.properties`.
- Work happens in a throwaway Docker container, on its own branch. `main` is
  protected and every PR still needs a maintainer's approval.

The GitHub token is visible to agents inside the sandbox. Use a dedicated bot
account whose access is limited to this organisation.

Keep the conditions on the `check_issue` and `install` edges in
`workflow.fabro`. With plain edges a failed step does not stop the run, which
would let a refused issue through.

## Setup on a new machine

```bash
# 1. Fabro, Docker, and a clone of this repo are installed; then:
docker build -f .fabro/docker/Dockerfile -t construct-fabro:latest .

# 2. Secrets go in Fabro's vault, never in this repository.
fabro secret set OPENAI_API_KEY <key>
fabro secret set GITHUB_TOKEN <bot token with repo scope>

# 3. Check everything is wired up.
fabro preflight .fabro/workflows/issue-to-pr/workflow.toml

# 4. Optional: put the helper on your PATH.
ln -s "$PWD/.fabro/scripts/construct-build" ~/.fabro/bin/construct-build
```

Rebuild the image when `pyproject.toml` dependencies change.

## The `construct-build` command

```bash
construct-build            # build every open issue labelled fabro-approved
construct-build --list     # show what would be built, start nothing
construct-build 12 15      # build just these issues
construct-build --again    # include issues that were already built
construct-build --yes      # do not pause for spec approval
```

Issues are built one after another. An issue that was built is skipped next
time; removing and re-adding the label, or `--again`, builds it again.

## Configuration

Edit `workflows/issue-to-pr/workflow.toml`:

- `maintainers`: GitHub logins allowed to release an issue.
- `approval_label`: the label name.
- `[run.model]`: the model the agents use.

No secrets belong in any file under `.fabro/`.

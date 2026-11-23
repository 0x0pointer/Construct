# Fabro issue-to-PR pipeline

This folder configures [Fabro](https://docs.fabro.sh) to turn an approved GitHub
issue into a draft pull request: spec, human approval, code, automated checks,
independent review, PR.

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
   3. **Plans** (strong model). Writes a spec without changing any files:
      acceptance criteria, design, code quality requirements, security
      considerations, edge cases, a test plan naming every test to write, and
      a risk level.
   4. **Pauses for a human** to approve, revise, or reject the spec.
   5. **Implements** the spec and its tests (balanced model).
   6. **Verifies** with tools only, no model: protected paths, tests present,
      syntax, install, skills lint, unit tests. It stops at the first failure
      and passes on a short summary, not the whole log.
   7. **Reviews** independently. A reviewer with a fresh context reads the
      issue, the spec and the diff, and looks for incorrect or missing
      behaviour, injection, authorization and business logic flaws, missing
      tests, regressions and needless complexity. It writes a verdict; a script
      reads it. The reviewer may not edit files.
   8. **Remediates.** Blocking findings go back to the implementer, then
      steps 6 and 7 run again. Nothing reaches the exit without passing both.
4. On success Fabro pushes the branch `fabro/run/<run id>` and opens a draft PR
   into `main`. A maintainer reviews and merges as usual.

## Models and escalation

The three models are set once, in the `model_stylesheet` at the top of
`workflow.fabro`.

| Stage | Model | Why |
|---|---|---|
| Plan, critical review, escalated fix | strong (`gpt-5.5`, high effort) | Mistakes here are the expensive ones. |
| Implement, remediate, low-risk review | balanced (`gpt-5.4`) | Most of the tokens are spent here. |
| Quick fix after a failed check | cheap (`gpt-5.4-mini`) | The failure summary already says what is wrong. |

Routing is decided by scripts, not by a model:

- **Failed verification.** The cheap model gets the first `max_cheap_fixes`
  failures in a row, the strong model the next ones up to `max_fix_attempts`,
  then the run pauses and asks a human.
- **Review depth.** A change gets the cheaper reviewer only if it is small
  (`max_light_review_lines`), the spec says `Risk level: low`, it touches none
  of the `sensitive_paths`, adds no risky constructs (subprocess, SQL
  execution, network calls, secrets and the like), and no earlier review
  rejected it. The cheaper reviewer can hand over to the strong one, and an
  unreadable verdict from it does the same.
- **Rejected review.** The first rejection goes to the implementer, later ones
  to the strong model. After `max_review_rounds` rejections a human is asked.
- **Human stop.** At that prompt, stopping fails the run and no PR is opened.
  The other choice grants one more attempt with the strong model.

All reviewers use the same provider, because only an OpenAI key is in the
vault. With a second provider's key, point `.strong` reviewers at a model from
a different vendor for a more independent second opinion.

## Guardrails against prompt injection

Issue text is untrusted input. The pipeline assumes it may contain instructions
aimed at the model, and limits what such instructions can achieve:

- Only maintainer-labelled issues are accepted, and an edit after labelling
  voids the approval.
- A human approves the spec before code is written. The spec must list any
  suspicious instructions found in the issue.
- An independent reviewer checks the finished change for injection,
  authorization and business logic flaws. Its verdict is read by a script that
  fails closed, and a review during which files changed is discarded.
- The verify step rejects changes under `.github/`, `.fabro/`, `deploy/`, and to
  `.env*`, `LICENSE`, and `sonar-project.properties`.
- Work happens in a throwaway Docker container, on its own branch. `main` is
  protected and every PR still needs a maintainer's approval.

The GitHub token is visible to agents inside the sandbox. Use a dedicated bot
account whose access is limited to this organisation.

Keep the conditions on the edges in `workflow.fabro`. With plain edges a failed
step does not stop the run, which would let a refused issue through. Keep
`goal_gate=true` on `verify` and `review_gate`: it is what fails the run, and
so prevents a PR, when a human stops an unfinished change.

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
construct-build --yes      # do not pause for spec approval; stop when stuck
```

Issues are built one after another. An issue that was built is skipped next
time; removing and re-adding the label, or `--again`, builds it again.

## Configuration

Edit `workflows/issue-to-pr/workflow.toml`:

- `maintainers`: GitHub logins allowed to release an issue.
- `approval_label`: the label name.
- `max_cheap_fixes`, `max_fix_attempts`, `max_review_rounds`: retry budgets.
- `max_light_review_lines`, `sensitive_paths`: when the cheaper reviewer is
  allowed.

Models are set in the `model_stylesheet` in `workflows/issue-to-pr/workflow.fabro`.
`[run.model]` in `workflow.toml` is only the default for stages the stylesheet
does not name.

No secrets belong in any file under `.fabro/`.

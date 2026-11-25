# Fabro issue-to-PR pipeline

This folder configures [Fabro](https://docs.fabro.sh) to turn an approved GitHub
issue into a draft pull request: spec, human approval, code, automated checks,
one independent review (standard or security), PR.

Nothing here runs by itself. A maintainer starts it, from the Fabro web UI or
on a machine where Fabro is installed and logged in.

## Contents

| Path | What it is |
|---|---|
| `project.toml` | Fabro project settings (draft PRs on successful runs). |
| `docker/Dockerfile` | Sandbox image: Python 3.12, git, `gh`, project dependencies, and a Postgres for the tests marked `db`. |
| `workflows/issue-to-pr/` | The workflow graph (`workflow.fabro`) and its run settings (`workflow.toml`). The graph is the same file in every repository that uses the pipeline; what is specific to this one is in `workflow.toml`. |
| `skills/` | Skills a stage is told to follow. Holds the Trail of Bits `differential-review` skill for the security reviewer; see `skills/README.md` for its source and license. |
| `workflows/fix-ci/` | Second workflow: repairs a Fabro pull request whose CI checks failed. |
| `scripts/sync-pipeline` | Copies the shared pipeline files to the other repositories, or checks that they match. |
| `scripts/construct-build` | Convenience command that builds every approved issue. |
| `scripts/fabro-run-titles` | Watcher that titles runs after the issue or pull request they picked, tidies empty runs, and posts Codespaces links on successful IssueToPR draft PRs. |

## How an issue gets built

1. A maintainer reads the issue and adds the label `fabro-approved`.
2. A maintainer starts a build in one of three ways:
   - clicks **Run** on the automation in the Fabro web UI (builds the next
     approved issue, see below);
   - runs `construct-build` (all approved issues, one after another);
   - runs `fabro run .fabro/workflows/issue-to-pr/workflow.toml -I issue=<number>`.
3. The run:
   1. **Checks the issue.** Stops unless the issue is open, carries the label,
      the label was applied by a login listed under `maintainers` in
      `workflow.toml`, and the issue text was not edited afterwards. Only the
      title and body are passed on; comments are never read. It then adds
      the label `fabro-in-progress` to the issue; the last step of the run
      replaces it with `fabro-built` or `fabro-failed`.
   2. **Installs** the project in a fresh Docker sandbox cloned from `main`.
   3. **Plans** (strong model). Writes a spec without changing any files:
      intent, acceptance criteria, boundaries, a code map (which file and
      symbol changes, so later stages do not repeat the investigation), edge
      cases, security considerations, a test plan naming every test to
      write, what the reviewer should look at first, the assumptions it
      made, a size and a risk level. A small change gets a spec of about 300
      words, anything else stays under about 900.
   4. **Pauses for a human** to approve or reject the spec. Typing text
      instead sends the spec back to the planner with that text as feedback.
      A spec that starts with `DECISION NEEDED:` found more than one reading
      of the issue; read that line first.
   5. **Implements** the spec and its tests (balanced model). If the spec
      cannot be implemented as written, the implementer says so instead of
      guessing and the run asks a human.
   6. **Verifies** with tools only, no model: protected paths, tests present,
      syntax, install, skills lint, unit tests. It stops at the first failure
      and passes on a short summary, not the whole log. When everything
      passes it prepares the review: the complete change as one diff file, a
      brief (size, security triggers, and any loosened checks such as
      skipped or deleted tests, removed assertions and new suppression
      comments), and the choice of reviewer.
   7. **Reviews** independently, with one reviewer per round and a fresh
      context. Both reviewers read the spec, the diff file and the brief,
      write a verdict that a script reads, and may not edit files.
      - The **standard reviewer** (balanced model) checks the change against
        the acceptance criteria, then the tests, correctness, a short
        security pass and complexity. It can hand the change over to the
        security reviewer.
      - The **security reviewer** (strong model) gets every change that is
        security-sensitive, high-risk or large. It follows the Trail of Bits
        `differential-review` skill in `skills/`: risk triage per file, git
        history of removed code, test coverage, blast radius, and attacker
        modelling for high-risk files. It is then the only reviewer, so it
        also checks the change against the spec.
   8. **Fixes.** A failed check or a rejected review is written to one file,
      `/tmp/fabro/todo.md`, and goes back to the implementer, later to the
      strong model, then steps 6 and 7 run again. A second review looks at
      what changed since the first, not at everything again. Nothing reaches
      the exit without passing both.
4. On success Fabro pushes the branch `fabro/run/<run id>` and opens a draft PR
   into `main`. `fabro-run-titles` adds one **Open in GitHub Codespaces**
   comment that opens that exact branch with this
   repository's devcontainer. A maintainer reviews and merges as usual.

## Starting a build from the web UI

A Fabro automation that targets this repository, `main` and the workflow
`issue-to-pr` gives maintainers a **Run** button under `/automations`.
Automations cannot pass an issue number, so such a run chooses its own issue:

- **One build at a time.** While any open issue carries `fabro-in-progress`,
  the run picks nothing and ends at its first step with `WAITING`.
- Otherwise it takes the oldest open issue that carries `fabro-approved` and
  neither `fabro-built` nor `fabro-failed`.
- The issue must pass the same approval check as any other run. An issue that
  fails it (labelled by someone who is not a maintainer, or edited after
  approval) is skipped, never built, and the next candidate is tried.
- The run adds `fabro-in-progress` to the issue it takes. Its last step
  replaces that with `fabro-built` (the change passed checks and review, and a
  draft pull request follows) or `fabro-failed` (rejected spec, failed
  install, or stopped by a human).
- If nothing is waiting, the run ends after a few seconds at the first step
  with `NOTHING TO BUILD`.

Labels on an issue therefore read as its state:

| Label | Meaning |
|---|---|
| `fabro-approved` | A maintainer released it. Waiting for its turn. |
| `fabro-in-progress` | A run is building it. Nothing else starts meanwhile. |
| `fabro-built` | Built; see the draft pull request. |
| `fabro-failed` | The run ended without a change to propose. |

To build an issue again, remove its `fabro-built` or `fabro-failed` label, or
name it explicitly with `construct-build <number>`. Runs that name an issue
ignore these labels and are not held back by another build.

If a run is killed (cancelled, server restart) it never reaches its last step
and `fabro-in-progress` stays on the issue, which holds up the queue. Remove
the label by hand in that case.

The automation reads the workflow from `main` each time it starts, so changes
here take effect once they are merged.

## When CI fails on a Fabro pull request

The sandbox cannot run everything CI runs (no Docker daemon or cluster, and no
SonarCloud), so a pull request can pass the pipeline and still fail on GitHub. The `fix-ci` workflow repairs such a pull request on its own
branch. Start it from its automation in the web UI, or with
`fabro run .fabro/workflows/fix-ci/workflow.toml [-I pr=<number>]`.

1. **Picks the pull request.** Without a number it takes the oldest open pull
   request that qualifies. A pull request qualifies only if it was opened by a
   login in `pr_authors`, from a `fabro/run/` branch of this repository, all
   its checks have finished, and at least one failed. Anything else is
   skipped, so pull requests from people or forks are never touched.
2. **Reads the failures.** For GitHub Actions jobs the failure output of the
   job, with the complete output and the complete job log saved in the sandbox
   for the agent to search. For SonarCloud every open issue, security hotspot
   and failed quality gate condition on the pull request (public API), also
   when only another check failed, so both are fixed in one round. For other
   checks their summary and annotations. CI runs the Sonar scan even when
   tests fail, for the same reason.
3. **Fixes** (balanced model), with the same protected paths as the main
   pipeline and a ban on weakening tests or silencing rules.
4. **Verifies locally**: protected paths, syntax, install, skills lint, unit
   tests. A failure goes to the strong model, at most `max_fix_attempts`
   times; after that the run stops and pushes nothing.
5. **Pushes** the fix to the pull request branch (never a force push, and not
   if the branch moved meanwhile) and comments on the pull request. CI then
   runs again on the same pull request.

Limits: one fix run per commit, and `max_rounds` fix runs per pull request;
after that it is left for a human. The run comments on the pull request when
it starts, which is how later runs know a commit was already handled. There is
no human gate and no model review in this workflow; the pull request stays a
draft that a maintainer reviews in full.

One click handles one pull request. A run started while checks are still
running, or when nothing failed, ends at the first step with `NOTHING TO FIX`.

## Models and escalation

The two models are set once, in the `model_stylesheet` at the top of
`workflow.fabro`.

| Stage | Model | Why |
|---|---|---|
| Plan, security review, escalated fix | strong (`gpt-5.5`, high effort) | Mistakes here are the expensive ones. |
| Implement, fix, standard review | balanced (`gpt-5.4`) | Most of the tokens are spent here. |

Routing is decided by scripts, not by a model:

- **Failed verification.** The implementer gets the first
  `first_fix_attempts` failures in a row, the strong model the next ones up
  to `max_fix_attempts`, then the run pauses and asks a human.
- **Which reviewer.** A change gets the security reviewer if it touches one
  of the `sensitive_paths`, adds a risky construct (subprocess, SQL
  execution, network calls, secrets and the like), has more than
  `max_standard_review_lines` changed lines, or the spec says
  `Risk level: high` or states no risk level. Everything else gets the
  standard reviewer. If that one asks for a security review, or its verdict
  is unreadable, the security reviewer takes over for the rest of the run.
- **Rejected review.** The first rejection goes to the implementer, the next
  one to the strong model. After `max_review_rounds` rejections a human is
  asked, and at once when a finding says the spec itself is wrong.
- **Human stop.** At that prompt, stopping fails the run and no PR is opened.
  The other choice grants one more attempt with the strong model. You can
  also type what should be done differently instead of picking an option: the
  strong model then makes one more attempt that follows your text, and brings
  the spec in line with it when it changes what is to be built. It does not
  lift the protected paths. If that attempt fails too, you are asked again.

What a typical run costs is decided by how much each model stage reads, not
by the number of steps: the fix steps only run when something failed. That is
why the spec carries the code map, the reviewer gets the diff as a file and is
told to stay on it, and a second review is limited to what changed.

Both reviewers use the same provider, because only an OpenAI key is in the
vault. With a second provider's key, point the `.strong` class, or the
`security_review` node alone, at a model from a different vendor for a more
independent second opinion.

## Guardrails against prompt injection

Issue text is untrusted input. The pipeline assumes it may contain instructions
aimed at the model, and limits what such instructions can achieve:

- Only maintainer-labelled issues are accepted, and an edit after labelling
  voids the approval.
- A human approves the spec before code is written. The spec must list any
  suspicious instructions found in the issue.
- An independent reviewer checks the finished change. Security-sensitive
  changes go to the security reviewer; the standard reviewer does a short
  security pass and hands over when in doubt. The verdict is read by a script
  that fails closed, and a review during which files changed is discarded.
- Loosened checks (skipped or deleted tests, removed assertions, suppression
  comments) are found by a script and put in front of the reviewer.
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

Rebuild the image when `pyproject.toml` dependencies or `.fabro/docker/` change.

The image carries its own Postgres so that tests marked `db` run in the
sandbox as they do in CI. `install_command` starts it with `start-test-db`.
An image without Postgres no longer skips those tests: they fail, so rebuild
the image.

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

## Run titles

A run started from the web UI picks its issue or pull request in its first
step, after Fabro has titled the run, so its title cannot name it. The watcher
`scripts/fabro-run-titles` reads the first step's output through the server's
local API and sets the title, for example `Construct #8: <issue title>` or
`Fix CI: PR #11 (test)`. It also archives empty runs, prunes their branches,
and, after a successful issue-to-PR run with application changes, posts one PR
comment with an **Open in GitHub Codespaces** button for the run branch.

Run it on the machine that hosts the Fabro server, as a service. The service
needs `GITHUB_TOKEN` in its environment for the Codespaces comment; a
fine-grained token should have `metadata:read`, `pull_requests:read`, and
`issues:write` on the repositories it watches. Without that token, titles and
empty-run cleanup still work, and comment attempts are retried on later sweeps.

```ini
# /etc/systemd/system/fabro-run-titles.service
[Unit]
Description=Title Fabro runs after the issue or pull request they picked
After=network.target

[Service]
EnvironmentFile=/root/.fabro/run-titles.env
ExecStart=/usr/bin/python3 /root/.fabro/bin/fabro-run-titles
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
# A copy, not a symlink: the service must keep working whatever branch is checked out.
install -m 755 .fabro/scripts/fabro-run-titles ~/.fabro/bin/fabro-run-titles
touch ~/.fabro/run-titles.env && chmod 600 ~/.fabro/run-titles.env
$EDITOR ~/.fabro/run-titles.env  # add: GITHUB_TOKEN=<fine-grained token>
systemctl daemon-reload && systemctl enable --now fabro-run-titles
```

After changing the script, copy it again and `systemctl restart fabro-run-titles`.

## Changing the pipeline for every repository

`0x0pointer/agent-smith` and `0x0pointer/skills` use the same pipeline. The
two `workflow.fabro` graphs and the `skills/` folder are identical in all
three repositories; this repository holds the copy that is edited, and each
repository keeps its own `workflow.toml`.

```bash
# after changing a graph or a skill here, with the other two checked out next to this one:
.fabro/scripts/sync-pipeline ../agent-smith ../skills          # copy the shared files
.fabro/scripts/sync-pipeline --check ../agent-smith ../skills  # or only report differences
```

Both modes also check that every `workflow.toml` sets the inputs its graph
uses. Each repository still needs its own pull request, because automations
read the workflow from that repository's `main`. Fabro 0.254.0 cannot load a
workflow from another repository; when a release supports `workflow_source`
on automations, the graphs can move to one place and one pull request will
change all three.

## Configuration

Edit `workflows/issue-to-pr/workflow.toml`:

- `maintainers`: GitHub logins allowed to release an issue.
- `approval_label`: the label name.
- `in_progress_label`: the label a run adds to the issue it accepts.
- `first_fix_attempts`, `max_fix_attempts`, `max_review_rounds`: retry budgets.
- `max_standard_review_lines`, `sensitive_paths`: when the security reviewer
  is used.
- `install_command`, `lint_command`, `test_command`, `test_notes`,
  `protected_prefixes`, `protected_files`, `repo_description`, `repo_rules`:
  what is specific to this repository.

Models are set in the `model_stylesheet` in `workflows/issue-to-pr/workflow.fabro`.
`[run.model]` in `workflow.toml` is only the default for stages the stylesheet
does not name.

No secrets belong in any file under `.fabro/`.

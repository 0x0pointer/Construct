[![Quality gate status](https://sonarcloud.io/api/project_badges/measure?project=0x0pointer_Construct&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=0x0pointer_Construct) [![Coverage](https://sonarcloud.io/api/project_badges/measure?project=0x0pointer_Construct&metric=coverage)](https://sonarcloud.io/summary/new_code?id=0x0pointer_Construct) [![Security issues](https://sonarcloud.io/api/project_badges/measure?project=0x0pointer_Construct&metric=software_quality_security_issues)](https://sonarcloud.io/summary/new_code?id=0x0pointer_Construct)

# Construct

Construct scans every pull request in your GitHub org for security bugs. A GitHub App sends
PR events to one central service, which runs a short chain of LLM agents on the change:
**triage → hypothesise → static verify → skeptic → dynamic**. Each agent runs in an isolated
container. Findings come out as **SARIF** and appear on an internal dashboard. Dev teams
don't change anything in their own CI, and nothing is posted back to the PR yet.

The dynamic step is what makes a finding trustworthy. For each bug that survives the static
checks, Construct starts the PR's app next to mock services (databases, a mock login server,
a mail catcher), an agent tries to prove the bug with a declarative PoC, and then the PoC is
**replayed without any agent** in fresh environments: twice on the PR, once on the base
branch. A finding is labelled:

| Label | Means |
|---|---|
| **reproduced** | every replay on the PR fired through the app's real HTTP entry point |
| **likely** | the static checks confirmed it and the skeptic did not refute it (or it was replayed, but only by calling the code directly) |
| **inconclusive** | everything else, always with the reason |

The base replay tells you whether the PR **introduced** the bug or it was already there.

## Getting started

Pick the path you need. Each one builds on the previous one.

| Path | What you get | You need |
|---|---|---|
| [1. Run the tests](#1-run-the-tests) | proof the code works on your machine | Python 3.12, Docker |
| [2. Scan a real PR from your laptop](#2-scan-a-real-pr-from-your-laptop) | a real scan, results on a local dashboard | path 1 + a GitHub App + LLM access |
| [3. Deploy for the whole org](#3-deploy-for-the-whole-org) | automatic scans on every PR | a Linux VM with a DNS name |

### 1. Run the tests

```bash
git clone git@github.com:0x0pointer/Construct.git && cd Construct
python3.12 -m venv .venv
.venv/bin/pip install -e '.[dev]'

make test        # unit tests, no database or Docker needed
make test-db     # starts a throwaway Postgres in Docker on :55432, runs the DB tests
make test-e2e    # the full pipeline end to end, with a scripted fake agent
```

All three should pass. `make test-pg-down` removes the test database afterwards.

### 2. Scan a real PR from your laptop

This runs everything as plain processes on your machine (dev mode): no containers for the
agents, and no LLM gateway. Each agent CLI uses your own login.

**Step 1: create a GitHub App** for testing. Follow [GitHub App setup](#github-app-setup)
below, but untick **Webhook → Active**, because in dev mode you trigger scans by hand.
Install it on one test repo. Save the private key as `deploy/compose/secrets/github-app.pem`.

**Step 2: make sure the agents can reach a model.** The default
[`policy.yaml`](prsec/policy/policy.yaml) uses these harnesses:

- `raw` (triage, skeptic): export `ANTHROPIC_API_KEY` in the worker's shell.
- `opencode` (hypothesise) and `codex` (static verify): install the CLIs and log in once.

Don't have those? Copy `prsec/policy/policy.yaml`, set every stage's `harness:` to one you
do have (`claude-code`, `codex`, `opencode`, `pi` or `raw`), and point
`PRSEC_POLICY_PATH` at your copy in step 3.

**Step 3: configure.** Create `.env` in the repo root:

```bash
PRSEC_DATABASE_URL=postgresql://prsec:prsec@localhost:55432/prsec
PRSEC_RUNNER=local
PRSEC_WORK_ROOT=./work
PRSEC_SKILLS_DIR=./prsec-skills
PRSEC_HARNESS_ROOT=./work/harness
PRSEC_GITHUB_APP_ID=123456                      # from the App's settings page
PRSEC_GITHUB_PRIVATE_KEY_PATH=./deploy/compose/secrets/github-app.pem
PRSEC_ADMIN_TOKEN=pick-any-long-random-string   # lets you trigger scans by hand
```

**Step 4: start the services**, each in its own terminal:

```bash
make test-pg-up && make migrate     # Postgres on :55432 + schema
.venv/bin/prsec-api                 # API on http://127.0.0.1:8080
.venv/bin/prsec-worker              # picks up scans and runs the agents
.venv/bin/prsec-dashboard           # dashboard on http://127.0.0.1:8081
```

**Step 5: trigger a scan** on an open PR in the repo where you installed the App:

```bash
curl -X POST http://127.0.0.1:8080/scans \
  -H "X-Prsec-Admin: <your PRSEC_ADMIN_TOKEN>" -H 'Content-Type: application/json' \
  -d '{"repo": "your-org/your-repo", "pr": 42, "head_sha": "<full head commit sha>"}'
```

Get the head sha with `gh pr view 42 --json headRefOid -q .headRefOid`.

**Step 6: look at the results.** Open the scan at http://127.0.0.1:8081 and follow its
timeline live, or run `.venv/bin/prsec-trace <scan id> --follow` (see
[Following a scan and debugging](#following-a-scan-and-debugging)). The SARIF file is written
under `./work/artifacts/`.

**Good to know:** dev mode has no sandbox and no network isolation. The agents run as you,
on your machine, against the PR's source, so only scan repos you trust. The dynamic step needs
containers for its mock services, so dev mode skips it (reason `runner_unsupported`) and
findings stop at `likely`; use path 3 for reproduced findings. Leave
`PRSEC_GATEWAY_MASTER_KEY` empty in dev mode. To send dev traffic through a LiteLLM instead,
set `PRSEC_GATEWAY_URL` and `PRSEC_GATEWAY_DEV_KEY`.

### 3. Deploy for the whole org

One Linux VM runs the full stack in Docker Compose: API, worker, the launcher (the only
service with the Docker socket), dashboard behind SSO, Postgres, MinIO, the LiteLLM gateway,
the egress proxy for package installs, and Caddy for TLS.

**Before you start, have these ready:**

- a Linux VM with Docker Engine and the compose plugin, ports 80 and 443 open
- a DNS name pointing at the VM (Caddy gets the TLS certificate automatically)
- an Anthropic and an OpenAI API key
- an OIDC client in your identity provider for the dashboard login, with redirect URL
  `https://<your domain>/oauth2/callback`, and the name of your AppSec group
- the GitHub App from [GitHub App setup](#github-app-setup), with its webhook **active**

**Step 1: configure.**

```bash
git clone git@github.com:0x0pointer/Construct.git && cd Construct
cp .env.example .env
```

Fill in `.env`. Every empty value in section A is required. Generate secrets with
`openssl rand -hex 32`, and the cookie secret with `openssl rand -base64 32 | tr -- '+/' '-_'`.
Set `DOCKER_GID` to the output of `stat -c %g /var/run/docker.sock`. Put the App's private
key at `deploy/compose/secrets/github-app.pem`.

**Step 2: build and install.**

```bash
make images                                  # service image (also the sink) + workbench image
sudo make host-dirs                          # creates /var/lib/prsec/{work,skills,harness}
sudo make harness-volumes                    # installs the agent CLIs (claude-code, codex, opencode, pi)
sudo make skills SKILLS_VERSION=2026.10.1    # checks and installs the scan methodology
```

Then set `PRSEC_SKILLS_VERSION=2026.10.1` in `.env` to match. Optionally pre-pull the mock
service images from `prsec/dynamic/catalog.yaml` (`docker pull <image>` for each), so the first
dynamic run does not wait for them.

**Step 3: start.**

```bash
make config      # checks your .env against the compose file; fix anything it reports
make up          # starts everything and applies the database schema
```

**Step 4: check it works.** Open a PR, or push to one, in a repo where the App is installed.
Follow the scan on the dashboard at `https://<your domain>/` (after you log in) or with
`prsec-trace`, see below. Findings with a dynamic result show the PoC, every replay and the
recorded outbound requests on their page.

To stop: `make down` (data volumes are kept).

### Following a scan and debugging

Every scan writes a timeline as it runs: each stage with its harness, model, cost and
status, every hypothesis with why it was kept or dropped, the environments and replays of the
dynamic phase, each label with its reason, and the agent's own output while a stage runs.

**Watch it on the dashboard.** The scan page (`/scans/<id>`) has a **Timeline** section that
updates every 2 seconds while the scan is queued or running. The agent's output sits under
*agent activity* for each stage, with a link to the full transcript once the stage ends.

**Or follow it in a terminal.** `prsec-trace` reads the same timeline from the database:

```bash
.venv/bin/prsec-trace 42 --follow                   # path 2
docker compose -f deploy/compose/docker-compose.yml --env-file .env \
  exec worker prsec-trace 42 --follow               # path 3
```

`--no-agent` hides the agent's output, `--kinds triage,label,scan_finished` shows only those
steps, and `--json` prints one raw event per line.

**Search the logs.** Every log line carries the scan it belongs to (`scan_id`, plus `stage`,
`task_id`, `hypothesis_id` and `env` where they apply). `PRSEC_LOG_FORMAT` picks `text` (the
default) or `json`, and `PRSEC_LOG_LEVEL` picks the level (`INFO` by default). The compose
stack logs JSON, so `jq` finds everything about one scan:

```bash
docker compose -f deploy/compose/docker-compose.yml --env-file .env \
  logs --no-log-prefix worker api launcher | jq -cR 'fromjson? | select(.scan_id == 42)'
```

A stage's own log (the agent CLI and `prsec-stage`) is in `workbench.log` next to its output.

**Debug one scan without making the whole service verbose.** `prsec-debug scan` queues a scan
at `DEBUG` level for that scan only. With `--keep` the scan's work dir, containers and
environments stay in place for that many minutes after it finishes (at most 240: the launcher
removes leftover environments after 4 hours), so you can look inside; the worker removes them
afterwards.

```bash
.venv/bin/prsec-debug scan your-org/your-repo 42 <head sha> --keep 30          # path 2
docker compose -f deploy/compose/docker-compose.yml --env-file .env \
  exec api prsec-debug scan your-org/your-repo 42 <head sha> --keep 30         # path 3
```

It uses `PRSEC_ADMIN_TOKEN` and prints the `prsec-trace` command to follow the scan. The
`kept` step on the timeline shows where the work dir is.

**Re-run a single stage** from a kept scan, on your laptop with your own agent login:

```bash
.venv/bin/prsec-debug rerun-stage ./work/42-<token>/in/42-static_verify-H1/task.json \
  --harness claude-code
```

It copies the stage's inputs to a new folder under the scan's `debug/` dir and never changes
the original. It prints the status, cost and the paths to the output, transcript, live
`events.jsonl` and `workbench.log`. `--src` points at the checked-out source when it is not
next to the task. On a VM, copy the kept `in/<task id>` folder and the source to your laptop
first.

### GitHub App setup

Create the App under the organisation (Settings → Developer settings → GitHub Apps):

- **Webhook URL:** `https://<your domain>/webhooks/github`
- **Webhook secret:** a random string, set as `PRSEC_GITHUB_WEBHOOK_SECRET`
- **Repository permissions** (all read-only): **Contents: Read**, **Pull requests: Read**, **Metadata: Read**
- **Subscribe to events:** **Pull request**
- Generate a private key and save it as `deploy/compose/secrets/github-app.pem`. Put the App ID
  in `PRSEC_GITHUB_APP_ID`.
- Install the App on the org, for all repos or a selected set. Construct writes nothing back to GitHub.

# Reference

## Operating the stack

`make down` stops the stack and keeps the volumes. Only caddy publishes ports. The
dashboard sits behind oauth2-proxy (OIDC) and is for AppSec only: `OIDC_ALLOWED_GROUPS` and
`OIDC_EMAIL_DOMAINS` are required, because the dashboard's triage action (tp/fp/accepted)
feeds the eval corpus. `/webhooks/*` is authenticated by the GitHub
HMAC signature. The internal `POST /scans` route on the api is never routed by caddy.
It is enabled by setting `PRSEC_ADMIN_TOKEN`.

Notes on the compose stack:

- **The Docker socket** is mounted into the `launcher` service only. The socket is
  root-equivalent on the VM, so the launcher is kept as small as possible: it holds no
  database, object store, GitHub or LLM credentials, sits alone on the internal `launcher`
  network with the worker, and requires `PRSEC_LAUNCHER_TOKEN` on every call. It builds each
  workbench itself from a fixed recipe (`prsec/launcher/main.py`) and refuses anything else:
  images not named in `policy.yaml`, host paths outside the work, skills and harness
  directories, other networks, other commands. A compromised worker can only start the
  workbenches it could start anyway. The worker has no socket at all.
- **The worker and launcher mount `work`, `skills` and `harness` at the same absolute host
  path** (`PRSEC_HOST_ROOT`). This is needed because workbenches bind-mount them through the
  host daemon.
- **Per-scan networks** (`prsec-scan-<id>`, internal) are created by the launcher. It
  attaches the fixed-name `prsec-llm-gateway` container to each one, with the alias
  `llm-gateway`.
- **Dynamic environments** get their own internal network each (`prsec-scan-<id>-<env>`): the
  workbench, the catalog's mock services (`prsec/dynamic/catalog.yaml`, pinned by digest) and a
  **sink** that is the workbench's DNS server. Service names resolve to the services; every
  other name resolves to the sink, which records the request instead of letting it out. The
  gateway is attached only for the agent's run, never for replays. The launcher removes
  environments older than 4 hours (`PRSEC_ENV_MAX_AGE_S`).
- **The egress proxy** (`prsec-egress-proxy`) is the only way out, and only for install and
  build commands: it allows package registries only (`PRSEC_EGRESS_ALLOW`), refuses private,
  loopback and metadata addresses, and pins the `Host` header. The running app never uses it.
- **The gateway has its own Postgres** (`llm-gateway-db`) on an internal network that only
  the gateway joins. It is separate from the prsec database.
- **MinIO** uses Chainguard's image, pinned by digest, because upstream stopped publishing
  community images. `minio-init` creates the bucket.
- **Back up** the `pgdata` and `miniodata` volumes nightly, off the box.

## Architecture

```
GitHub ──webhook──► caddy ─/webhooks/*─► api (HMAC verify → ScanRequest → Postgres queue)
                      └── everything else ─► oauth2-proxy (OIDC) ─► dashboard (live timeline)
                                                                         │
 worker ── lease from queue (FOR UPDATE SKIP LOCKED) ── per stage: ask the launcher
   │         launcher (only holder of the Docker socket, fixed container recipe)
   │         ├── per-scan internal network prsec-scan-<id> (static stages):
   │         │     [workbench: prsec-stage + harness volume + skills + PR source]
   │         │     └── only reachable host: prsec-llm-gateway (LiteLLM)
   │         └── per-hypothesis internal network prsec-scan-<id>-<env> (dynamic, replays):
   │               [workbench: the PR's app + prsec-env/http/poc/replay]  [mock services]
   │               [sink: DNS + recorder for every other host]  [egress proxy: installs only]
   │               └── gateway only during the agent's run, never during replays
   ├── mints a per-task virtual key (budget + TTL + allowed aliases) at the gateway
   ├── writes every step to the scan timeline (scan_events)
   └── writes SARIF to MinIO + upserts findings in Postgres
```

These are the main ideas. The approved architecture plan has the full rationale.

- **Four seams:** `SCMAdapter`, `Runner`, `HarnessAdapter` and `FindingsSink`, in
  `prsec/adapters/`. Each MVP implementation can be swapped (GitLab, K8sRunner, DefectDojo, and so on).
- **The harness contract** is files in, files out. Each stage gets a `StageTask`: a
  harness-neutral prompt, skills, an output schema and limits. The agent must write
  `/work/out/<stage>.json`. `prsec-stage` validates that file and runs a repair loop if it
  is invalid. Tools are shell CLIs on `PATH` (`prsec-cite`, and so on), never MCP or
  harness plugins.
- **Models are decoupled from harnesses** through the LiteLLM gateway. Harnesses only see
  aliases (`agent-large`, `agent-small`, `judge`) and a short-lived virtual key. Provider
  keys live only in the `llm-gateway` container.
- **Citations are checked deterministically.** Every `file:line` and quote a stage cites
  is fuzzy-matched against the real source. Findings that fail are dropped.
- **Fingerprints** are `bug_class` + sink + entry point, so findings dedupe across pushes.
  Findings are never auto-closed.
- **Only the replay counts as dynamic evidence.** The agent writes a PoC (`poc.yaml`): users,
  HTTP steps (or several sent at once, for races), and oracles that code evaluates, on the
  response body, status, headers or JSON, on a request recorded by the sink, or on a command's
  output. Canaries are fresh per replay, and an oracle never passes on a value the PoC itself
  sent. The design is in [docs/design/phase2-dynamic.md](docs/design/phase2-dynamic.md).

## Repository layout

| Path | What |
|---|---|
| `prsec/` | the Python package (api, orchestrator, adapters, launcher, sandbox entrypoint, sarif, dashboard, db) |
| `prsec/dynamic/` | dynamic validation: EnvSpec, PoC, mock catalog, app runner, replay, sink, egress proxy |
| `prsec/obs/` | logging, the scan timeline, `prsec-trace` and `prsec-debug` |
| `docs/design/` | design notes (dynamic validation) |
| `prsec/policy/policy.yaml` | central scan policy (harness + model per stage, budgets, experiments, per-repo overrides) |
| `prsec-skills/` | the methodology (SKILL.md skills), its own repo in production |
| `deploy/compose/` | single-VM stack: `docker-compose.yml`, `caddy/Caddyfile`, `litellm/config.yaml` + `prsec_hooks.py` |
| `images/prsec/` | service image (`prsec-api`, `prsec-worker`, `prsec-launcher`, `prsec-dashboard`) |
| `images/workbench-base/` | workbench image: Ubuntu 24.04, toolchains (mise: node, python, go, temurin), `prsec-stage`; **no harness CLIs** |
| `images/harness/build.sh` | builds a self-contained harness volume |
| `tests/` | unit tests; `-m db` needs Postgres, `-m docker` a Docker daemon |

## LLM gateway (LiteLLM)

`deploy/compose/litellm/config.yaml` maps the aliases to the **direct** Anthropic and OpenAI APIs:

| Alias | Primary | Fallback |
|---|---|---|
| `agent-large` | `anthropic/claude-opus-5-5` | `openai/gpt-6-astra` |
| `agent-small` | `anthropic/claude-haiku-5-5` | `openai/gpt-6-luna` |
| `judge` | `openai/gpt-6-astra` (a different family from agent-large, to reduce correlated errors) | `anthropic/claude-sonnet-5-5` |

The `*-anthropic` and `*-openai` aliases pin a model family for the harness × model eval matrix.
The proxy serves the three wire APIs the harnesses need:

- `/v1/chat/completions`: raw, OpenCode and pi.
- `/v1/messages` (Anthropic format): Claude Code, with `ANTHROPIC_BASE_URL` pointed at the
  gateway and the virtual key as the auth token. OpenAI aliases are translated.
- `/v1/responses`: Codex (`wire_api = "responses"`). Anthropic aliases are bridged to
  chat completions.

Caveats from the LiteLLM docs, for the pinned `v1.105.5`:

- **Responses API sessions.** Through the bridge, `previous_response_id` and stored
  sessions need `store_prompts_in_spend_logs: true` plus cold storage. We keep it `false`
  so source code never lands in the gateway DB. Harnesses must send full context
  (Codex `exec` does by default), and the repair loop starts a fresh call instead of resuming.
- **Codex** may open WebSocket connections early and leave them idle. The gateway timeout
  (`request_timeout: 600`) and the stage wall clock bound them.
- **Translation is lossy.** Provider-specific parameters are dropped (`drop_params: true`).
  Anthropic thinking `budget_tokens` must be ≥ 1024 and < `max_tokens`. Prefer native
  routes (Claude Code → Anthropic alias, Codex → OpenAI alias) when the eval matrix allows.
- **Server-side tools** (provider-executed web search or fetch, hosted code execution,
  remote MCP) would bypass the per-scan network isolation. LiteLLM has no built-in switch
  for them, and its `tool_permission` guardrail only sees `function` tools. So
  `litellm/prsec_hooks.py` strips them in a pre-call hook on every route. Harness
  adapters also disable their web tools.
- Message logging is off (`turn_off_message_logging`), and so are prompts in spend logs.
  Spend per virtual key gives per-scan cost.

## policy.yaml

`prsec/policy/policy.yaml` is the central policy owned by AppSec. Repos cannot override it
from their branches. In compose it is bind-mounted read-only at `/etc/prsec/policy.yaml`;
set `PRSEC_POLICY_FILE` to use a file outside the repo. It sets:

- per stage, under `defaults`: `harness`, `model` alias, `skills`, `wall_clock_s`,
  `usd_budget` and an optional `max_turns`
- `experiments`: shadow A/B of harnesses for a stage, as a sampled fraction of scans
- `repos`: glob-keyed overrides (`enabled: false`, or per-stage harness and model changes,
  or `workbench_image`)
- global knobs: `max_hypotheses`, `static_verify_min_severity`, `skip_audit_sample`,
  `scan_drafts`, `scan_forks`
- `dynamic`: `enabled`, how many hypotheses per scan get a dynamic attempt
  (`max_hypotheses`, highest severity first, at or above `min_severity`), `replay_runs` (at
  least 2; all must fire), `base_replay`, `replay_timeout_s` and `concurrency`. The `env` and
  `dynamic` stages under `defaults` pick their harness and model like every other stage.

## Skills

The methodology lives in `prsec-skills/`, in the open `SKILL.md` format, one directory per
skill: `triage`, `taint-analysis`, `business-logic`, `static-validation` and `org` for the static
stages; `env-building`, `mocking`, `poc-authoring` and `oracles` for the dynamic ones. Skills must use harness-neutral language: generic actions and `prsec-*` CLIs, with
no harness-specific tools. `make lint-skills` enforces this.

`make skills SKILLS_VERSION=<ver>` lints the skills, copies them to
`$PRSEC_HOST_ROOT/skills/<ver>` and moves `skills/current` to that copy. Set
`PRSEC_SKILLS_VERSION` to the same value. It is part of the scan idempotency key, so a new
skills version rescans open PRs on their next push or reconcile. Each adapter installs the
skills in its harness's native location, or falls back to an index in `AGENTS.md`.

## Adding a harness

1. Write `prsec/adapters/harness/<name>.py`: a class decorated with `@register` that
   implements `HarnessAdapter` (`prsec/adapters/harness/base.py`). It covers caps,
   `install_skills`, `env` (gateway base URL, key, model alias), `command`,
   `parse_events` and `resume_command`. Look up the binary at `$PRSEC_HARNESS_HOME/bin/<cli>`
   first, then on `PATH`.
2. Add a `case` to `images/harness/build.sh` with the npm package and CLI name, then build it:
   `images/harness/build.sh <name> <version> /var/lib/prsec/harness`. The volume contains
   `bin/<cli>` (a wrapper), its own `node/`, `pkg/` and `manifest.json`
   (`{name, version, cli, sha256, ...}`). By default it moves `<name>/current` to the new version.
   Use `PLATFORM=linux/amd64` when building on a different architecture than the VM.
3. Run the harness conformance suite (`tests/harness_conformance/`). The offline tier
   (`make conformance`) runs automatically for every registered adapter: a stub CLI installed as
   `$PRSEC_HARNESS_HOME/bin/<cli>` checks skill discovery, prompt delivery, output validation, the
   repair loop, the wall-clock kill and transcript/usage normalisation through LocalRunner and the
   real entrypoint. Teach `tests/harness_conformance/stub_harness.py` the new CLI's skill discovery
   rules and add a captured native event stream under `tests/harness/fixtures/<name>/`. The live tier
   (`make conformance-live LIVE_HARNESSES=<name>`) runs the real CLI against the `sqli-new-endpoint`
   eval case in dev mode. A harness is supported only once both tiers pass.
4. Reference it in `policy.yaml`, first as an `experiments` entry.

Workbenches mount `<harness_root>/<name>/current` read-only at `/opt/harness/<name>/current`.
Upgrading a harness means building a new volume and moving `current`. Images don't change.

## Tests

```bash
make test        # unit tests (no DB, no Docker, no network)
make test-db     # starts postgres:16 on :55432 (container prsec-test-pg) and runs -m db
.venv/bin/pytest -m docker          # needs a Docker daemon (runner, compose config, a real dynamic env)
make conformance  # harness conformance suite, offline tier (all adapters, stub CLIs)
make test-e2e     # pipeline end to end: Postgres queue + LocalRunner + scripted harness
make conformance-live LIVE_HARNESSES=claude-code   # real harness CLIs + LLM (dev-mode login)
```

DB tests read `PRSEC_TEST_DATABASE_URL` and create their own schema per test.
`make test-pg-down` removes the test database.

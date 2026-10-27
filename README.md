# PRSec

PRSec is an agentic, harness-agnostic security scanner for pull requests. An org-level
GitHub App sends `pull_request` events to a central service. The service runs a small
pipeline of LLM-agent stages on each PR: **triage → hypothesise → static verify → skeptic**.
The stages run inside isolated workbench containers. The result is evidence-backed findings,
written as **SARIF** plus a Postgres index, and shown on an internal dashboard.

Dev teams add nothing to their CI. Phase 1 is the static core only: there is no dynamic
validation yet and no PR comments or checks. PR code is treated as trusted, because all
scanned repos are our own.

## Architecture (phase 1)

```
GitHub ──webhook──► caddy ─/webhooks/*─► api (HMAC verify → ScanRequest → Postgres queue)
                      └── everything else ─► oauth2-proxy (OIDC) ─► dashboard
                                                                         │
 worker ── lease from queue (FOR UPDATE SKIP LOCKED) ── per stage: DockerRunner
   │         └── per-scan internal network prsec-scan-<id>:
   │               [workbench: prsec-stage + harness volume + skills + PR source]
   │               └── only reachable host: prsec-llm-gateway (LiteLLM)
   ├── mints a per-scan virtual key (budget + TTL + allowed aliases) at the gateway
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
  Findings are never auto-closed in phase 1.

## Repository layout

| Path | What |
|---|---|
| `prsec/` | the Python package (api, orchestrator, adapters, sandbox entrypoint, sarif, dashboard, db) |
| `prsec/policy/policy.yaml` | central scan policy (harness + model per stage, budgets, experiments, per-repo overrides) |
| `prsec-skills/` | the methodology (SKILL.md skills), its own repo in production |
| `deploy/compose/` | single-VM stack: `docker-compose.yml`, `caddy/Caddyfile`, `litellm/config.yaml` + `prsec_hooks.py` |
| `images/prsec/` | service image (`prsec-api`, `prsec-worker`, `prsec-dashboard`) |
| `images/workbench-base/` | workbench image: Ubuntu 24.04, toolchains (mise: node, python, go, temurin), `prsec-stage`; **no harness CLIs** |
| `images/harness/build.sh` | builds a self-contained harness volume |
| `tests/` | unit tests; `-m db` needs Postgres, `-m docker` a Docker daemon |

## GitHub App setup

Create the App under the organisation (Settings → Developer settings → GitHub Apps):

- **Webhook URL:** `https://<PRSEC_DOMAIN>/webhooks/github`
- **Webhook secret:** a random string, set as `PRSEC_GITHUB_WEBHOOK_SECRET`
- **Repository permissions** (all read-only): **Contents: Read**, **Pull requests: Read**, **Metadata: Read**
- **Subscribe to events:** **Pull request**
- Then generate a private key. Save it as `deploy/compose/secrets/github-app.pem`, or point
  `PRSEC_GITHUB_PRIVATE_KEY_FILE` at it. Put the App ID in `PRSEC_GITHUB_APP_ID`.
- Install the App on the org, for all repos or a selected set. PRSec writes nothing back to GitHub.

## Quickstart on one VM

Prerequisites: Linux with Docker Engine and the compose plugin, a DNS name pointing at the
VM, and ports 80/443 open. Caddy gets a TLS certificate automatically.

```bash
cp .env.example .env               # fill in passwords, API keys, App id, OIDC client
make images                        # prsec/prsec + prsec/workbench-base
sudo make host-dirs                # /var/lib/prsec/{work,skills,harness}, work owned by uid 10001
sudo make harness-volumes          # claude-code, codex, opencode, pi (HARNESSES="codex@0.130.0 ..." to pin)
sudo make skills SKILLS_VERSION=2026.10.1    # lint + install prsec-skills, move skills/current
# set PRSEC_SKILLS_VERSION=2026.10.1 and DOCKER_GID=$(stat -c %g /var/run/docker.sock) in .env
make config                        # validate compose with your .env
make up                            # start; migrations run as the one-shot `migrate` service
```

`make down` stops the stack and keeps the volumes. Only caddy publishes ports. The
dashboard sits behind oauth2-proxy (OIDC) and is for AppSec only: `OIDC_ALLOWED_GROUPS` and
`OIDC_EMAIL_DOMAINS` are required, because the dashboard's triage action (tp/fp/accepted)
feeds the eval corpus. `/webhooks/*` is authenticated by the GitHub
HMAC signature. The internal `POST /scans` route on the api is never routed by caddy.
It is enabled by setting `PRSEC_ADMIN_TOKEN`.

Notes on the compose stack:

- **The Docker socket** is mounted into `worker` only. It is root-equivalent on the VM.
  This is accepted for the MVP because PR code runs in workbenches without the socket.
  Harden it with a docker-socket-proxy or rootless Docker; the risk goes away with K8sRunner.
- **The worker mounts `work`, `skills` and `harness` at the same absolute host path**
  (`PRSEC_HOST_ROOT`). This is needed because DockerRunner bind-mounts them into
  workbenches through the host daemon.
- **Per-scan networks** (`prsec-scan-<id>`, internal) are created by the worker. The
  worker attaches the fixed-name `prsec-llm-gateway` container to each one, with the
  alias `llm-gateway`.
- **The gateway has its own Postgres** (`llm-gateway-db`) on an internal network that only
  the gateway joins. It is separate from the prsec database.
- **MinIO** uses Chainguard's image, pinned by digest, because upstream stopped publishing
  community images. `minio-init` creates the bucket.
- **Back up** the `pgdata` and `miniodata` volumes nightly, off the box.

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

## Skills

The methodology lives in `prsec-skills/`, in the open `SKILL.md` format, one directory per
skill. Skills must use harness-neutral language: generic actions and `prsec-*` CLIs, with
no harness-specific tools. `make lint-skills` enforces this.

`make skills SKILLS_VERSION=<ver>` lints the skills, copies them to
`$PRSEC_HOST_ROOT/skills/<ver>` and moves `skills/current` to that copy. Set
`PRSEC_SKILLS_VERSION` to the same value. It is part of the scan idempotency key, so a new
skills version rescans open PRs on their next push or reconcile. Each adapter installs the
skills in its harness's native location, or falls back to an index in `AGENTS.md`.

## Dev mode (no VM, no gateway)

You can run stages on your laptop with **LocalRunner**. It runs `prsec-stage` as a host
subprocess against plain directories, without containers and without network isolation.
The harness uses **its own local login**: your `claude`, `codex`, `opencode` or `pi`
session. This works whenever `PRSEC_GATEWAY_MASTER_KEY` and `PRSEC_GATEWAY_DEV_KEY` are
both empty, because no gateway env is then injected. If `PRSEC_GATEWAY_DEV_KEY` is set
instead, its key is passed through to the configured `PRSEC_GATEWAY_URL` (for example a
local LiteLLM).

```bash
python3.12 -m venv .venv && .venv/bin/pip install -e '.[dev]'
make test-pg-up                     # Postgres on 127.0.0.1:55432
export PRSEC_DATABASE_URL=postgresql://prsec:prsec@localhost:55432/prsec
export PRSEC_RUNNER=local PRSEC_WORK_ROOT=$PWD/work PRSEC_SKILLS_DIR=$PWD/prsec-skills
make migrate
.venv/bin/prsec-api &               # webhook ingest on :8080
.venv/bin/prsec-worker              # leases scans and runs stages via LocalRunner
```

Harness binaries are found at `$PRSEC_HARNESS_HOME/bin/<cli>` first, then on `PATH`. A
locally installed CLI is therefore enough in dev mode.

## Tests

```bash
make test        # unit tests (no DB, no Docker, no network)
make test-db     # starts postgres:16 on :55432 (container prsec-test-pg) and runs -m db
.venv/bin/pytest -m docker          # needs a Docker daemon (runner, compose config)
make conformance  # harness conformance suite, offline tier (all adapters, stub CLIs)
make test-e2e     # pipeline end to end: Postgres queue + LocalRunner + scripted harness
make conformance-live LIVE_HARNESSES=claude-code   # real harness CLIs + LLM (dev-mode login)
```

DB tests read `PRSEC_TEST_DATABASE_URL` and create their own schema per test.
`make test-pg-down` removes the test database.

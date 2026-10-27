# Phase 2: dynamic validation (design)

Static survivors get a dynamic attempt: the PR's app is started inside the workbench next to
mock services, an agent tries to prove the bug with a declarative PoC, and an **agent-free
replay** re-runs that PoC in fresh environments. Only the replay counts as evidence.

The contracts are code, not prose. Read them first; they are the source of truth:

| File | What |
|---|---|
| `prsec/dynamic/envspec.py` | `EnvSpec` (install/build/start/port/health/env/services/stubs) |
| `prsec/dynamic/poc.py` | `PoC` (users, steps, oracles, `${...}` placeholders) |
| `prsec/dynamic/results.py` | `EnvRequest`/`EnvInfo`, `ReplayRequest`/`ReplayResult`, `DynamicEvidence`, fixed paths |
| `prsec/dynamic/catalog.py` + `catalog.yaml` | allowlisted mock images, env, caps, seed path |
| `prsec/stages/outputs.py` | `EnvOutput`, `DynamicOutput` (stage outputs) |
| `prsec/adapters/protocols.py` | `WorkbenchSpec.env_name/app_dir/mode`, `Runner.supports_envs/create_env/destroy_env/run_replay` |
| `prsec/config.py` | `Policy.dynamic` (`DynamicPolicy`) |

## Flow

```
static survivors (verdict plausible|confirmed_static, severity >= dynamic.min_severity,
                  top dynamic.max_hypotheses by severity)
  │
  ├─ env stage (once per scan; agent; network = static scan network, no services)
  │     in: pr.json, diff.patch, changed_files.txt, previous_envspec.json (cached, if any)
  │     out: EnvOutput.envspec
  │
  └─ per hypothesis (dynamic.concurrency at a time):
        runner.create_env(scan, "h<i>", EnvRequest(services, stubs, llm=True, packages=True))
        dynamic stage (agent) in that env, app_dir = <root>/app/h<i> (writable, /work/app)
            in: hypothesis.json, static_verify.json, envspec.json, code_slices.md, pr.json, diff.patch
            tools: prsec-env up|status|logs|reset|down, prsec-http, prsec-canary, prsec-poc validate|run
            out: DynamicOutput {outcome, poc, envspec (commands/env/stubs may be corrected)}
        runner.destroy_env
        if outcome == reproduced and poc is valid:
            replay r1..rN on head  (fresh env each: create_env(llm=False), fresh app_dir copy of head src,
                                    run_replay, destroy_env)
            replay on base (if dynamic.base_replay): same, with the base_sha source
        -> DynamicEvidence(head_runs, head_fired, base_fired, entry, poc, replays)
  │
verdict.decide(..., dynamic=DynamicEvidence|None)
```

The env stage's service list is authoritative: the dynamic stage may correct commands, env and
stubs (`DynamicOutput.envspec`) but not services. Replays use the corrected spec with the env
stage's services. When a replay env comes up healthy, the spec is cached as
`<work_root>/profiles/<owner>__<repo>.envspec.json` and handed to the next scan's env stage.

## Labels

| Label | Rule |
|---|---|
| **reproduced** | `dynamic.replay_confirmed` (all ≥2 head replays fired) AND `entry == "http"` AND static verdict not refuted, `reachable == "yes"`, citations verified. Skeptic does not block it (replayed evidence beats opinion). |
| **likely** | as phase 1, OR replay confirmed but `entry == "script"` or reachability not `yes` (direct call into code is capped at likely: reason `replay_confirmed_direct_call`). |
| **inconclusive** | everything else; the reason always records the dynamic outcome when one ran (e.g. `plausible_static_only; dynamic=not_reproduced`). |

`introduced`: base replay fired → `false` (pre-existing); base replay ran and did not fire → `true`;
otherwise `None`. Dynamic `not_reproduced` never downgrades a static label: absence of proof is not proof.

## Environment (runner / launcher)

- Network `prsec-scan-<scan_id>-<env>` (internal bridge; `env` matches `results.ENV_NAME`), labelled
  `prsec.scan_id=<id>` and `prsec.env=<env>`. `destroy_scan` removes all of them.
- **Sink** (`prsec-sink`, image `PRSEC_SINK_IMAGE` = the prsec service image), alias `sink`, started
  first. It is the DNS server for the workbench: names in its hosts map (catalog services, `sink`,
  `llm-gateway`, `egress-proxy`) resolve to their real IPs on that network; **every other name resolves
  to the sink itself**. HTTP :80 records every request (host, method, path, headers, body ≤ 64 KiB)
  and answers from the env's stubs, else `200 {}`. TLS :443 records the SNI host of the ClientHello and
  closes. API on Host `sink`: `GET /__prsec/hits?contains=<s>`, `GET /__prsec/health`.
  Port 53/80/443 as non-root via sysctl `net.ipv4.ip_unprivileged_port_start=0`.
- The runner writes `<env_dir>/sink/hosts.json`, `<env_dir>/sink/stubs.json` (sink reloads on change)
  and `<env_dir>/resolv.conf` (`nameserver <sink_ip>`), and mounts `resolv.conf` read-only at
  `/etc/resolv.conf` in the workbench, so name resolution never depends on Docker's embedded DNS
  forwarding behaviour on internal networks.
- **Catalog services**: image/env/caps/seed path from `catalog.yaml` only; requested `seed_dir` is
  validated to be under the work root and mounted read-only at the entry's `seed_path`; cap_drop ALL +
  the entry's caps, no-new-privileges, mem/pids limits, labels. Health = exec the entry's `health`
  command until it succeeds (≤ 120 s); a service that never gets healthy is reported in
  `EnvInfo.services`, not fatal.
- **LLM gateway** attached (alias `llm-gateway`) only when `EnvRequest.llm`. **Egress proxy**
  (`prsec-egress-proxy` compose service, alias `egress-proxy`) attached only when
  `EnvRequest.packages`. It is an HTTP CONNECT/forward proxy that allows only registry hosts
  (`PRSEC_EGRESS_ALLOW`, default: pypi.org, files.pythonhosted.org, registry.npmjs.org,
  registry.yarnpkg.com, proxy.golang.org, sum.golang.org, repo1.maven.org, repo.maven.apache.org,
  plugins.gradle.org, services.gradle.org) and refuses targets that resolve to private, loopback,
  link-local or metadata addresses. It sits on its own non-internal `egress` network.
- **Workbench in an env**: same hardened recipe as static stages, plus `app_dir` → `/work/app` (rw),
  resolv.conf mount, network = env network. `mode == "replay"` runs entrypoint `prsec-replay` with
  command `/work/in/replay.json` (fixed). Replay envs never get the gateway.
- The **launcher** gets the same operations: `POST /scans/{id}/envs/{env}` (body `EnvRequest`),
  `DELETE /scans/{id}/envs/{env}`, and `/run` accepts `env_name`, `app_dir`, `mode`. Everything is
  validated like phase 1: env name regex, kinds in the catalog, seed/env/app dirs under the work root,
  stubs size-capped; DNS / resolv.conf and the sink are computed by the launcher, never taken from
  the request. LocalRunner raises `NotImplementedError` for envs (dynamic is skipped with reason
  `runner_unsupported`).

## Inside the workbench

- `prsec.dynamic.app` (shared): copy `/work/src` → `/work/app/src` (once), run `install` + `build`
  with `HTTP(S)_PROXY=http://egress-proxy:3128` (only if the name resolves to a non-sink address,
  i.e. packages are allowed), start `start` in the background **without** proxy env, with
  `EnvSpec.env`, logs to `/work/app/.prsec/app.log`, pid in `/work/app/.prsec/app.pid`; wait for
  `health`. Before start, write the canary sentinel file when canaries are given.
- `prsec-env up|status|logs [-n N]|reset|down` drives that for the agent (envspec from
  `/work/in/envspec.json`, or `--spec`). `prsec-http` sends one request as a named user
  (`prsec-http --user alice --login-from poc.yaml GET /path`), keeping per-user cookie jars under
  `/work/app/.prsec/users/`. `prsec-canary new|hits [--contains]` prints canary values / sink hits.
  `prsec-poc validate <file>` checks a poc.yaml/json against `PoC`; `prsec-poc run <file>` runs it
  against the running app exactly like the replay does and prints the oracle results.
- `prsec-replay /work/in/replay.json` (agent-free): fresh canaries, app up, run PoC
  (`kind: http`: users' login then steps; `kind: script`: bash `script`), evaluate oracles,
  write `ReplayResult` to `/work/out/replay_result.json`. It never raises: env failure →
  `env_ok=false, env_error=...`.

## Skills (prsec-skills)

`env-building` (SKILL.md + references python.md, node.md), `mocking` (catalog, stubs, seeding,
test users), `poc-authoring` (poc.yaml by bug class: sqli, idor/bola two users, bfla, ssrf via
canary URL, path traversal via sentinel file, cmdi via echoed canary token, xss reflected marker,
business logic invariants with json_compare), `oracles` (choosing an oracle that cannot fire by
accident; a PoC must fail on fixed code). Harness-neutral language (skills lint), benign canaries only.

## Integration details (settled while building)

Points the contracts above leave open, and how the modules agree on them:

- **Runner capability.** `Runner.supports_envs` (Docker and Launcher: `True`, Local: `False`) is
  checked before the paid env stage; without it dynamic is skipped with reason `runner_unsupported`.
  A `NotImplementedError` from `create_env` still maps to the same outcome.
- **Sink files.** `<env_dir>/sink` is mounted read-write at `/sink` (`prsec-sink --data-dir /sink`,
  `PRSEC_SINK_DIR=/sink`). `hosts.json` is `{name: ipv4}` (written atomically; it always holds `sink`),
  `stubs.json` is a list of `StubSpec`. Unknown names resolve to `hosts.json["sink"]`, else to
  `--self-ip` / `PRSEC_SINK_SELF_IP`, else to the container's own address. The sink appends every
  record to `/sink/requests.jsonl` (memory only when that is not writable).
- **Sink hit record** (`/__prsec/hits`, `ReplayResult.sink_hits`): `ts` (epoch float), `client_ip`,
  `tls`, `host`, `method`, `path`, `query`, `headers`, `body` (≤ 64 KiB), `body_truncated`. `contains`
  matches host, path, raw or decoded query, any header value, or the body.
- **Workbench in an env.** `WorkbenchSpec` names the env, not its dir: `create_env` stores the checked
  `env_dir` in the network label `prsec.env_dir` and the runner reads `resolv.conf` from there. Only
  the runner sets that label; a request never chooses the resolv.conf.
- **Replay request.** The orchestrator writes `<in_dir>/replay.json` (`ReplayRequest`) before
  `run_replay`; runners take `run_id` from it. A replay's `StageTask` is minimal (stage `dynamic`,
  task id `<scan>-replay-<hyp>-r<n>` / `-base`, empty prompt and schema, `wall_clock_s =
  dynamic.replay_timeout_s`, which is also `ReplayRequest.timeout_s`), and `harness_volume` is
  `None`. The container's wall clock is that plus the runner's grace.
- **Canary sentinel** lives at `/work/app/.prsec/canary/sentinel-<token>.txt` (readable by the app).
- **Extract.** A value extracted on a step becomes `${VARS.<var>}` and, when the step runs as a user,
  `${USER.<var>}` for that user and `${USERS.<user>.<var>}` for everyone else.
- **Script PoCs.** Oracles read the script's stdout as step `script` (`poc.SCRIPT_STEP`; status 200
  when it exits 0, else 500), besides `command` and `canary_hit`.
- **User headers during login.** A user header that cannot be rendered yet (e.g. a bearer token the
  login extracts) is left out of that user's login steps; elsewhere an unrenderable placeholder
  aborts the run.
- **Unexpected replay errors** after the app came up are recorded as a `StepRecord(name="replay",
  method="-", error=...)` with `fired=false`.
- **CLIs.** `prsec-http` takes `--login-from` (alias `--poc`), `--relogin`, `--json`, `--form k=v`,
  `--data` and `-H`. `prsec-env reset` stops the app, deletes the app copy (fresh DB files, re-install)
  and runs `up` again. Each `prsec-env` subcommand takes `--spec`.
- **Agent outcome `blocked`** becomes `DynamicEvidence(outcome="not_reproduced", reason="blocked: ...")`.
- **Provenance.** `DynamicEvidence.provenance` holds the dynamic stage run (task id, harness, model,
  skills, image) and is copied to `Finding.provenance["dynamic"]`.
- **Prompts.** `_io.md` keeps static stages read-only; when `app_dir` is set (dynamic stage) it
  allows installing and running the app through the listed tools in the writable copy only.

Known gaps (not yet expressible): no oracle on response headers (XSS `Content-Type`, open redirect
`Location`); absolute step URLs are limited to canary hosts, so a PoC cannot fetch a token from the
`oauth2` mock or read `mailpit`'s API; steps run sequentially, so race conditions cannot be proven.
The skills tell the agent to report `blocked` / `not_reproduced` for these.

## Rules for every change

- Never write reverse-shell-like content (no `/dev/tcp` redirections, no `nc -e`, no interactive
  shell redirects, no socket+dup2/pty patterns, no PowerShell TCP clients). Canaries are benign.
- Keep the code style of the surrounding code (comment density, naming, typing).

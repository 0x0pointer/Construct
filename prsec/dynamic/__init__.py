"""Phase 2: dynamic validation.

For hypotheses that survive static verification, the PR's code is run inside the workbench next
to mock services, and an agent tries to prove the bug with a declarative PoC. An agent-free replay
then re-runs that PoC in fresh environments (twice on head, once on base) and evaluates its oracles
in code; only that replay counts as evidence.

    envspec.py   EnvSpec: how to install, build and start the app, and which mock services it needs
    poc.py       PoC (poc.yaml): multi-user HTTP request sequence + oracles, with ${...} placeholders
    catalog.py   allowlisted mock service images (catalog.yaml, owned by AppSec)
    results.py   replay request/result, env provisioning request/info, per-hypothesis dynamic evidence
    app.py       app lifecycle inside the workbench (copy src, install, build, start, health), shared
                 by prsec-env and prsec-replay
    replay.py    agent-free PoC interpreter + oracle evaluation (prsec-replay entrypoint)
    sink.py      per-env catch-all HTTP recorder + DNS stub + canary hit API (prsec-sink)
    egress_proxy.py  allowlisting CONNECT proxy for package installs only (prsec-egress-proxy)

Environment layout (one per agent run or replay, on its own internal network prsec-scan-<id>-<env>):

    workbench  --- app started by prsec-env / prsec-replay on 127.0.0.1:<envspec.port>
    sink       --- DNS for the workbench: catalog services / gateway / proxy resolve to their real
                   address, every other name resolves to the sink, whose HTTP(S) listeners record
                   the request instead of letting it leave. Canary URLs land here.
    <services> --- catalog mocks (postgres, redis, ...) reachable by their EnvSpec service name
    llm-gateway  (agent envs only)       egress-proxy (only for install/build commands)
"""

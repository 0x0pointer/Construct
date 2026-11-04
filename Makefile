# PRSec developer / single-VM operations. Run from the repo root.
SHELL := /usr/bin/env bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help

PYTHON ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)
PYTEST ?= $(PYTHON) -m pytest

ENV_FILE ?= .env
COMPOSE_FILE := deploy/compose/docker-compose.yml
COMPOSE := docker compose -f $(COMPOSE_FILE) $(if $(wildcard $(ENV_FILE)),--env-file $(ENV_FILE))

PRSEC_IMAGE ?= prsec/prsec:latest
WORKBENCH_IMAGE ?= prsec/workbench-base:latest
PRSEC_HOST_ROOT ?= /var/lib/prsec
HARNESS_ROOT ?= $(PRSEC_HOST_ROOT)/harness
SKILLS_SRC ?= prsec-skills
SKILLS_VERSION ?= dev

# Harness volumes to build: <name>@<version> ("latest" resolves via npm and is recorded in manifest.json).
HARNESSES ?= claude-code@latest codex@latest opencode@latest pi@latest

TEST_PG_CONTAINER ?= prsec-test-pg
TEST_PG_PORT ?= 55432
PRSEC_TEST_DATABASE_URL ?= postgresql://prsec:prsec@localhost:$(TEST_PG_PORT)/prsec

.PHONY: help images image-prsec image-workbench harness-volumes skills host-dirs config up down logs \
        migrate test test-db test-pg-up test-pg-down lint-skills conformance conformance-live test-e2e \
        test-dynamic local-up local-down local-worker local-dashboard eval \
        kind-up kind-data kind-load kind-deploy kind-dashboard kind-eval test-k8s kind-down

help: ## list targets
	@grep -E '^[a-zA-Z0-9_-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-16s %s\n", $$1, $$2}'

images: image-prsec image-workbench ## build the prsec service image and the workbench base image

image-prsec:
	docker build -f images/prsec/Dockerfile -t $(PRSEC_IMAGE) .

image-workbench:
	docker build -f images/workbench-base/Dockerfile -t $(WORKBENCH_IMAGE) .

harness-volumes: ## build harness volumes into $(HARNESS_ROOT) (HARNESSES="codex@0.130.0 ...")
	@for h in $(HARNESSES); do \
	  name=$${h%@*}; ver=$${h#*@}; \
	  if [[ "$$ver" != latest && -e "$(HARNESS_ROOT)/$$name/$$ver" ]]; then echo "skip $$name@$$ver (exists)"; continue; fi; \
	  images/harness/build.sh "$$name" "$$ver" "$(HARNESS_ROOT)"; \
	done

skills: ## lint and install $(SKILLS_SRC) as $(PRSEC_HOST_ROOT)/skills/$(SKILLS_VERSION) (+ current)
	$(PYTHON) -m prsec.skills_lint $(SKILLS_SRC)
	mkdir -p "$(PRSEC_HOST_ROOT)/skills/$(SKILLS_VERSION)"
	cp -R "$(SKILLS_SRC)/." "$(PRSEC_HOST_ROOT)/skills/$(SKILLS_VERSION)/"
	printf '%s\n' "$(SKILLS_VERSION)" > "$(PRSEC_HOST_ROOT)/skills/$(SKILLS_VERSION)/VERSION"
	chmod -R a+rX,go-w "$(PRSEC_HOST_ROOT)/skills/$(SKILLS_VERSION)"
	ln -sfn "$(SKILLS_VERSION)" "$(PRSEC_HOST_ROOT)/skills/current"

host-dirs: ## create the host dirs the worker bind-mounts (owned by uid 10001)
	mkdir -p "$(PRSEC_HOST_ROOT)/work" "$(PRSEC_HOST_ROOT)/skills" "$(HARNESS_ROOT)"
	@if [[ "$$(id -u)" == 0 ]]; then chown 10001:10001 "$(PRSEC_HOST_ROOT)/work"; \
	 else echo "note: run 'sudo chown 10001:10001 $(PRSEC_HOST_ROOT)/work' so the worker (uid 10001) can write"; fi

config: ## validate the compose file (with .env)
	$(COMPOSE) config -q && echo "compose config OK"

up: host-dirs ## start the stack (detached)
	$(COMPOSE) up -d --wait

down: ## stop the stack (volumes are kept)
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f --tail=200

migrate: ## apply prsec/db/schema.sql (idempotent) to PRSEC_DATABASE_URL, or via compose when the stack runs
	@if $(COMPOSE) ps --status running --services 2>/dev/null | grep -qx postgres; then \
	  $(COMPOSE) run --rm migrate; \
	else \
	  $(PYTHON) -c 'import psycopg; from prsec.config import settings; from prsec.db.conn import migrate; migrate(psycopg.connect(settings().database_url, autocommit=True)); print("migrated")'; \
	fi

lint-skills: ## lint the skills repo for harness-neutral language
	$(PYTHON) -m prsec.skills_lint $(SKILLS_SRC)

test: ## unit tests (no DB, no docker)
	$(PYTEST) -q -m "not db and not docker and not k8s and not live_harness"

test-pg-up: ## start a throwaway Postgres 16 for DB tests on :$(TEST_PG_PORT)
	@if ! docker ps --format '{{.Names}}' | grep -qx $(TEST_PG_CONTAINER); then \
	  docker rm -f $(TEST_PG_CONTAINER) >/dev/null 2>&1 || true; \
	  docker run -d --name $(TEST_PG_CONTAINER) -p 127.0.0.1:$(TEST_PG_PORT):5432 \
	    -e POSTGRES_USER=prsec -e POSTGRES_PASSWORD=prsec -e POSTGRES_DB=prsec postgres:16.15-alpine >/dev/null; \
	fi
	@for _ in $$(seq 1 30); do \
	  docker exec $(TEST_PG_CONTAINER) pg_isready -U prsec -d prsec >/dev/null 2>&1 && exit 0; sleep 1; \
	done; echo "postgres did not become ready" >&2; exit 1

test-pg-down:
	docker rm -f $(TEST_PG_CONTAINER)

test-db: test-pg-up ## DB tests against the throwaway Postgres
	PRSEC_TEST_DATABASE_URL=$(PRSEC_TEST_DATABASE_URL) $(PYTEST) -q -m db

conformance: ## harness conformance suite, offline tier (every adapter, stub CLIs)
	$(PYTEST) -q tests/harness_conformance -m "not live_harness"

conformance-live: ## live tier: real CLIs in dev mode (LIVE_HARNESSES=claude-code,opencode to narrow)
	PRSEC_LIVE_HARNESS=1 PRSEC_LIVE_HARNESSES=$(LIVE_HARNESSES) $(PYTEST) -q -s -m live_harness tests/harness_conformance

test-e2e: test-pg-up ## offline end-to-end pipeline test (Postgres + LocalRunner + scripted harness)
	PRSEC_TEST_DATABASE_URL=$(PRSEC_TEST_DATABASE_URL) $(PYTEST) -q tests/e2e

test-dynamic: images ## reference PoCs of the dynamic eval cases, replayed in real Docker envs (no LLM)
	PRSEC_TEST_IMAGE=$(PRSEC_IMAGE) PRSEC_TEST_WORKBENCH_IMAGE=$(WORKBENCH_IMAGE) \
	  $(PYTEST) -q -m docker tests/dynamic/test_reference_replays.py

# ---------------------------------------------------------------- local pilot (Docker runner + Spark)
# Infra in Docker (deploy/compose/docker-compose.local.yml); worker, dashboard and prsec-eval on the
# host with deploy/local/spark.env. SPARK_HOST is resolved here: containers cannot resolve mDNS names.
SPARK_HOST ?= spark-efb9.local
SPARK_PORT ?= 8000
# JEV-27B on the Spark (rules-jev shadow arm); harmless when it is not running
SPARK_JEV_PORT ?= 8001
LOCAL_COMPOSE := docker compose -f deploy/compose/docker-compose.local.yml
LOCAL_ENV := set -a; PRSEC_LOCAL_ROOT="$(CURDIR)"; . deploy/local/spark.env; set +a
RESOLVE_SPARK := python3 -c 'import socket, sys; print(socket.gethostbyname(sys.argv[1]))' "$(SPARK_HOST)"

local-up: images ## start the local pilot infra: Postgres, LLM gateway -> Spark, egress proxy
	@spark_ip="$$($(RESOLVE_SPARK))"; echo "Spark $(SPARK_HOST) -> $$spark_ip"; \
	  SPARK_IP="$$spark_ip" SPARK_API_BASE="http://$$spark_ip:$(SPARK_PORT)/v1" \
	  SPARK_JEV_API_BASE="http://$$spark_ip:$(SPARK_JEV_PORT)/v1" \
	  $(LOCAL_COMPOSE) up -d --wait
	@mkdir -p work/local
	@$(LOCAL_ENV); $(PYTHON) -c 'import psycopg; from prsec.config import settings; from prsec.db.conn import migrate; migrate(psycopg.connect(settings().database_url, autocommit=True)); print("migrated")'
	@test -e work/harness/opencode/current || images/harness/build.sh opencode latest "$(CURDIR)/work/harness"

local-down: ## stop the local pilot infra (the database volume is kept)
	$(LOCAL_COMPOSE) down

local-worker: ## run prsec-worker on the host against the local pilot (Ctrl-C to stop)
	$(LOCAL_ENV); exec .venv/bin/prsec-worker

local-dashboard: ## dashboard for the local pilot on http://127.0.0.1:8081
	$(LOCAL_ENV); exec .venv/bin/prsec-dashboard

eval: ## queue eval cases for the local worker and score them (CASES="a b" or TAG=dynamic; default all)
	$(LOCAL_ENV); .venv/bin/prsec-eval run $(CASES) $(if $(TAG),--tag $(TAG))

# ---------------------------------------------------------------- kind (the whole stack on local Kubernetes)
# docs/design/k8s.md. The node's /var/lib/prsec is work/kind on this Mac (the chart's hostPath volume).
KIND_CLUSTER ?= construct
KIND_DATA := $(CURDIR)/work/kind
KIND_CTX := kind-$(KIND_CLUSTER)
KUBECTL := kubectl --context $(KIND_CTX)
HELM := helm --kube-context $(KIND_CTX)

CALICO_VERSION ?= v3.32.3
CALICO_MANIFEST := work/calico-$(CALICO_VERSION).yaml

kind-up: ## create the local kind cluster with Calico (NetworkPolicy enforced in the dataplane)
	@mkdir -p "$(KIND_DATA)"
	@if kind get clusters 2>/dev/null | grep -qx "$(KIND_CLUSTER)"; then echo "kind cluster $(KIND_CLUSTER) exists"; else \
	  sed 's|$${PRSEC_KIND_DATA}|$(KIND_DATA)|' deploy/kind/cluster.yaml.tmpl > work/kind-cluster.yaml && \
	  kind create cluster --config work/kind-cluster.yaml; fi
	@test -s $(CALICO_MANIFEST) || curl -fsSL -o $(CALICO_MANIFEST) \
	  https://raw.githubusercontent.com/projectcalico/calico/$(CALICO_VERSION)/manifests/calico.yaml
	@sed -e 's|# - name: CALICO_IPV4POOL_CIDR|- name: CALICO_IPV4POOL_CIDR|' \
	     -e 's|#   value: "192.168.0.0/16"|  value: "10.244.0.0/16"|' $(CALICO_MANIFEST) | $(KUBECTL) apply -f - >/dev/null
	$(KUBECTL) -n kube-system rollout status ds/calico-node --timeout=300s
	$(KUBECTL) wait --for=condition=Ready nodes --all --timeout=300s

kind-data: ## prepare the data volume (work/kind): work dir, skills as version 'local', harness volumes
	mkdir -p "$(KIND_DATA)/work" "$(KIND_DATA)/skills/local" "$(KIND_DATA)/harness"
	$(PYTHON) -m prsec.skills_lint $(SKILLS_SRC)
	rsync -a --delete "$(SKILLS_SRC)/" "$(KIND_DATA)/skills/local/"
	printf 'local\n' > "$(KIND_DATA)/skills/local/VERSION"
	ln -sfn local "$(KIND_DATA)/skills/current"
	@test -e work/harness/opencode/current || images/harness/build.sh opencode latest "$(CURDIR)/work/harness"
	rsync -a work/harness/ "$(KIND_DATA)/harness/"
	chmod -R a+rwX "$(KIND_DATA)/work"  # pods run as uid 10001

kind-load: images ## load the prsec images into the kind node
	kind load docker-image $(PRSEC_IMAGE) $(WORKBENCH_IMAGE) --name $(KIND_CLUSTER)

kind-deploy: kind-up kind-data kind-load ## deploy the whole stack on kind (gateway -> the Spark)
	@spark_ip="$$($(RESOLVE_SPARK))"; echo "Spark $(SPARK_HOST) -> $$spark_ip"; \
	$(HELM) upgrade --install construct deploy/helm/construct -n prsec --create-namespace \
	  -f deploy/kind/values.yaml \
	  --set-file policy=policy-spark.yaml \
	  --set-file gateway.config=deploy/compose/litellm/config.spark.yaml \
	  --set-file gateway.hooks=deploy/compose/litellm/prsec_hooks.py \
	  --set gateway.env.SPARK_API_BASE="http://$$spark_ip:$(SPARK_PORT)/v1" \
	  --set gateway.env.SPARK_JEV_API_BASE="http://$$spark_ip:$(SPARK_JEV_PORT)/v1" \
	  --set "gateway.hostAliases[0].ip=$$spark_ip" --set "gateway.hostAliases[0].hostnames[0]=spark" \
	  --wait --timeout 15m
	$(KUBECTL) -n prsec get pods

kind-dashboard: ## dashboard of the kind stack on http://127.0.0.1:8082
	$(KUBECTL) -n prsec port-forward svc/dashboard 8082:8081

kind-eval: ## prsec-eval in the cluster's worker, detached (CASES="a b" or TAG=dynamic); log+report in work/kind/work/evals
	@run=kind-$$(date +%Y%m%dT%H%M%S); out=/var/lib/prsec/work/evals/$$run; \
	$(KUBECTL) -n prsec exec deploy/worker -c worker -- sh -c "mkdir -p $$out && nohup prsec-eval run $(CASES) \
	  $(if $(TAG),--tag $(TAG)) --out $$out > $$out/eval.log 2>&1 &" && \
	echo "eval started in the worker pod; follow: tail -f work/kind/work/evals/$$run/eval.log"

test-k8s: ## K8sRunner against the kind cluster: isolation probes + reference replays (needs kind-deploy)
	PRSEC_K8S_CONTEXT=$(KIND_CTX) PRSEC_K8S_DATA_ROOT="$(KIND_DATA)" $(PYTEST) -q -m k8s tests/k8s

kind-down: ## delete the kind cluster (work/kind is kept)
	kind delete cluster --name $(KIND_CLUSTER)

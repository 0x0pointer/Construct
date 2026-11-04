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
        kind-up kind-data kind-load kind-deploy kind-dashboard kind-eval test-k8s kind-down \
        do-images do-nfs do-deploy do-data do-test-k8s do-eval do-report do-down

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
LOCAL_COMPOSE := docker compose -f deploy/compose/docker-compose.local.yml
LOCAL_ENV := set -a; PRSEC_LOCAL_ROOT="$(CURDIR)"; . deploy/local/spark.env; set +a
RESOLVE_SPARK := python3 -c 'import socket, sys; print(socket.gethostbyname(sys.argv[1]))' "$(SPARK_HOST)"

local-up: images ## start the local pilot infra: Postgres, LLM gateway -> Spark, egress proxy
	@spark_ip="$$($(RESOLVE_SPARK))"; echo "Spark $(SPARK_HOST) -> $$spark_ip"; \
	  SPARK_IP="$$spark_ip" SPARK_API_BASE="http://$$spark_ip:$(SPARK_PORT)/v1" \
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

kind-deploy: kind-up kind-data kind-load ## deploy the whole stack on kind (gateway -> the Spark; provider keys from .env)
	@spark_ip="$$($(RESOLVE_SPARK))"; echo "Spark $(SPARK_HOST) -> $$spark_ip"; \
	oa="$${OPENAI_API_KEY:-$$(grep -E '^OPENAI_API_KEY=' $(ENV_FILE) 2>/dev/null | tail -1 | cut -d= -f2-)}"; \
	an="$${ANTHROPIC_API_KEY:-$$(grep -E '^ANTHROPIC_API_KEY=' $(ENV_FILE) 2>/dev/null | tail -1 | cut -d= -f2-)}"; \
	$(HELM) upgrade --install construct deploy/helm/construct -n prsec --create-namespace \
	  $${oa:+--set-string secrets.openaiApiKey=$$oa} $${an:+--set-string secrets.anthropicApiKey=$$an} \
	  -f deploy/kind/values.yaml \
	  --set-file policy=policy-spark.yaml \
	  --set-file gateway.config=deploy/compose/litellm/config.spark.yaml \
	  --set-file gateway.hooks=deploy/compose/litellm/prsec_hooks.py \
	  --set gateway.env.SPARK_API_BASE="http://$$spark_ip:$(SPARK_PORT)/v1" \
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

# ---------------------------------------------------------------- DigitalOcean (the whole stack on DOKS, OpenAI)
# A dedicated DOKS cluster (doctl kubernetes cluster create $(DO_CLUSTER) ...), amd64 images in DOCR,
# DO Network File Storage as the shared volume, every model on OpenAI (policy-openai.yaml).
DO_CLUSTER ?= construct-e2e
DO_REGION ?= ams3
DO_CTX := do-$(DO_REGION)-$(DO_CLUSTER)
DO_REGISTRY ?= registry.digitalocean.com/foundry-registry
DO_NFS_SIZE ?= 50
DO_NFS_TIER ?= standard
DO_KUBECTL := kubectl --context $(DO_CTX)
DO_HELM := helm --kube-context $(DO_CTX)
DO_TAG = $(shell cat work/do-image-tag 2>/dev/null)
DO_PRSEC = $(DO_REGISTRY)/prsec:$(DO_TAG)
DO_WORKBENCH = $(DO_REGISTRY)/workbench-base:$(DO_TAG)

do-images: ## build the amd64 images and push them to DOCR (tag in work/do-image-tag)
	doctl registry login --expiry-seconds 3600
	@tag="0.1.0-$$(git rev-parse --short HEAD)-$$(date +%m%d%H%M)"; echo "$$tag" > work/do-image-tag; \
	docker buildx build --platform linux/amd64 -f images/prsec/Dockerfile -t $(DO_REGISTRY)/prsec:$$tag --push . && \
	docker buildx build --platform linux/amd64 -f images/workbench-base/Dockerfile -t $(DO_REGISTRY)/workbench-base:$$tag --push .
	@test -e work/harness-amd64/opencode/current || PLATFORM=linux/amd64 images/harness/build.sh opencode latest "$(CURDIR)/work/harness-amd64"

do-nfs: ## create the DO NFS share in the cluster's VPC (once); its address goes to work/do-nfs
	@vpc=$$(doctl kubernetes cluster get $(DO_CLUSTER) -o json | $(PYTHON) -c 'import json,sys; d=json.load(sys.stdin); print((d[0] if isinstance(d,list) else d)["vpc_uuid"])'); \
	id=$$(doctl nfs list --region $(DO_REGION) --format ID,Name --no-header | awk '$$2=="$(DO_CLUSTER)"{print $$1}'); \
	if [ -z "$$id" ]; then doctl nfs create --name $(DO_CLUSTER) --region $(DO_REGION) --size $(DO_NFS_SIZE) \
	  --performance-tier $(DO_NFS_TIER) --vpc-ids $$vpc >/dev/null; \
	  id=$$(doctl nfs list --region $(DO_REGION) --format ID,Name --no-header | awk '$$2=="$(DO_CLUSTER)"{print $$1}'); fi; \
	until doctl nfs get --id $$id --region $(DO_REGION) --format Status --no-header | grep -qi active; do sleep 10; done; \
	doctl nfs get --id $$id --region $(DO_REGION) -o json > work/do-nfs.json; echo "NFS share $$id ready"

do-deploy: ## deploy the whole stack on DOKS with OpenAI (needs do-images, do-nfs; OPENAI_API_KEY from .env)
	doctl kubernetes cluster registry add $(DO_CLUSTER)
	@sed "s|^workbench_image: .*|workbench_image: $(DO_WORKBENCH)|" policy-openai.yaml > work/policy-do.yaml
	@nfs_host=$$($(PYTHON) -c 'import json; d=json.load(open("work/do-nfs.json")); d=d[0] if isinstance(d,list) else d; print(d["host"])'); \
	nfs_path=$$($(PYTHON) -c 'import json; d=json.load(open("work/do-nfs.json")); d=d[0] if isinstance(d,list) else d; print(d["mount_path"])'); \
	oa="$${OPENAI_API_KEY:-$$(grep -E '^OPENAI_API_KEY=' $(ENV_FILE) 2>/dev/null | tail -1 | cut -d= -f2-)}"; \
	[ -n "$$oa" ] || { echo "OPENAI_API_KEY is not set (environment or $(ENV_FILE))" >&2; exit 1; }; \
	$(DO_HELM) upgrade --install construct deploy/helm/construct -n prsec --create-namespace \
	  -f deploy/do/values.yaml \
	  --set images.prsec=$(DO_PRSEC) --set images.workbench=$(DO_WORKBENCH) \
	  --set storage.volume.nfs.server=$$nfs_host --set storage.volume.nfs.path=$$nfs_path \
	  --set-file policy=work/policy-do.yaml \
	  --set-file gateway.config=deploy/compose/litellm/config.openai.yaml \
	  --set-file gateway.hooks=deploy/compose/litellm/prsec_hooks.py \
	  --set-string secrets.openaiApiKey=$$oa \
	  --wait --timeout 15m
	$(DO_KUBECTL) -n prsec get pods

do-data: ## put skills (version 'local') and the amd64 harness volumes on the shared NFS volume
	@sed "s|IMAGE_REPO:IMAGE_TAG|$(DO_PRSEC)|g" deploy/do/loader-pod.yaml | $(DO_KUBECTL) -n prsec apply -f - >/dev/null
	$(DO_KUBECTL) -n prsec wait --for=condition=Ready pod/construct-data-loader --timeout=300s
	$(DO_KUBECTL) -n prsec exec construct-data-loader -- sh -c 'mkdir -p /var/lib/prsec/work /var/lib/prsec/skills /var/lib/prsec/harness'
	COPYFILE_DISABLE=1 tar -C $(SKILLS_SRC) -cf - . | $(DO_KUBECTL) -n prsec exec -i construct-data-loader -- sh -c \
	  'rm -rf /var/lib/prsec/skills/local && mkdir -p /var/lib/prsec/skills/local && tar -C /var/lib/prsec/skills/local -xf - && echo local > /var/lib/prsec/skills/local/VERSION && ln -sfn local /var/lib/prsec/skills/current'
	COPYFILE_DISABLE=1 tar -C work/harness-amd64 -cf - . | $(DO_KUBECTL) -n prsec exec -i construct-data-loader -- tar -C /var/lib/prsec/harness -xf -
	$(DO_KUBECTL) -n prsec exec construct-data-loader -- sh -c 'ls -lan /var/lib/prsec /var/lib/prsec/skills /var/lib/prsec/harness/opencode'
	$(DO_KUBECTL) -n prsec delete pod construct-data-loader --wait=false

do-test-k8s: ## tests/k8s inside the DO cluster (launcher's account): isolation on DO's CNI + reference replays
	@sed -e "s|IMAGE_REPO:IMAGE_TAG|$(DO_PRSEC)|g" -e "s|WORKBENCH_REPO:IMAGE_TAG|$(DO_WORKBENCH)|g" deploy/do/test-pod.yaml | \
	  $(DO_KUBECTL) -n prsec apply -f - >/dev/null
	$(DO_KUBECTL) -n prsec wait --for=condition=Ready pod/construct-k8s-tests --timeout=300s
	COPYFILE_DISABLE=1 tar -cf - tests pyproject.toml prsec/policy/policy.yaml | $(DO_KUBECTL) -n prsec exec -i construct-k8s-tests -- sh -c 'mkdir -p /tmp/repo && tar -C /tmp/repo -xf -'
	$(DO_KUBECTL) -n prsec exec construct-k8s-tests -- sh -c 'pip install -q --target /tmp/py pytest pytest-asyncio 2>&1 | tail -1; \
	  cd /tmp/repo && python -m pytest -q -p no:cacheprovider -m k8s tests/k8s'; \
	  rc=$$?; $(DO_KUBECTL) -n prsec delete pod construct-k8s-tests --wait=false >/dev/null; exit $$rc

do-eval: ## prsec-eval in the DO worker pod, detached (CASES="a b" or TAG=dynamic); then make do-report
	@run=do-$$(date +%Y%m%dT%H%M%S); out=/var/lib/prsec/work/evals/$$run; echo "$$run" > work/do-eval-run; \
	$(DO_KUBECTL) -n prsec exec deploy/worker -c worker -- sh -c "mkdir -p $$out && nohup prsec-eval run $(CASES) \
	  $(if $(TAG),--tag $(TAG)) --out $$out > $$out/eval.log 2>&1 &" && echo "eval $$run started in the DO worker"

do-report: ## the latest DO eval's log tail and report (once written)
	@run=$$(cat work/do-eval-run); $(DO_KUBECTL) -n prsec exec deploy/worker -c worker -- sh -c \
	  "grep -v psycopg /var/lib/prsec/work/evals/$$run/eval.log | tail -8; cat /var/lib/prsec/work/evals/$$run/report.md 2>/dev/null"

do-down: ## delete the DO cluster (with its volumes and load balancers) and the NFS share; DOCR images stay
	@cid=$$(doctl kubernetes cluster get $(DO_CLUSTER) --format ID --no-header); test -n "$$cid"; \
	doctl kubernetes cluster delete $(DO_CLUSTER) --dangerous --force && \
	id=$$(doctl nfs list --region $(DO_REGION) --format ID,Name --no-header | awk '$$2=="$(DO_CLUSTER)"{print $$1}'); \
	{ [ -z "$$id" ] || doctl nfs delete --id $$id --region $(DO_REGION); } && \
	echo "waiting for the cluster's PVC volumes to detach (they can outlive the cluster)" && \
	python3 deploy/do/reap_volumes.py "$$cid"

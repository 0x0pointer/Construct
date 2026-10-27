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
        migrate test test-db test-pg-up test-pg-down lint-skills conformance conformance-live test-e2e

help: ## list targets
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-16s %s\n", $$1, $$2}'

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
	$(PYTEST) -q -m "not db and not docker and not live_harness"

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

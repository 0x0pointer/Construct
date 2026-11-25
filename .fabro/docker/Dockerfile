# Sandbox image for Fabro runs on Construct: Python 3.12, git, gh, and the
# project's dependencies pre-installed so each run's setup step is fast.
# Build from the repo root:  docker build -f .fabro/docker/Dockerfile -t construct-fabro:latest .
FROM python:3.12-bookworm

RUN apt-get update \
 && apt-get install -y --no-install-recommends git curl ca-certificates jq make gh \
 && rm -rf /var/lib/apt/lists/*

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_ROOT_USER_ACTION=ignore PYTHONDONTWRITEBYTECODE=1

COPY pyproject.toml /tmp/deps/pyproject.toml
RUN python -c "import tomllib; p=tomllib.load(open('/tmp/deps/pyproject.toml','rb'))['project']; print('\n'.join(p['dependencies']+p['optional-dependencies']['dev']))" > /tmp/deps/requirements.txt \
 && pip install --no-cache-dir -r /tmp/deps/requirements.txt

# Postgres for the tests marked `db`, which CI runs against a Postgres
# service. Without it those tests are skipped in the sandbox and a change can
# pass here and fail in CI. A step must run `start-test-db` before testing.
RUN apt-get update \
 && apt-get install -y --no-install-recommends postgresql \
 && rm -rf /var/lib/apt/lists/* \
 && service postgresql start \
 && su postgres -c "psql -c \"CREATE ROLE prsec LOGIN SUPERUSER PASSWORD 'prsec'\" -c 'CREATE DATABASE prsec OWNER prsec'" \
 && service postgresql stop
COPY .fabro/docker/start-test-db /usr/local/bin/start-test-db
ENV PRSEC_TEST_DATABASE_URL=postgresql://prsec:prsec@localhost:5432/prsec

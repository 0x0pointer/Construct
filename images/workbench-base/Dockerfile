# syntax=docker/dockerfile:1.7
# Workbench base: the container a stage runs in. Toolchains + prsec-stage / prsec-cite.
# NO harness CLI is baked in: harnesses come from read-only harness volumes mounted at
# /opt/harness/<name>/<version> (PRSEC_HARNESS_HOME), see images/harness/build.sh.
# Build from the repo root:  docker build -f images/workbench-base/Dockerfile -t prsec/workbench-base .

FROM ubuntu:24.04

ARG MISE_VERSION=v2026.10.21
ARG NODE_VERSION=24
ARG PYTHON_VERSION=3.12
ARG GO_VERSION=1.27
ARG JAVA_VERSION=temurin-21

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl git jq ripgrep less file unzip xz-utils zstd \
      build-essential pkg-config \
      python3 python3-venv python3-pip \
 && rm -rf /var/lib/apt/lists/*

# Toolchains via mise, installed system-wide and read-only for the agent.
ENV MISE_DATA_DIR=/opt/mise \
    MISE_CONFIG_DIR=/etc/mise \
    MISE_CACHE_DIR=/tmp/mise-cache \
    MISE_GLOBAL_CONFIG_FILE=/etc/mise/config.toml \
    MISE_YES=1
RUN arch="$(dpkg --print-architecture)" \
 && case "$arch" in amd64) march=x64 ;; arm64) march=arm64 ;; *) echo "unsupported arch $arch" >&2; exit 1 ;; esac \
 && curl -fsSL -o /usr/local/bin/mise \
      "https://github.com/jdx/mise/releases/download/${MISE_VERSION}/mise-${MISE_VERSION}-linux-${march}" \
 && chmod 0755 /usr/local/bin/mise \
 && mkdir -p /etc/mise \
 && mise use --global "node@${NODE_VERSION}" "python@${PYTHON_VERSION}" "go@${GO_VERSION}" "java@${JAVA_VERSION}" \
 && mise install \
 && mise reshim \
 && rm -rf /tmp/mise-cache \
 && chmod -R a+rX /opt/mise /etc/mise
ENV PATH=/opt/mise/shims:$PATH

# prsec (prsec-stage entrypoint, prsec-cite and the other prsec-* sandbox CLIs) in its own
# venv built from the distro python, so project toolchains can't break it.
COPY pyproject.toml /opt/prsec-src/
COPY prsec /opt/prsec-src/prsec
RUN python3 -m venv /opt/prsec \
 && /opt/prsec/bin/pip install /opt/prsec-src \
 && rm -rf /opt/prsec-src \
 && for f in /opt/prsec/bin/prsec-*; do ln -s "$f" "/usr/local/bin/$(basename "$f")"; done

RUN groupadd --gid 10001 agent \
 && useradd --uid 10001 --gid agent --create-home --home-dir /home/agent --shell /bin/bash agent \
 && mkdir -p /work/src /work/in /work/out /skills /opt/harness \
 && chown agent:agent /work /work/out

USER agent
WORKDIR /work/src
ENV HOME=/home/agent
ENTRYPOINT ["prsec-stage"]

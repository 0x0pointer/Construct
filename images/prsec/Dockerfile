# syntax=docker/dockerfile:1.7
# PRSec service image: prsec-api, prsec-worker, prsec-dashboard (one image, different commands).
# Build from the repo root:  docker build -f images/prsec/Dockerfile -t prsec/prsec .

FROM python:3.12-slim AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
COPY pyproject.toml ./
COPY prsec ./prsec
RUN python -m venv /opt/prsec \
 && /opt/prsec/bin/pip install --upgrade pip \
 && /opt/prsec/bin/pip install .

FROM python:3.12-slim
ENV PATH=/opt/prsec/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
# uid/gid 10001 matches the workbench 'agent' user so files in the shared host work dir
# have one owner across worker and workbenches.
RUN groupadd --system --gid 10001 prsec \
 && useradd --system --uid 10001 --gid prsec --home-dir /home/prsec --create-home --shell /usr/sbin/nologin prsec
COPY --from=build /opt/prsec /opt/prsec
USER prsec
WORKDIR /home/prsec
EXPOSE 8080 8081
CMD ["prsec-api"]

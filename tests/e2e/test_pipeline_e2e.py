"""Offline end to end: real Postgres queue + real pipeline + LocalRunner + real entrypoint and
adapters, with a scripted harness CLI and a fake SCM serving the skills eval cases.

Needs PRSEC_TEST_DATABASE_URL. No network, no LLM.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import uuid
from pathlib import Path
from typing import Iterator

import jsonschema
import psycopg
import pytest
import yaml
from psycopg.conninfo import make_conninfo
from psycopg.rows import dict_row

from prsec.adapters import scm as scm_pkg
from prsec.adapters.sinks.sarif_store import read_uri
from prsec.config import settings
from prsec.db import conn as db_conn
from prsec.db import queue
from prsec.models import PRInfo, ScanRequest
from prsec.orchestrator import pipeline

pytestmark = pytest.mark.db

ROOT = Path(__file__).resolve().parents[2]
CASES = ROOT / "prsec-skills" / "evals" / "cases"
SARIF_SCHEMA = json.loads((ROOT / "tests" / "sarif" / "sarif-schema-2.1.0.json").read_text())
FIXTURES = ROOT / "tests" / "harness" / "fixtures"
STUB = Path(__file__).parent / "scripted_harness.py"
REPO = "evals/shop-flask"
SQLI_PR, CSS_PR = 101, 103


class FakeSCM:
    """Serves eval cases as PRs: number -> case dir (pr.json, diff.patch, repo/)."""

    name = "github"

    def __init__(self) -> None:
        self.cases = {SQLI_PR: CASES / "sqli-new-endpoint", CSS_PR: CASES / "css-only"}
        self.heads: dict[int, str] = {}
        self.fetched: list[tuple[str, str]] = []

    def get_pr(self, repo: str, number: int, installation_id: int | None = None) -> PRInfo:
        meta = json.loads((self.cases[number] / "pr.json").read_text())
        return PRInfo(repo=repo, number=number, title=meta["title"], body=meta["body"], base_ref=meta["base_ref"],
                      base_sha="b" * 40, head_ref=meta["head_ref"], head_sha=self.heads.get(number, "a" * 40),
                      changed_files=meta["changed_files"], commits=meta["commits"])

    def get_diff(self, repo: str, number: int, installation_id: int | None = None) -> str:
        return (self.cases[number] / "diff.patch").read_text()

    def fetch_source(self, repo: str, sha: str, dest: Path, installation_id: int | None = None) -> Path:
        self.fetched.append((repo, sha))
        number = next(n for n, h in self.heads.items() if h == sha)
        shutil.copytree(self.cases[number] / "repo", dest, dirs_exist_ok=True)
        return dest

    def list_open_prs(self, installation_id: int | None = None) -> list[PRInfo]:
        return []


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[dict]:
    base = os.environ.get("PRSEC_TEST_DATABASE_URL")
    if not base:
        pytest.skip("PRSEC_TEST_DATABASE_URL not set")
    schema = f"t_e2e_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(base, autocommit=True) as c:
        c.execute(f'CREATE SCHEMA "{schema}"')
    url = make_conninfo(base, options=f"-csearch_path={schema}")

    for adapter, cli in (("claude-code", "claude"), ("opencode", "opencode")):
        bindir = tmp_path / "harness" / adapter / "current" / "bin"
        bindir.mkdir(parents=True)
        (bindir / cli).write_text(f'#!/bin/sh\nexec "{sys.executable}" "{STUB}" {cli} "$@"\n')
        (bindir / cli).chmod(0o755)
    stage = {"model": "agent-large", "wall_clock_s": 60, "usd_budget": 1.0}
    policy = {
        "version": "1", "workbench_image": "local", "max_hypotheses": 8, "static_verify_min_severity": "medium",
        "skip_audit_sample": 0.0, "experiments": [],
        "defaults": {
            "triage": {**stage, "harness": "claude-code", "skills": ["triage"]},
            "hypothesise": {**stage, "harness": "opencode", "skills": ["taint-analysis", "business-logic"]},
            "static_verify": {**stage, "harness": "claude-code", "skills": ["static-validation"]},
            "skeptic": {**stage, "harness": "claude-code", "skills": []},
        },
    }
    (tmp_path / "policy.yaml").write_text(yaml.safe_dump(policy))
    for k, v in {
        "PRSEC_DATABASE_URL": url, "PRSEC_RUNNER": "local", "PRSEC_WORK_ROOT": str(tmp_path / "work"),
        "PRSEC_SKILLS_DIR": str(ROOT / "prsec-skills"), "PRSEC_HARNESS_ROOT": str(tmp_path / "harness"),
        "PRSEC_POLICY_PATH": str(tmp_path / "policy.yaml"), "PRSEC_SARIF_DIR": str(tmp_path / "sarif"),
        "PRSEC_GATEWAY_MASTER_KEY": "", "PRSEC_S3_ACCESS_KEY": "", "PRSEC_SKILLS_VERSION": "e2e",
        "PRSEC_E2E_FIXTURES": str(FIXTURES),
    }.items():
        monkeypatch.setenv(k, v)
    for k in ("PRSEC_GATEWAY_DEV_KEY", "PRSEC_GATEWAY_URL", "PRSEC_GATEWAY_KEY", "PRSEC_HARNESS_HOME"):
        monkeypatch.delenv(k, raising=False)
    settings.cache_clear()
    db_conn.close_pool()
    with db_conn.get_pool().connection() as c:
        db_conn.migrate(c)
    scm = FakeSCM()
    monkeypatch.setattr(scm_pkg, "get_scm", lambda name="github": scm)
    try:
        with psycopg.connect(url, autocommit=True, row_factory=dict_row) as sql:
            yield {"scm": scm, "sql": sql, "tmp": tmp_path}
    finally:
        db_conn.close_pool()
        settings.cache_clear()
        with psycopg.connect(base, autocommit=True) as c:
            c.execute(f'DROP SCHEMA "{schema}" CASCADE')


def _enqueue(env: dict, pr: int, head: str) -> int:
    env["scm"].heads[pr] = head
    scan_id = queue.enqueue(ScanRequest(repo=REPO, pr=pr, head_sha=head, reason="opened"), "e2e", 0, 5)
    assert scan_id is not None
    return scan_id


def _lease(scan_id: int) -> dict:
    row = queue.lease_next(600)
    assert row is not None and row["id"] == scan_id
    return row


def _scan(sql, scan_id: int) -> dict:
    return sql.execute("SELECT * FROM scans WHERE id = %s", (scan_id,)).fetchone()


def test_css_only_pr_is_skipped_by_rules(env: dict) -> None:
    scan_id = _enqueue(env, CSS_PR, "c" * 40)
    pipeline.run_scan(_lease(scan_id))
    row = _scan(env["sql"], scan_id)
    assert row["status"] == "skipped", row["error"]
    assert row["triage"]["source"] == "rules" and row["triage"]["reason"].startswith("noise_only")
    assert env["scm"].fetched == []  # never downloaded source, never ran a stage
    assert env["sql"].execute("SELECT count(*) AS n FROM stage_runs").fetchone()["n"] == 0


def test_sqli_pr_yields_likely_finding_and_valid_sarif(env: dict) -> None:
    head = "d" * 40
    scan_id = _enqueue(env, SQLI_PR, head)
    pipeline.run_scan(_lease(scan_id))
    sql = env["sql"]
    row = _scan(sql, scan_id)
    assert row["status"] == "done", row["error"]
    assert row["triage"]["decision"] == "full" and row["triage"]["source"] == "llm"
    assert float(row["cost_usd"]) > 0

    runs = sql.execute("SELECT stage, harness, status FROM stage_runs WHERE scan_id = %s ORDER BY stage", (scan_id,)).fetchall()
    by_stage: dict[str, list[dict]] = {}
    for r in runs:
        by_stage.setdefault(r["stage"], []).append(r)
    assert set(by_stage) == {"triage", "hypothesise", "static_verify", "skeptic"}
    assert all(r["status"] == "ok" for r in runs), runs
    assert by_stage["hypothesise"][0]["harness"] == "opencode"
    assert len(by_stage["static_verify"]) == 2  # H3 dropped by the citation check before verification
    assert len(by_stage["skeptic"]) == 1  # H2 refuted statically

    findings = sql.execute("SELECT * FROM findings WHERE repo = %s AND last_pr = %s", (REPO, SQLI_PR)).fetchall()
    assert len(findings) == 1
    f = findings[0]
    assert f["bug_class"] == "sqli"  # 'sql-injection' alias canonicalised before fingerprinting
    assert f["label"] == "likely" and f["status"] == "open" and f["sink_file"] == "app.py"

    uri = row["sarif_uri"]
    assert uri.startswith("file://") and uri.endswith(f"{head}.sarif")
    doc = json.loads(read_uri(uri))
    jsonschema.Draft4Validator(SARIF_SCHEMA).validate(doc)
    results = doc["runs"][0]["results"]
    assert [r["ruleId"] for r in results] == ["sqli"]
    assert results[0]["properties"]["label"] == "likely"
    region = results[0]["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 35 and "LIKE" in region["snippet"]["text"]
    dropped = {d["id"]: d["reason"] for d in doc["runs"][0]["properties"]["dropped"]}
    assert dropped == {"H3": "hypothesis_citations_unverified", "H2": "static_refuted"}


def test_newer_head_supersedes_running_scan(env: dict) -> None:
    sql = env["sql"]
    old = _enqueue(env, SQLI_PR, "e" * 40)
    leased = _lease(old)
    new = _enqueue(env, SQLI_PR, "f" * 40)  # push while the old scan is running
    assert _scan(sql, old)["status"] == "superseded"
    assert _scan(sql, new)["supersede_count"] == 1

    pipeline.run_scan(leased)  # the worker notices and aborts without writing findings
    row = _scan(sql, old)
    assert row["status"] == "superseded" and row["sarif_uri"] is None
    assert sql.execute("SELECT count(*) AS n FROM stage_runs WHERE scan_id = %s", (old,)).fetchone()["n"] == 0

    pipeline.run_scan(_lease(new))
    row = _scan(sql, new)
    assert row["status"] == "done", row["error"]
    assert row["head_sha"] == "f" * 40
    assert sql.execute("SELECT count(*) AS n FROM findings WHERE last_pr = %s", (SQLI_PR,)).fetchone()["n"] == 1

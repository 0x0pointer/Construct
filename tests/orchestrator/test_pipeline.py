import json
from pathlib import Path
from typing import Any, Callable

import pytest

from prsec.adapters import runner as runner_pkg
from prsec.adapters import scm as scm_pkg
from prsec.adapters import sinks as sinks_pkg
from prsec.config import load_policy, settings
from prsec.models import Label, PRInfo, ScanStatus, Stage, StageResult, StageStatus, Usage
from prsec.orchestrator import pipeline
from prsec.sarif.fingerprint import fingerprint

SRC = {
    "app/orders.py": (
        "from db import q\n"
        "\n"
        "def get_order(req):\n"
        "    oid = req.args['id']\n"
        "    return q('SELECT * FROM orders WHERE id=' + oid)\n"
    ),
}
CODE_DIFF = (
    "diff --git a/app/orders.py b/app/orders.py\n--- a/app/orders.py\n+++ b/app/orders.py\n"
    "@@ -1,4 +1,5 @@\n def get_order(req):\n+    oid = req.args['id']\n+    return q('SELECT * FROM orders WHERE id=' + oid)\n"
)
CSS_DIFF = "diff --git a/web/a.css b/web/a.css\n--- a/web/a.css\n+++ b/web/a.css\n@@ -1 +1 @@\n-a{}\n+b{}\n"

SINK = {"file": "app/orders.py", "line": 5, "quote": "return q('SELECT * FROM orders WHERE id=' + oid)"}
SOURCE = {"file": "app/orders.py", "line": 4, "quote": "oid = req.args['id']"}


def hyp(hid="H1", sink=SINK, severity="high"):
    return {
        "id": hid, "vuln_class": "technical", "bug_class": "sqli", "title": "SQLi in get_order", "description": "concat",
        "entry_point": "GET /orders/123", "source": SOURCE, "sink": sink, "path": [], "assumed_guards": [],
        "impact": "dump db", "severity_guess": severity, "introduced_by_diff": True,
    }


def static(hid="H1", verdict="confirmed_static", reachable="yes", cits=None):
    return {"hypothesis_id": hid, "verdict": verdict, "reachable": reachable, "reasoning": "no binding",
            "guards": [{"description": "none", "effective": False}], "citations": cits or [SINK],
            "severity": "critical", "remediation": "use params"}


TRIAGE_FULL = {"decision": "full", "rationale": "query", "risk_tags": ["sqli"], "focus_files": ["app/orders.py"]}


class FakeSCM:
    name = "github"

    def __init__(self, diff: str):
        self.diff = diff

    def get_pr(self, repo, number, installation_id=None):
        return PRInfo(repo=repo, number=number, title="Add order lookup", body="lookup by id", base_ref="main",
                      base_sha="b" * 40, head_ref="feat", head_sha="h" * 40, changed_files=[])

    def get_diff(self, repo, number, installation_id=None):
        return self.diff

    def fetch_source(self, repo, sha, dest: Path, installation_id=None):
        for name, text in SRC.items():
            (dest / name).parent.mkdir(parents=True, exist_ok=True)
            (dest / name).write_text(text)
        return dest

    def list_open_prs(self, installation_id=None):
        return []


class FakeRunner:
    name = "fake"

    def __init__(self, script: dict[str, Callable[[Any], Any]], fail_network: bool = False, events: list | None = None):
        self.script = script
        self.specs = []
        self.destroyed: list[int] = []
        self.fail_network = fail_network
        self.events = events if events is not None else []
        self.inputs: dict[str, dict[str, str]] = {}  # task_id -> in_dir files (the work dir is deleted after the scan)

    def create_scan_network(self, scan_id):
        if self.fail_network:
            raise RuntimeError("no docker")
        return f"prsec-scan-{scan_id}"

    def run_workbench(self, spec):
        self.specs.append(spec)
        t = spec.task
        self.inputs[t.task_id] = {f.name: f.read_text() for f in spec.in_dir.iterdir()}
        out = self.script[t.stage.value](t)
        (spec.out_dir / "transcript.jsonl").write_text('{"kind": "message", "text": "hi"}\n')
        status = StageStatus.ok
        if isinstance(out, StageStatus):
            status, out = out, None
        return StageResult(task_id=t.task_id, stage=t.stage, status=status, output=out, harness=t.harness,
                           harness_version="1.0", model=t.model_alias, usage=Usage(usd=0.5))

    def destroy_scan(self, scan_id):
        self.destroyed.append(scan_id)
        self.events.append("destroy")


class FakeSink:
    name = "fake"

    def __init__(self, fail=False):
        self.calls = []
        self.fail = fail

    def write_scan(self, scan_id, pr, findings, meta):
        if self.fail:
            raise RuntimeError("minio down")
        self.calls.append((scan_id, pr, findings, meta))
        return f"s3://prsec/sarif/{pr.repo}/{pr.number}/{pr.head_sha}.sarif"


class FakeQueue:
    def __init__(self, superseded_after: int | None = None, lease_lost_after: int | None = None):
        self.finished = []
        self.stage_runs = []
        self.transcripts: dict[str, str | None] = {}
        self.cost = 0.0
        self.checks = 0
        self.superseded_after = superseded_after
        self.lease_checks = 0
        self.lease_lost_after = lease_lost_after
        self.enqueued = []
        self.events: list[str] = []

    def is_superseded(self, scan_id):
        self.checks += 1
        return self.superseded_after is not None and self.checks > self.superseded_after

    def owns_lease(self, scan_id, token):
        self.lease_checks += 1
        return self.lease_lost_after is None or self.lease_checks <= self.lease_lost_after

    def finish(self, scan_id, status, *, triage=None, error=None, sarif_uri=None, lease_token=None):
        self.events.append("finish")
        self.finished.append({"status": ScanStatus(status), "triage": triage, "error": error, "sarif_uri": sarif_uri,
                              "lease_token": lease_token})

    def record_stage_run(self, scan_id, result, transcript_uri, lease_token=None):
        self.stage_runs.append(result.task_id)
        self.transcripts[result.task_id] = transcript_uri

    def enqueue(self, req, skills_version, debounce_s, max_supersedes):
        self.enqueued.append((req, skills_version))
        return 999

    def add_cost(self, scan_id, usd):
        self.cost += usd


@pytest.fixture
def env(tmp_path, monkeypatch):
    state = {"minted": [], "revoked": []}
    monkeypatch.setattr(settings(), "work_root", tmp_path / "work")
    monkeypatch.setattr(settings(), "runner", "fake")
    policy = load_policy().model_copy(update={"experiments": [], "skip_audit_sample": 0.0})
    monkeypatch.setattr(pipeline, "load_policy", lambda: policy)
    monkeypatch.setattr(pipeline.gateway, "mint_key", lambda *a: state["minted"].append(a) or "sk-scan")
    monkeypatch.setattr(pipeline.gateway, "revoke_key", lambda k: state["revoked"].append(k))
    monkeypatch.setattr(pipeline.gateway, "per_task_keys", lambda: False)
    monkeypatch.setattr(pipeline, "_open_findings", lambda repo, pr: state.get("prior", []))
    monkeypatch.setenv("PRSEC_SARIF_DIR", str(tmp_path / "artifacts"))
    monkeypatch.setattr(settings(), "s3_access_key", "")

    def setup(diff=CODE_DIFF, script=None, q=None, sink=None, fail_network=False, policy_update=None, scm=None):
        if policy_update:
            monkeypatch.setattr(pipeline, "load_policy", lambda: policy.model_copy(update=policy_update))
        q = q or FakeQueue()
        runner = FakeRunner(script or {}, fail_network=fail_network, events=q.events)
        sink = sink or FakeSink()
        monkeypatch.setattr(scm_pkg, "get_scm", lambda name="github": scm or FakeSCM(diff), raising=False)
        monkeypatch.setattr(runner_pkg, "get_runner", lambda name: runner, raising=False)
        monkeypatch.setattr(sinks_pkg, "get_sink", lambda: sink, raising=False)
        for fn in ("is_superseded", "owns_lease", "finish", "record_stage_run", "add_cost", "enqueue"):
            monkeypatch.setattr(pipeline.queue, fn, getattr(q, fn))
        state.update(runner=runner, q=q, sink=sink)
        return state

    return setup


ROW = {"id": 101, "repo": "acme/shop", "pr": 7, "head_sha": "h" * 40, "base_sha": None, "installation_id": 5,
       "scm": "github", "skills_version": "sk-1"}


def full_script(hyps=None, static_fn=None, skeptic_refuted=False):
    return {
        "triage": lambda t: TRIAGE_FULL,
        "hypothesise": lambda t: {"summary": "adds lookup", "hypotheses": hyps if hyps is not None else [hyp()]},
        "static_verify": static_fn or (lambda t: static(t.task_id.rsplit("-", 1)[1])),
        "skeptic": lambda t: {"hypothesis_id": t.task_id.rsplit("-", 1)[1], "refuted": skeptic_refuted,
                              "confidence": "high", "reasoning": "r"},
    }


def only(q):
    assert len(q.finished) == 1
    return q.finished[0]


def test_rules_skip(env):
    s = env(diff=CSS_DIFF)
    pipeline.run_scan(ROW)
    f = only(s["q"])
    assert f["status"] == ScanStatus.skipped
    assert f["triage"]["source"] == "rules"
    assert f["triage"]["reason"].startswith("noise_only:")
    assert not s["minted"]
    assert not s["runner"].specs
    assert not s["runner"].destroyed


def test_rules_skip_audit_sample_still_scans(env):
    s = env(diff=CSS_DIFF, script=full_script(hyps=[]), policy_update={"skip_audit_sample": 1.0})
    pipeline.run_scan(ROW)
    f = only(s["q"])
    assert f["status"] == ScanStatus.done
    assert f["triage"]["would_skip"]
    assert f["triage"]["audit_sample"]
    assert f["triage"]["source"] == "rules"


def test_llm_triage_skip(env):
    s = env(script={"triage": lambda t: {"decision": "skip", "rationale": "copy change"}})
    pipeline.run_scan(ROW)
    f = only(s["q"])
    assert f["status"] == ScanStatus.skipped
    assert f["triage"]["source"] == "llm"
    assert f["triage"]["rules"] == {"decision": "llm", "reason": None}
    assert s["q"].stage_runs == ["101-triage"]
    assert s["q"].cost == 0.5
    assert s["runner"].destroyed == [101]
    assert s["revoked"] == ["sk-scan"]


def test_superseded_mid_scan(env):
    q = FakeQueue(superseded_after=2)  # pre-fetch check, pre-triage check pass; pre-hypothesise check fails
    s = env(script=full_script(), q=q)
    pipeline.run_scan(ROW)
    assert only(q)["status"] == ScanStatus.superseded
    assert q.stage_runs == ["101-triage"]
    assert not s["sink"].calls
    assert s["runner"].destroyed == [101]
    assert s["revoked"] == ["sk-scan"]


def test_hypothesis_dropped_by_citation_check(env):
    bad = hyp(sink={"file": "app/orders.py", "line": 5, "quote": "cursor.execute(raw_sql)"})
    s = env(script=full_script(hyps=[bad]))
    pipeline.run_scan(ROW)
    f = only(s["q"])
    assert f["status"] == ScanStatus.done
    assert f["sarif_uri"].startswith("s3://")
    _, _, findings, meta = s["sink"].calls[0]
    assert findings == []
    assert meta["dropped"][0]["reason"] == "hypothesis_citations_unverified"
    assert s["q"].stage_runs == ["101-triage", "101-hypothesise"]
    assert meta["scanned_files"] == meta["changed_files"] == ["app/orders.py"]


def test_refuted_is_dropped(env):
    s = env(script=full_script(static_fn=lambda t: static(verdict="refuted", reachable="no")))
    pipeline.run_scan(ROW)
    _, _, findings, meta = s["sink"].calls[0]
    assert findings == []
    assert meta["dropped"] == [{"id": "H1", "reason": "static_refuted", "errors": []}]
    assert "101-skeptic-H1" not in s["q"].stage_runs


def test_static_citation_failure_is_dropped(env):
    bad_cit = [{"file": "app/orders.py", "line": 1, "quote": "subprocess.run(cmd, shell=True)"}]
    s = env(script=full_script(static_fn=lambda t: static(cits=bad_cit)))
    pipeline.run_scan(ROW)
    _, _, findings, meta = s["sink"].calls[0]
    assert findings == []
    assert meta["dropped"][0]["reason"] == "static_citations_unverified"


def test_likely(env):
    s = env(script=full_script())
    pipeline.run_scan(ROW)
    f = only(s["q"])
    assert f["status"] == ScanStatus.done
    assert f["triage"]["decision"] == "full"
    _, pr, findings, meta = s["sink"].calls[0]
    assert pr.head_sha == "h" * 40
    [fd] = findings
    assert fd.label == Label.likely
    assert fd.label_reason == "confirmed_static_reachable_skeptic_upheld"
    assert fd.severity == "critical"
    assert fd.remediation == "use params"
    assert fd.fingerprint == fingerprint("sqli", "app/orders.py", "get_order", "GET /orders/123")
    assert fd.sink.snippet == "    return q('SELECT * FROM orders WHERE id=' + oid)"
    assert set(fd.provenance) >= {"hypothesise", "static_verify", "skeptic"}
    assert fd.provenance["static_verify"]["harness"] == load_policy().defaults["static_verify"].harness
    assert fd.provenance["skeptic"]["skills_version"] == "sk-1"
    assert s["q"].stage_runs == ["101-triage", "101-hypothesise", "101-static_verify-H1", "101-skeptic-H1"]
    assert s["q"].cost == pytest.approx(2.0)
    usd, ttl, models = s["minted"][0][1:]
    assert s["minted"][0][0] == 101
    assert usd > 0
    assert ttl > 600
    assert "judge" in models

    # skeptic got trusted snapshot slices, not agent quotes
    sk_spec = next(sp for sp in s["runner"].specs if sp.task.stage == Stage.skeptic)
    sk_in = s["runner"].inputs[sk_spec.task.task_id]
    hyp_json = sk_in["hypothesis.json"]
    assert "quote" not in hyp_json
    assert "SELECT" not in hyp_json
    slices = sk_in["code_slices.md"]
    assert "return q('SELECT * FROM orders WHERE id=' + oid)" in slices
    assert set(sk_spec.task.context_files) == {"hypothesis.json", "static_verify.json", "code_slices.md", "output_schema.json"}
    assert "diff.patch" not in sk_spec.task.context_files
    # every task got schema + task.json and gateway env
    for sp in s["runner"].specs:
        files = s["runner"].inputs[sp.task.task_id]
        assert json.loads(files["output_schema.json"]) == sp.task.output_schema
        assert "task.json" in files
        assert sp.env["PRSEC_GATEWAY_KEY"] == "sk-scan"
        assert sp.network == "prsec-scan-101"
        assert "PRSEC_GATEWAY_KEY_SCOPE" not in sp.env
    hyp_in = s["runner"].inputs["101-hypothesise"]
    assert json.loads(hyp_in["pr.json"])["title"] == "Add order lookup"
    assert json.loads(hyp_in["triage.json"])["decision"] == "full"
    assert "prior_findings.json" not in hyp_in
    # evidence is stored outside the (deleted) work dir and linked from stage runs and the finding
    assert not (settings().work_root / "101").exists()
    tr = s["q"].transcripts["101-static_verify-H1"]
    assert tr
    assert tr.startswith("file://")
    assert "evidence/acme/shop/7/" in tr
    assert Path(tr[7:]).is_file()
    assert fd.evidence_uri == tr


def test_skeptic_refuted_is_inconclusive(env):
    s = env(script=full_script(skeptic_refuted=True))
    pipeline.run_scan(ROW)
    [fd] = s["sink"].calls[0][2]
    assert fd.label == Label.inconclusive
    assert fd.label_reason == "skeptic_refuted"


def test_plausible_and_failed_static(env):
    hyps = [hyp("H1"), hyp("H2"), hyp("H3", severity="low")]

    def sv(t):
        hid = t.task_id.rsplit("-", 1)[1]
        return StageStatus.timeout if hid == "H2" else static(hid, verdict="plausible", reachable="unknown")

    s = env(script=full_script(hyps=hyps, static_fn=sv))
    pipeline.run_scan(ROW)
    _, _, findings, meta = s["sink"].calls[0]
    # H1 and H2 share a fingerprint (same class/sink/route) -> deduped to one
    assert len(findings) == 1
    assert findings[0].label_reason in {"plausible_static_only", "static_verify_unavailable"}
    assert {"id": "H3", "reason": "below_static_verify_min_severity"} in meta["dropped"]
    assert "101-static_verify-H3" not in s["q"].stage_runs
    # a plausible / reachability-unknown verdict stays inconclusive whatever a skeptic says: no skeptic run
    assert not any("skeptic" in r for r in s["q"].stage_runs)


def test_hypothesis_cap(env):
    hyps = [hyp(f"H{i}") for i in range(1, 6)]
    s = env(script=full_script(hyps=hyps), policy_update={"max_hypotheses": 2})
    pipeline.run_scan(ROW)
    meta = s["sink"].calls[0][3]
    assert [d["id"] for d in meta["dropped"] if d["reason"] == "over_cap"] == ["H3", "H4", "H5"]
    assert sum(1 for r in s["q"].stage_runs if "static_verify" in r) == 2


def test_triage_failure_fails_open(env):
    script = full_script(hyps=[])
    script["triage"] = lambda t: StageStatus.output_invalid
    s = env(script=script)
    pipeline.run_scan(ROW)
    f = only(s["q"])
    assert f["status"] == ScanStatus.done
    assert f["triage"]["source"] == "fallback"


def test_failure_path_cleans_up(env):
    s = env(script=full_script(), sink=FakeSink(fail=True))
    pipeline.run_scan(ROW)
    f = only(s["q"])
    assert f["status"] == ScanStatus.failed
    assert "minio down" in f["error"]
    assert s["runner"].destroyed == [101]
    assert s["revoked"] == ["sk-scan"]


def test_failure_before_network(env):
    s = env(script=full_script(), fail_network=True)
    pipeline.run_scan(ROW)
    assert only(s["q"])["status"] == ScanStatus.failed
    assert s["runner"].destroyed == [101]
    assert s["revoked"] == ["sk-scan"]


def test_runner_exception_becomes_stage_failure(env):
    script = full_script()

    def boom(t):
        raise RuntimeError("container died")

    script["static_verify"] = boom
    s = env(script=script)
    pipeline.run_scan(ROW)
    [fd] = s["sink"].calls[0][2]
    assert fd.label == Label.inconclusive
    assert fd.label_reason == "static_verify_unavailable"


def test_repo_disabled(env):
    from prsec.config import RepoOverride

    s = env(policy_update={"repos": {"acme/*": RepoOverride(enabled=False)}})
    pipeline.run_scan(ROW)
    assert only(s["q"])["triage"]["reason"] == "repo_disabled"


def test_failed_hypothesise_is_incomplete_not_clean(env):
    script = full_script()
    script["hypothesise"] = lambda t: StageStatus.timeout
    s = env(script=script)
    pipeline.run_scan(ROW)
    f = only(s["q"])
    assert f["status"] == ScanStatus.failed
    assert "hypothesise stage timeout" in f["error"]
    assert f["sarif_uri"]  # the SARIF still records the run, marked unsuccessful
    _, _, findings, meta = s["sink"].calls[0]
    assert findings == []
    assert meta["complete"] is False
    assert meta["errors"]


def test_moved_head_supersedes_and_enqueues_current_head(env):
    class MovedSCM(FakeSCM):
        def get_pr(self, repo, number, installation_id=None):
            return super().get_pr(repo, number).model_copy(update={"head_sha": "n" * 40})

    s = env(script=full_script(), scm=MovedSCM(CODE_DIFF))
    pipeline.run_scan(ROW)
    assert only(s["q"])["status"] == ScanStatus.superseded
    [(req, skills)] = s["q"].enqueued
    assert (req.head_sha, req.pr, req.repo, req.installation_id, skills) == ("n" * 40, 7, "acme/shop", 5, "sk-1")
    assert not s["runner"].specs
    assert not s["sink"].calls


def test_per_task_gateway_keys_and_authoritative_cost(env, monkeypatch):
    s = env(script=full_script())
    minted, spent = [], {}
    monkeypatch.setattr(pipeline.gateway, "per_task_keys", lambda: True)
    monkeypatch.setattr(pipeline.gateway, "mint_key",
                        lambda scan_id, usd, ttl, models, task_id=None: minted.append((task_id, usd, models)) or f"sk-{task_id}")
    monkeypatch.setattr(pipeline.gateway, "key_spend", lambda key: spent.setdefault(key, 1.25))
    pipeline.run_scan(ROW)
    assert only(s["q"])["status"] == ScanStatus.done
    tasks = ["101-triage", "101-hypothesise", "101-static_verify-H1", "101-skeptic-H1"]
    assert [m[0] for m in minted] == tasks
    policy = load_policy()
    assert minted[1][1] == policy.defaults["hypothesise"].usd_budget
    assert minted[1][2] == [policy.defaults["hypothesise"].model]
    for sp in s["runner"].specs:
        assert sp.env["PRSEC_GATEWAY_KEY"] == f"sk-{sp.task.task_id}"
        assert sp.env["PRSEC_GATEWAY_KEY_SCOPE"] == "task"
    assert s["q"].cost == pytest.approx(1.25 * 4)  # gateway spend, not the harness-reported 0.5
    assert sorted(s["revoked"]) == sorted([f"sk-{t}" for t in tasks] + [""])


def test_lease_lost_stops_without_writing(env):
    q = FakeQueue(lease_lost_after=1)  # pre-triage check passes, pre-hypothesise check fails
    s = env(script=full_script(), q=q)
    pipeline.run_scan({**ROW, "lease_token": "tok-123456789abcdef"})
    assert q.finished == []
    assert not s["sink"].calls
    assert s["runner"].destroyed == []  # the new owner's containers/network are left alone
    assert q.stage_runs == ["101-triage"]
    assert not any(settings().work_root.glob("101*"))


def test_cleanup_precedes_lease_release_and_token_is_passed(env):
    q = FakeQueue()
    s = env(script=full_script(), q=q)
    pipeline.run_scan({**ROW, "lease_token": "tok-123456789abcdef"})
    f = only(q)
    assert f["status"] == ScanStatus.done
    assert f["lease_token"] == "tok-123456789abcdef"
    assert q.events[-2:] == ["destroy", "finish"]
    assert s["runner"].specs[0].src_dir == settings().work_root / "101-tok-12345678" / "src"
    assert not (settings().work_root / "101-tok-12345678").exists()


def test_prior_findings_are_given_to_hypothesise(env):
    s = env(script=full_script())
    s["prior"] = [{
        "fingerprint": "fp1", "bug_class": "idor", "vuln_class": "technical", "title": "IDOR on orders",
        "severity": "high", "label": "likely", "sink_file": "app/orders.py", "sink_line": 5,
        "data": {"entry_point": "GET /orders/1", "head_sha": "o" * 40,
                 "sink": {"file": "app/orders.py", "line": 5, "snippet": "return q(...)"}},
    }]
    pipeline.run_scan(ROW)
    hyp_in = s["runner"].inputs["101-hypothesise"]
    prior = json.loads(hyp_in["prior_findings.json"])["prior_findings"]
    assert prior[0]["fingerprint"] == "fp1"
    assert prior[0]["sink"]["snippet_at_previous_head"] == "return q(...)"
    assert "prior_findings.json" in s["runner"].specs[1].task.context_files
    assert "prior_findings.json" not in s["runner"].inputs["101-static_verify-H1"]


def test_container_paths_in_citations_are_relativised(env):
    abs_sink = {**SINK, "file": "/work/src/app/orders.py"}
    s = env(script=full_script(hyps=[hyp(sink=abs_sink)]))
    pipeline.run_scan(ROW)
    [fd] = s["sink"].calls[0][2]
    assert fd.sink.file == "app/orders.py"
    assert fd.label == Label.likely
    assert fd.fingerprint == fingerprint("sqli", "app/orders.py", "get_order", "GET /orders/123")

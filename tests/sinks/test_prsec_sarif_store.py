import json
from pathlib import Path

import pytest
from _factories import finding, pr

from prsec.adapters.sinks import get_sink, sarif_store
from prsec.config import settings


@pytest.fixture
def local_store(tmp_path, monkeypatch):
    monkeypatch.setenv("PRSEC_SARIF_DIR", str(tmp_path))
    monkeypatch.setattr(settings(), "s3_access_key", "")
    calls = []
    import prsec.db.findings as dbf

    monkeypatch.setattr(dbf, "upsert_findings", lambda *a, **kw: calls.append((a, kw)))
    return tmp_path, calls


def test_local_dir_fallback(local_store):
    root, calls = local_store
    sink = get_sink()
    assert sink.name == "sarif-store"
    f = finding()
    uri = sink.write_scan(5, pr(), [f], {"changed_files": ["app/orders.py", "README.md"], "skills_version": "v1"})
    path = root / "sarif/acme/shop/7" / ("a" * 40 + ".sarif")
    assert uri == path.resolve().as_uri() and path.exists()
    doc = json.loads(path.read_text())
    assert doc["runs"][0]["results"][0]["partialFingerprints"]["prsec/v1"] == f.fingerprint
    assert "changed_files" not in doc["runs"][0]["properties"]
    (args, kw) = calls[0]
    assert args == (5, "acme/shop", 7, [f]) and kw == {"scanned_files": {"app/orders.py", "README.md"}}
    assert json.loads(sarif_store.read_uri(uri)) == doc


def test_read_uri_refuses_outside_root(local_store, tmp_path_factory):
    other = tmp_path_factory.mktemp("other") / "x.sarif"
    other.write_text("{}")
    with pytest.raises(PermissionError):
        sarif_store.read_uri(other.as_uri())
    with pytest.raises(ValueError):
        sarif_store.read_uri("http://example.com/x")


def test_s3_path(monkeypatch):
    class FakeMinio:
        def __init__(self):
            self.buckets, self.objects = set(), {}

        def bucket_exists(self, b):
            return b in self.buckets

        def make_bucket(self, b):
            self.buckets.add(b)

        def put_object(self, b, key, data, length, content_type):
            self.objects[(b, key)] = data.read()
            assert length == len(self.objects[(b, key)])

    fake = FakeMinio()
    monkeypatch.setattr(settings(), "s3_access_key", "minio")
    monkeypatch.setattr(sarif_store, "_minio", lambda: fake)
    uri = sarif_store.put_bytes("sarif/acme/shop/7/x.sarif", b"{}")
    assert uri == f"s3://{settings().s3_bucket}/sarif/acme/shop/7/x.sarif"
    assert settings().s3_bucket in fake.buckets and fake.objects[(settings().s3_bucket, "sarif/acme/shop/7/x.sarif")] == b"{}"


def test_unknown_sink():
    with pytest.raises(ValueError):
        get_sink("nope")


def test_incomplete_scan_marks_nothing_stale(local_store):
    root, calls = local_store
    get_sink().write_scan(6, pr(), [], {"changed_files": ["app/orders.py"], "complete": False, "errors": ["boom"]})
    (args, kw) = calls[0]
    assert args == (6, "acme/shop", 7, []) and kw == {"scanned_files": set()}

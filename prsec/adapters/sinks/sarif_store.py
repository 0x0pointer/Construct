"""SARIF to object storage (MinIO/S3) or a local dir, plus the Postgres findings index."""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
from urllib.parse import unquote, urlparse

from prsec.config import settings
from prsec.models import Finding, PRInfo
from prsec.sarif.builder import build_sarif


def sarif_key(repo: str, pr: int, head_sha: str) -> str:
    return f"sarif/{repo}/{pr}/{head_sha}.sarif"


def local_dir() -> Path:
    """Fallback root when no S3 credentials are configured (PRSEC_SARIF_DIR overrides)."""
    return Path(os.environ.get("PRSEC_SARIF_DIR") or settings().work_root / "artifacts")


def _minio():
    from minio import Minio

    s = settings()
    return Minio(s.s3_endpoint, access_key=s.s3_access_key, secret_key=s.s3_secret_key, secure=s.s3_secure)


def put_bytes(key: str, data: bytes, content_type: str = "application/sarif+json") -> str:
    s = settings()
    if not s.s3_access_key:
        dest = (local_dir() / key).resolve()
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        return dest.as_uri()
    client = _minio()
    if not client.bucket_exists(s.s3_bucket):
        client.make_bucket(s.s3_bucket)
    client.put_object(s.s3_bucket, key, io.BytesIO(data), len(data), content_type=content_type)
    return f"s3://{s.s3_bucket}/{key}"


def read_uri(uri: str) -> bytes:
    """Fetch an object written by `put_bytes` (s3:// or file://)."""
    u = urlparse(uri)
    if u.scheme == "file":
        path = Path(unquote(u.path)).resolve()
        root = local_dir().resolve()
        if not path.is_relative_to(root):
            raise PermissionError(f"{path} is outside {root}")
        return path.read_bytes()
    if u.scheme == "s3":
        resp = _minio().get_object(u.netloc, u.path.lstrip("/"))
        try:
            return resp.read()
        finally:
            resp.close()
            resp.release_conn()
    raise ValueError(f"unsupported uri {uri!r}")


def evidence_key(repo: str, pr: int, head_sha: str, task_id: str, name: str) -> str:
    return f"evidence/{repo}/{pr}/{head_sha}/{task_id}/{name}"


class SarifStoreSink:
    name = "sarif-store"

    def write_scan(self, scan_id: int, pr: PRInfo, findings: list[Finding], meta: dict) -> str:
        sarif = build_sarif(pr, scan_id, findings, meta)
        data = json.dumps(sarif, indent=2, default=str).encode()
        uri = put_bytes(sarif_key(pr.repo, pr.number, pr.head_sha), data)

        from prsec.db.findings import upsert_findings

        # An incomplete analysis (a required stage failed) did not really look, so it must not
        # retire anything: no file counts as scanned and nothing becomes stale.
        changed = (meta.get("changed_files") or pr.changed_files) if meta.get("complete", True) else []
        upsert_findings(scan_id, pr.repo, pr.number, findings, scanned_files=set(changed))
        return uri

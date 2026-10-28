"""Test-suite-wide setup.

Unit tests run against the packaged policy (prsec/policy/policy.yaml), never a developer's
dev-pilot `.env`. That `.env` can repoint PRSEC_POLICY_PATH at policy-dev.yaml — which, for an
OpenAI-only pilot, turns dynamic validation off — and pydantic-settings would otherwise read it
from the repo root and change policy-dependent tests (scan budgets, the dynamic pipeline).

Setting PRSEC_POLICY_PATH in os.environ here (before `prsec.config.settings()` is first read)
overrides the `.env` value, since real environment variables outrank the dotenv file. `setdefault`
still lets a developer point the suite elsewhere on purpose.
"""
import os
from pathlib import Path

os.environ.setdefault(
    "PRSEC_POLICY_PATH",
    str(Path(__file__).resolve().parents[1] / "prsec" / "policy" / "policy.yaml"),
)

"""Sanity checks on the Dockerfiles and the harness volume build script (no docker needed)."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BUILD_SH = ROOT / "images" / "harness" / "build.sh"


def _dockerfile(name: str) -> str:
    return (ROOT / "images" / name / "Dockerfile").read_text()


def test_prsec_image_runs_non_root() -> None:
    text = _dockerfile("prsec")
    assert "FROM python:3.12-slim" in text
    assert "USER prsec" in text
    assert "--uid 10001" in text


def test_workbench_image() -> None:
    text = _dockerfile("workbench-base")
    assert "FROM ubuntu:24.04" in text
    assert "--uid 10001" in text
    assert "USER agent" in text
    assert 'ENTRYPOINT ["prsec-stage"]' in text
    for tool in ("git", "ripgrep", "jq", "curl", "python3"):
        assert tool in text
    for harness_pkg in ("@anthropic-ai/claude-code", "@openai/codex", "opencode-ai", "pi-coding-agent"):
        assert harness_pkg not in text


def test_dockerignores_exclude_secrets() -> None:
    for name in ("prsec", "workbench-base"):
        lines = (ROOT / "images" / name / "Dockerfile.dockerignore").read_text().split()
        assert lines[0] == "*"  # allow-list only


def test_build_sh_is_executable_and_parses() -> None:
    assert BUILD_SH.stat().st_mode & 0o111
    subprocess.run(["bash", "-n", str(BUILD_SH)], check=True)


@pytest.mark.parametrize(
    "args",
    [[], ["claude-code", "1.0.0"], ["nope", "1.0.0", "/tmp/x"], ["codex", "1.0;id", "/tmp/x"], ["pi", "../1", "/tmp/x"]],
)
def test_build_sh_rejects_bad_args(args: list[str], tmp_path: Path) -> None:
    if len(args) == 3:
        args[2] = str(tmp_path)
    proc = subprocess.run(["bash", str(BUILD_SH), *args], capture_output=True, text=True, timeout=30)
    assert proc.returncode == 2
    assert not any(tmp_path.iterdir())


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck not installed")
def test_build_sh_shellcheck() -> None:
    subprocess.run(["shellcheck", str(BUILD_SH)], check=True)

"""Harness-neutral stage prompt templates (Jinja2)."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import jinja2

FILE_NOTES = {
    "pr.json": "PR title, description, author and commit messages (the author's stated intent)",
    "diff.patch": "unified diff of the PR (base...head)",
    "changed_files.txt": "changed file paths, one per line",
    "triage.json": "triage decision, risk tags and focus files",
    "hypothesis.json": "the hypothesis under review",
    "static_verify.json": "the static verifier's verdict",
    "code_slices.md": "cited code excerpts from the repository at the PR head",
    "repo_profile.json": "repository profile: stack, routes, auth model, glossary",
    "output_schema.json": "JSON Schema your output must satisfy",
    "prior_findings.json": "findings reported on earlier commits of this PR, to re-confirm or retire",
}


@lru_cache
def _env() -> jinja2.Environment:
    return jinja2.Environment(
        loader=jinja2.FileSystemLoader(Path(__file__).parent),
        undefined=jinja2.StrictUndefined,
        autoescape=False,
        keep_trailing_newline=True,
        trim_blocks=False,
    )


def render(stage: str, **ctx: Any) -> str:
    ctx.setdefault("file_notes", FILE_NOTES)
    return _env().get_template(f"{stage}.md").render(**ctx)

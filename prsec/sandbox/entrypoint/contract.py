"""The output contract the entrypoint appends to every stage prompt, and output validation."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from pydantic import BaseModel, ValidationError

from prsec.models import StageTask
from prsec.stages.outputs import model_for

SCHEMA_FILE = "output_schema.json"  # the one schema file every prompt names: `{in_dir}/output_schema.json`
MAX_ECHO_CHARS = 20_000
MAX_ERRORS = 25


def schema_path(task: StageTask) -> Path:
    return Path(task.in_dir) / SCHEMA_FILE


def write_schema(task: StageTask) -> Path:
    """Ensure the schema file matches task.output_schema (the orchestrator usually wrote it already)."""
    path = schema_path(task)
    text = json.dumps(task.output_schema, indent=2)
    try:
        if json.loads(path.read_text()) == task.output_schema:
            return path
    except (OSError, ValueError):
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def output_contract(task: StageTask) -> str:
    inputs = "\n".join(f"  - `{Path(task.in_dir) / f}`" for f in task.context_files) or "  - (none)"
    return f"""

---

## OUTPUT CONTRACT (mandatory)

- **Repository** (read-only): `{task.workdir}`. Do NOT modify, create or delete files in it.
- **Inputs** are files in `{task.in_dir}`:
{inputs}
- **Tools:** a standard shell. Use `prsec-cite check <file> --root {task.workdir}` to verify that
  every `file`/`line`/`quote` citation in your output matches the code before you finish.
- **Output:** write exactly ONE JSON document to `{task.output_path}`. It MUST validate against the
  JSON Schema in `{schema_path(task)}`. Write the file with a shell command or file-write tool;
  do not print the JSON as your answer. No markdown fences, no comments, no trailing text in the file.
- Citations must quote the code verbatim (at least one full line) at the cited file and line.
- When the output file is written and verified, reply with the single word `DONE`.
"""


def compose_prompt(task: StageTask) -> str:
    return task.prompt_md.rstrip() + output_contract(task)


def _pydantic_model(task: StageTask) -> type[BaseModel] | None:
    try:
        model = model_for(task.stage)
    except KeyError:
        return None
    # Only apply the pydantic model when the task's schema was generated from it.
    return model if task.output_schema.get("title") == model.__name__ else None


def validate_output(task: StageTask) -> tuple[dict[str, Any] | None, list[str], str | None]:
    """Returns (validated output, errors, raw text). Output is None iff errors is non-empty."""
    path = Path(task.output_path)
    if not path.is_file():
        return None, [f"output file {task.output_path} was not written"], None
    raw = path.read_text(encoding="utf-8", errors="replace")
    try:
        doc = json.loads(raw)
    except ValueError as e:
        return None, [f"output is not valid JSON: {e}"], raw

    errors = [
        f"{e.json_path}: {e.message}"
        for e in sorted(Draft202012Validator(task.output_schema).iter_errors(doc), key=lambda e: list(e.path))
    ]
    if errors:
        return None, errors[:MAX_ERRORS], raw
    if not isinstance(doc, dict):
        return None, ["output must be a JSON object"], raw

    model = _pydantic_model(task)
    if model is not None:
        try:
            doc = model.model_validate(doc).model_dump(mode="json")
        except ValidationError as e:
            errs = [f"$.{'.'.join(map(str, err['loc']))}: {err['msg']}" for err in e.errors()]
            return None, errs[:MAX_ERRORS], raw
    return doc, [], raw


def _errors_md(errors: list[str]) -> str:
    return "\n".join(f"- {e}" for e in errors)


def repair_prompt_resume(task: StageTask, errors: list[str], moved_to: str | None) -> str:
    moved = f" The invalid file was moved to `{moved_to}`." if moved_to else ""
    return f"""Your output at `{task.output_path}` failed validation against `{schema_path(task)}`.{moved}

Validation errors:
{_errors_md(errors)}

Fix these problems and write the complete, corrected JSON document to `{task.output_path}`
(the whole document, not a patch). Do not modify the repository. When done, reply `DONE`."""


def repair_prompt_fresh(task: StageTask, errors: list[str], previous: str | None) -> str:
    prev = (previous or "")[:MAX_ECHO_CHARS]
    prev_md = f"\n```json\n{prev}\n```\n" if prev else "\n(no output file was written)\n"
    return (
        compose_prompt(task)
        + f"""

---

## REPAIR: a previous attempt produced invalid output

Previous output:
{prev_md}
Validation errors:
{_errors_md(errors)}

Re-do the task as needed and write a complete, valid JSON document to `{task.output_path}`.
"""
    )

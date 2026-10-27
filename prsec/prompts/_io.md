## Working environment

{% if has_tools -%}
- The repository at the PR head commit is checked out read-only at `{{ workdir }}`. Read any file you need; follow callers and callees beyond the diff.
- Your inputs are files in `{{ in_dir }}`:
{%- for f in context_files %}
  - `{{ in_dir }}/{{ f }}`{% if f in file_notes %} — {{ file_notes[f] }}{% endif %}
{%- endfor %}
{%- if app_dir is defined and app_dir %}
- You may run shell commands (for example `cat`, `grep`, `find`, `sed -n`) to inspect code. Do not modify the repository checkout. Install, build and run the application only with the tools described under "The environment" below, which work in a writable copy under `{{ app_dir }}`.
{%- else %}
- You may run read-only shell commands (for example `cat`, `grep`, `find`, `sed -n`) to inspect code. Do not modify the repository, do not install anything, and do not contact external services.
{%- endif %}
{% else -%}
- You cannot run commands or open files. The contents of your input files are included after this prompt, each under a heading with its file name:
{%- for f in context_files %}
  - `{{ f }}`{% if f in file_notes %} — {{ file_notes[f] }}{% endif %}
{%- endfor %}
- Base your answer only on that material. Where something you would need is not shown, say so in your reasoning instead of guessing.
{% endif %}
{%- if skills %}

## Methodology skills

These skills describe how AppSec wants this job done. {% if has_tools %}Before you start, read the `SKILL.md` of each relevant skill (under `{{ skills_dir }}/<name>/`, or wherever your environment lists them) and follow it.{% else %}Their guidance is included with your inputs where available; follow it.{% endif %}
{% for s in skills %}
- `{{ s }}`
{%- endfor %}
{%- endif %}

## Output

{% if has_tools -%}
Write exactly one JSON object to `{{ output_path }}`. It must validate against the JSON Schema in `{{ in_dir }}/output_schema.json`. Write the file even when your conclusion is negative. Do not write anything else to that path, and do not wrap the JSON in Markdown.
{%- else -%}
Reply with exactly one JSON object and nothing else (no Markdown fences, no commentary). It must validate against the JSON Schema in `output_schema.json`.
{%- endif %}

Citations: every `file` is a path relative to the repository root, `line`/`end_line` are 1-based line numbers at the PR head, and `quote` is copied verbatim from those lines (at least one full line). Citations are checked mechanically against the real code; a finding with a wrong or invented citation is discarded.

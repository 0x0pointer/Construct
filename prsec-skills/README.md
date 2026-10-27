# prsec-skills

The methodology behind PRSec: harness-neutral skills used by the scan stages. They work with any
agent that can **read files, run shell commands and write files**. Nothing in here may depend on a
feature of one particular agent runtime.

| Skill | Used by stage | Purpose |
|---|---|---|
| [triage](triage/SKILL.md) | `triage` | Is this PR worth scanning: `skip`, `light` or `full` |
| [taint-analysis](taint-analysis/SKILL.md) | `hypothesise` | Technical source-to-sink hypotheses, per language and framework |
| [business-logic](business-logic/SKILL.md) | `hypothesise` | Intended vs actual workflow, invariants, abuse cases |
| [static-validation](static-validation/SKILL.md) | `static_verify`, `skeptic` | Refute-first verification of one hypothesis, one reference per bug class |
| [org](org/SKILL.md) | `hypothesise`, `static_verify` | Company knowledge: internal auth libraries, safe wrappers, glossary |

[evals/](evals/README.md) holds the labelled corpus that every skills change is measured against.

## Contract every skill follows

1. **Inputs are files.** The stage prompt names the input directory (normally `/work/in`) holding
   `diff.patch`, `pr.json`, and optionally `repo_profile.json` and `prior_findings.json`. The
   repository at the PR head is the working directory (normally `/work/src`).
2. **Output is one JSON file** at the path the prompt names, valid against the stage schema. The
   field names used throughout these skills are exactly the schema fields (`decision`,
   `hypotheses[].sink`, `verdict`, `citations[]`, ...).
3. **Non-interactive.** Nobody answers questions. If information is missing, decide, say what you
   assumed in the free-text field (`rationale`, `description`, `reasoning`) and move on.
4. **Evidence is a citation.** A citation is `{file, line, end_line?, quote}`: a repo-relative
   path, a 1-based line number, and a verbatim copy of the code on those lines. Citations are
   checked by code after the stage ends; a citation that does not match the file drops the
   hypothesis. When a shell is available run `prsec-cite check <output.json>` before finishing.
5. **One vocabulary.** `bug_class` values come from [bug-classes.yaml](bug-classes.yaml) only.
6. **Tools are shell CLIs** on `PATH` (`prsec-cite`, later `prsec-env`, `prsec-http`, `prsec-poc`).
   Use plain shell (`grep -rn`, `sed -n`, `cat`, `find`, `git` if present) for everything else.

## Writing or changing a skill

- One directory per skill with a `SKILL.md` whose YAML frontmatter has `name` (equal to the
  directory name) and a one-line `description` of at most 1024 characters.
- Keep `SKILL.md` focused on method; push long per-language or per-class detail into
  `references/*.md` and link to it relatively.
- Write for a single non-interactive run: no delegation to helpers, no tool names that only one
  agent runtime has, no interactive commands, no attack tooling. Describe actions generically
  ("search the repository for callers of `f`") or via the `prsec-*` CLIs.
- Run `prsec-skills-lint prsec-skills/` and the eval smoke subset before merging. If a term is
  legitimately needed (e.g. in an example of what not to write), add
  `<!-- lint-allow: reason -->` to that line.

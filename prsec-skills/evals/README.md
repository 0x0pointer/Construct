# Eval corpus

Labelled PR cases that every skills change is measured against: seeded vulnerabilities **and**
known false positives, per bug class. The corpus runs as a harness x model matrix; the dashboard
reports precision and recall per bug class, label and combination.

## Layout of one case

```
cases/<case-id>/
  pr.json          # PR metadata the agent sees: title, body, commits, changed_files
  diff.patch       # unified diff, paths a/<file> b/<file>, relative to repo/
  repo/            # the tiny repository at the PR head (what the agent reads)
  expected.json    # labels, validated against expected.schema.json
```

`repo/` is the **head** state. `diff.patch` must be the exact diff from base to head, so that
reverse-applying it to `repo/` yields the base (`git apply -R --check` inside `repo/` must pass).
Keep cases tiny: a handful of files, no dependencies to install, no generated code.

## expected.json

Schema: [expected.schema.json](expected.schema.json). Fields:

| Field | Meaning |
|---|---|
| `id` | equals the directory name |
| `description` | one or two sentences: what the PR does and what the right answer is |
| `stack` | e.g. `python-flask`, `node-express`, `java-spring` |
| `known_false_positive` | `true` when the case exists to catch over-reporting |
| `triage.acceptable` | triage decisions counted as correct |
| `expected_findings[]` | findings that must be reported: canonical `bug_class`, `vuln_class`, `sink_file`, optional `sink_lines` `[start, end]` the sink citation must fall in, acceptable `static_verdicts` and final `labels`, optional `min_severity`, `introduced` |
| `expected_refutations[]` | hypotheses that may be raised but must end `refuted` in static validation |
| `must_not_find[]` | findings whose presence is a false positive |

Matching rule: a reported finding matches an expectation when `bug_class` (after alias
normalisation via `bug-classes.yaml`) and `sink_file` are equal and, if given, the sink line is
inside `sink_lines`. Any reported finding that matches nothing is counted as a false positive.

In phase 1 (static only) the best possible label is `likely`; list `reproduced` as well once a
case is meant to be validated dynamically.

## Adding a case

1. Start from a real PR (or a false positive reported by AppSec triage in the dashboard). Strip
   it down to the smallest repo that still shows the behaviour; rename business terms if needed.
2. Create `repo/` at the head state and `diff.patch` from base to head
   (e.g. `git diff --no-index --no-prefix base head`, then rewrite paths to `a/` and `b/`).
3. Write `pr.json` with the real intent wording; the PR text is part of what is being tested.
4. Write `expected.json`. For every false positive, add a `must_not_find` entry with the reason
   the code is safe; that reason is what the static-validation skill should have found.
5. Run the repository's test suite: `tests/skills` validates every case against the schema,
   checks that `id` equals the directory name, that bug classes are canonical, that sink lines
   exist in `repo/`, and that the diff reverse-applies cleanly.
6. Add the case to the smoke subset only if it is fast and discriminating.

## Seed cases

| Case | Expectation |
|---|---|
| [sqli-new-endpoint](cases/sqli-new-endpoint/expected.json) | `full` triage; `sqli` at `app.py` 35-37, label `likely` |
| [sqli-parameterised](cases/sqli-parameterised/expected.json) | same feature, bound parameters: any `sqli` hypothesis must be `refuted` (known false positive) |
| [css-only](cases/css-only/expected.json) | `skip` |

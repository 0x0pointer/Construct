# Spec for issue #5: update readme

## Summary
Add a small paragraph to the repository root `README.md` explaining how approved GitHub issues are built through the Fabro issue-to-PR pipeline. The paragraph should be concise, point maintainers to the existing `.fabro/README.md` for full details, and mention the main workflow: approve an issue with the `fabro-approved` label, run the Fabro workflow/`construct-build`, review the generated spec, then review the draft PR.

## Scope (files to change)
- `README.md`
  - Add a short documentation paragraph or subsection about building approved issues with Fabro.
  - Prefer placing it near the project setup/development guidance, e.g. after the initial "Getting started" overview or near the end before detailed operational sections, so it is discoverable without disrupting user deployment instructions.

## Out of scope
- No changes to `.fabro/` workflow files, scripts, Docker image, or configuration.
- No changes to CI, deployment manifests, package dependencies, or runtime code under `prsec/`.
- No changes to the existing Fabro process beyond documenting it in the root README.
- No command execution required by the issue text beyond normal repository inspection and test validation.

## Design
- Add a concise README section, for example `### Building approved issues with Fabro` or `## Issue-to-PR workflow with Fabro`.
- The text should summarize the existing process already documented in `.fabro/README.md`:
  - A maintainer applies `fabro-approved` to an open issue.
  - A maintainer runs `construct-build` or `fabro run .fabro/workflows/issue-to-pr/workflow.toml -I issue=<number>`.
  - Fabro verifies the issue approval, installs the project in a clean sandbox, writes a spec, pauses for human review, implements the change, runs verification, and opens a draft PR.
  - Maintainers review the resulting draft PR before merge.
- Include a relative link to `.fabro/README.md` so the README stays brief while the detailed operational and security guidance remains in one place.
- Keep the wording factual and aligned with current repository terminology (`fabro-approved`, `construct-build`, draft PR, spec approval).

## Test plan (which tests to add or update under tests/)
- No new tests under `tests/` are necessary because this is a documentation-only README change and does not alter package behavior.
- Run the existing fast test suite to confirm no unintended changes were introduced:
  - `make test`
- If a documentation lint/check is later added to the repository, update the plan to include it; none is currently present for README prose.

## Risks
- The root README could duplicate or drift from `.fabro/README.md`. Mitigate by keeping the new text short and linking to `.fabro/README.md` for authoritative details.
- Placing the paragraph in the wrong section could distract from user installation/deployment instructions. Mitigate by using a small, clearly titled subsection.
- Over-specifying workflow internals in the root README could require frequent updates. Mitigate by describing only stable high-level steps.

## Suspicious content
none
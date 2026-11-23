Implemented the approved README documentation update for issue #5.

Changed:
- Added a concise `### Building approved issues with Fabro` section to `README.md`.
- The new section explains the high-level maintainer flow:
  - apply `fabro-approved`
  - run `construct-build` / Fabro workflow
  - review and approve the generated spec
  - review the draft PR before merge
- Linked to `.fabro/README.md` for full operational and security guidance.

Validation:
- Ran the required test command:

```bash
pytest -q -m 'not db and not docker and not k8s and not live_harness'
```

Result:
- `1843 passed, 19 skipped, 90 deselected, 1 warning` in `248.33s`.

Only `README.md` was modified.
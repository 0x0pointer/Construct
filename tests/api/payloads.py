from __future__ import annotations

import copy
from typing import Any

_BASE: dict[str, Any] = {
    "action": "opened",
    "number": 7,
    "pull_request": {
        "number": 7,
        "state": "open",
        "draft": False,
        "head": {"sha": "a" * 40, "ref": "feat", "repo": {"full_name": "acme/api"}},
        "base": {"sha": "b" * 40, "ref": "main", "repo": {"full_name": "acme/api"}},
    },
    "repository": {"full_name": "acme/api"},
    "installation": {"id": 99},
}


def pr_payload(**overrides: Any) -> dict[str, Any]:
    p = copy.deepcopy(_BASE)
    for key, value in overrides.items():
        target = p
        *parents, leaf = key.split("__")
        for part in parents:
            target = target[part]
        target[leaf] = value
    return p

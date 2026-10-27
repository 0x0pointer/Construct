"""SCM adapters. `get_scm()` returns a process-wide instance so token caches are shared."""
from __future__ import annotations

import threading

from prsec.adapters.protocols import SCMAdapter

_instances: dict[str, SCMAdapter] = {}
_lock = threading.Lock()


def get_scm(name: str = "github") -> SCMAdapter:
    with _lock:
        if name not in _instances:
            if name == "github":
                from prsec.adapters.scm.github import GitHubAppSCM

                _instances[name] = GitHubAppSCM()
            else:
                raise ValueError(f"unknown SCM adapter: {name!r}")
        return _instances[name]

"""Importing this package registers every adapter (see base.register)."""
from importlib import import_module

for _mod in ("claude_code", "codex", "opencode", "pi", "raw"):
    try:
        import_module(f"{__name__}.{_mod}")
    except ModuleNotFoundError as e:  # adapter file not written yet
        if e.name != f"{__name__}.{_mod}":
            raise

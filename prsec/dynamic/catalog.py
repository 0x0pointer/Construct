"""Allowlisted mock services (catalog.yaml). The launcher starts nothing that is not in here."""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

CATALOG_FILE = Path(__file__).with_name("catalog.yaml")
ALLOWED_CAPS = frozenset({"CHOWN", "SETUID", "SETGID", "DAC_OVERRIDE", "FOWNER"})


class CatalogEntry(BaseModel):
    image: str
    port: int
    env: dict[str, str] = Field(default_factory=dict)
    seed_path: str | None = None
    # Only data files: the images' entrypoints also execute *.sh (and mongo *.js) from seed_path,
    # as root in a container that does not get the workbench's hardening.
    seed_suffixes: list[str] = Field(default_factory=lambda: [".sql", ".sql.gz"])
    health: list[str] = Field(default_factory=list)  # exec'd in the container; [] = running is enough
    caps: list[str] = Field(default_factory=list)
    connection: str = ""

    def model_post_init(self, _: object) -> None:
        bad = set(self.caps) - ALLOWED_CAPS
        if bad:
            raise ValueError(f"catalog caps not allowed: {sorted(bad)}")


def seed_allowed(entry: CatalogEntry, name: str) -> bool:
    return any(name.lower().endswith(sfx) for sfx in entry.seed_suffixes)


class Catalog(BaseModel):
    services: dict[str, CatalogEntry]


@lru_cache
def load_catalog(path: str | None = None) -> Catalog:
    p = Path(path or os.environ.get("PRSEC_CATALOG_PATH") or CATALOG_FILE)
    return Catalog.model_validate(yaml.safe_load(p.read_text()))


def describe() -> str:
    """Markdown table of the catalog for the env-stage prompt."""
    rows = ["| kind | port | seed files (.sql / .sql.gz) | connection |", "|---|---|---|---|"]
    for kind, e in load_catalog().services.items():
        rows.append(f"| `{kind}` | {e.port} | {'yes' if e.seed_path else 'no'} | `{e.connection}` |")
    return "\n".join(rows)

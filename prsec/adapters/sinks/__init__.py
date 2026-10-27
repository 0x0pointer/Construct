from __future__ import annotations

from prsec.adapters.protocols import FindingsSink


def get_sink(name: str = "sarif-store") -> FindingsSink:
    if name == "sarif-store":
        from prsec.adapters.sinks.sarif_store import SarifStoreSink

        return SarifStoreSink()
    raise ValueError(f"unknown findings sink {name!r}")

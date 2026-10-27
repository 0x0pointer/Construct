import pytest

from prsec.obs import events


class Timeline:
    """Records timeline rows instead of inserting them (these tests run without Postgres)."""

    def __init__(self):
        self.rows: list[dict] = []

    def insert(self, row):
        self.rows.append(row)

    def kinds(self, scan_id=None) -> list[str]:
        return [r["kind"] for r in self.rows if scan_id is None or r["scan_id"] == scan_id]

    def of(self, kind) -> list[dict]:
        return [r for r in self.rows if r["kind"] == kind]


@pytest.fixture(autouse=True)
def timeline(monkeypatch):
    t = Timeline()
    events.reset_backoff()
    monkeypatch.setattr(events, "_insert", t.insert)
    return t

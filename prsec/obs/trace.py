"""prsec-trace: follow one scan's event timeline from the terminal.

    prsec-trace 42                    # everything recorded so far, then exit
    prsec-trace 42 --follow           # ... and keep printing new events until the scan finishes
    prsec-trace 42 --kinds triage,dynamic_outcome --no-agent
    prsec-trace 42 --json | jq .      # one raw event per line

Reads `scan_events` (prsec.obs.events.list_events) from PRSEC_DATABASE_URL.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Callable, Iterable
from datetime import datetime
from typing import Any, TextIO

from prsec.obs.logging import setup_logging

PAGE = 500
POLL_S = 2.0
TERMINAL = frozenset({"done", "skipped", "failed", "superseded"})
KIND_W = 17
WHERE_W = 24
DATA_MAX = 160

_COLOURS = {"debug": "\033[2m", "warning": "\033[33m", "error": "\033[31m"}
_RESET = "\033[0m"

Event = dict[str, Any]
Fetch = Callable[[int, int], list[Event]]  # (scan_id, after_id) -> events with id > after_id, ordered
Status = Callable[[int], str | None]  # scan status, None when the scan does not exist


# ------------------------------------------------------------------ formatting


def _clock(ts: Any) -> str:
    if isinstance(ts, str):
        try:
            ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            return ts[:8]
    if isinstance(ts, datetime):
        return (ts.astimezone() if ts.tzinfo else ts).strftime("%H:%M:%S")
    return "--:--:--"


def _where(ev: Event) -> str:
    parts = [p for p in (ev.get("stage"), ev.get("hypothesis_id")) if p]
    return "/".join(str(p) for p in parts) or "-"


def _scalar(v: Any) -> str:
    return v if isinstance(v, str) else json.dumps(v, default=str, separators=(",", ":"))


def format_data(data: Any) -> str:
    """`k=v k=v` for an event's data, truncated to DATA_MAX characters."""
    if not isinstance(data, dict) or not data:
        return ""
    text = " ".join(f"{k}={_scalar(v)}" for k, v in data.items())
    return text if len(text) <= DATA_MAX else text[: DATA_MAX - 3] + "..."


def format_event(ev: Event, *, colour: bool = False) -> str:
    """One readable line: time, level, kind, stage/hypothesis, message (and compact data)."""
    level = str(ev.get("level") or "info").lower()
    kind = str(ev.get("kind") or "?")
    message = " ".join(str(ev.get("message") or "").split())
    if kind == "agent":
        line = f"{_clock(ev.get('ts'))} {level.upper():<7}   > {_where(ev)}: {message}"
    else:
        line = f"{_clock(ev.get('ts'))} {level.upper():<7} {kind:<{KIND_W}} {_where(ev):<{WHERE_W}} {message}"
        data = format_data(ev.get("data"))
        if data:
            line += f"  [{data}]"
    if colour and level in _COLOURS:
        return f"{_COLOURS[level]}{line}{_RESET}"
    return line


def format_json(ev: Event) -> str:
    return json.dumps(ev, default=str, ensure_ascii=False)


def make_filter(kinds: Iterable[str] | None, no_agent: bool) -> Callable[[Event], bool]:
    wanted = {k.strip() for k in kinds or () if k.strip()}

    def keep(ev: Event) -> bool:
        kind = ev.get("kind")
        if no_agent and kind == "agent":
            return False
        return not wanted or kind in wanted

    return keep


# ------------------------------------------------------------------ loop


def follow(
    scan_id: int,
    fetch: Fetch,
    status: Status,
    emit: Callable[[Event], None],
    *,
    keep_following: bool = True,
    interval: float = POLL_S,
    sleep: Callable[[float], None] = time.sleep,
    page: int = PAGE,
) -> int:
    """Print every event of the scan; with keep_following, poll until the scan is finished.

    The status is read *before* each batch, so every event written before the scan turned
    terminal is printed. Returns the process exit code (1: unknown scan).
    """
    after_id = 0
    while True:
        st = status(scan_id)
        if st is None:
            return 1
        batch = fetch(scan_id, after_id)
        for ev in batch:
            emit(ev)
            after_id = max(after_id, int(ev["id"]))
        if len(batch) >= page:
            continue  # more is already waiting
        if not keep_following or st in TERMINAL:
            return 0
        sleep(interval)


# ------------------------------------------------------------------ database


def db_fetch(scan_id: int, after_id: int) -> list[Event]:
    from prsec.obs.events import list_events

    return list_events(scan_id, after_id=after_id, limit=PAGE)


def db_status(scan_id: int) -> str | None:
    from prsec.db import conn as db_conn

    with db_conn.get_pool().connection() as c:
        row = c.execute("SELECT status FROM scans WHERE id = %s", (scan_id,)).fetchone()
    if row is None:
        return None
    return row["status"] if isinstance(row, dict) else row[0]


# ------------------------------------------------------------------ CLI


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="prsec-trace", description="Print the event timeline of one scan.")
    p.add_argument("scan_id", type=int)
    p.add_argument("--follow", "-f", action="store_true", help="keep printing new events until the scan finishes")
    p.add_argument("--json", action="store_true", help="one raw JSON event per line")
    p.add_argument("--kinds", default="", help="comma-separated event kinds to show (default: all)")
    p.add_argument("--no-agent", action="store_true", help="hide the live agent stream (kind=agent)")
    p.add_argument("--interval", type=float, default=POLL_S, help=argparse.SUPPRESS)
    return p


def main(
    argv: list[str] | None = None,
    *,
    fetch: Fetch | None = None,
    status: Status | None = None,
    out: TextIO | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    args = build_parser().parse_args(argv)
    setup_logging("trace")  # stderr; the trace itself goes to stdout
    out = out or sys.stdout
    keep = make_filter(args.kinds.split(","), args.no_agent)
    colour = not args.json and out.isatty()

    def emit(ev: Event) -> None:
        if keep(ev):
            out.write((format_json(ev) if args.json else format_event(ev, colour=colour)) + "\n")
            out.flush()

    try:
        code = follow(args.scan_id, fetch or db_fetch, status or db_status, emit,
                      keep_following=args.follow, interval=args.interval, sleep=sleep)
    except KeyboardInterrupt:
        return 130
    if code == 1:
        print(f"prsec-trace: scan {args.scan_id} not found", file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())

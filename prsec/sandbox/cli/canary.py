"""prsec-canary: the canary values of this session and what the sink saw.

    prsec-canary new                    rotate: fresh token/host/url/sentinel file, printed as JSON
    prsec-canary show                   current values (created on first use)
    prsec-canary hits [--contains S]    sink records containing S (default: the current token)

Use the values through placeholders in a PoC (${CANARY.url}, ...): the replay generates its own.
"""
from __future__ import annotations

import argparse
import json
import sys

import httpx

from prsec.dynamic.app import app_root_default, load_or_create_canaries, new_canaries, save_canaries, write_sentinel
from prsec.dynamic.replay import fetch_sink_hits, sink_url_default


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="prsec-canary", description="Canary values and sink hits.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("new", help="generate fresh canaries (and sentinel file)")
    sub.add_parser("show", help="print the current canaries")
    hits = sub.add_parser("hits", help="requests the sink recorded")
    hits.add_argument("--contains", help="substring to look for (default: current canary token)")
    args = ap.parse_args(argv)

    root = app_root_default()
    if args.cmd == "new":
        canaries = new_canaries(root)
        save_canaries(root, canaries)
        write_sentinel(canaries)
        print(canaries.model_dump_json(indent=2))
        return 0
    canaries = load_or_create_canaries(root)
    if args.cmd == "show":
        print(canaries.model_dump_json(indent=2))
        return 0
    try:
        found = fetch_sink_hits(args.contains or canaries.token, sink_url_default())
    except (httpx.HTTPError, ValueError) as e:
        print(f"prsec-canary: sink query failed: {e}", file=sys.stderr)
        return 1
    print(json.dumps({"count": len(found), "hits": found}, indent=2))
    return 0

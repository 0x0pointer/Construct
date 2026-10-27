"""prsec-http: send one request to the running app, optionally as a named user.

    prsec-http [--user alice [--poc poc.yaml] [--relogin]] METHOD PATH
               [--json '{"a": 1}' | --form k=v ... | --data RAW] [--header 'K: V' ...]

Cookies and extracted vars persist per user under /work/app/.prsec/users/<user>.json. With --poc
(alias --login-from) the user's headers and vars come from the PoC, and its `login` steps run
the first time (or again with --relogin). PATH and bodies may use ${...} placeholders.
Prints the status line, response headers and body. Exit 0 = got a response, 1 = request failed.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from prsec.dynamic.app import load_or_create_canaries, state_dir
from prsec.dynamic.poc import Step, User
from prsec.dynamic.replay import ANON, PocEngine, StepError, sink_url_default
from prsec.sandbox.cli.env import add_spec_arg, default_spec_path, readable_errors, runner_from
from prsec.sandbox.cli.poc import PocFileError, load_poc_file

BODY_LIMIT = 64 * 1024


def jar_path(app_root: Path, user: str | None) -> Path:
    return state_dir(app_root) / "users" / f"{user or ANON}.json"


def load_jar(engine: PocEngine, path: Path, user: str | None) -> bool:
    """Restore a user's cookies and vars into the engine. False when there is no saved jar."""
    try:
        saved = json.loads(path.read_text())
    except (OSError, ValueError):
        return False
    cookies = engine.session(user).client.cookies
    for c in saved.get("cookies", []):
        cookies.set(c["name"], c["value"], domain=c.get("domain", ""), path=c.get("path", "/"))
    if user is not None:
        engine.ctx.users.setdefault(user, {}).update(saved.get("vars", {}))
    engine.ctx.vars.update(saved.get("globals", {}))
    return True


def save_jar(engine: PocEngine, path: Path, user: str | None) -> None:
    jar = engine.session(user).client.cookies.jar
    doc = {
        "cookies": [{"name": c.name, "value": c.value, "domain": c.domain, "path": c.path} for c in jar],
        "vars": engine.ctx.users.get(user, {}) if user else {},
        "globals": engine.ctx.vars,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2))


def _kv(items: list[str], sep: str) -> dict[str, str]:
    out = {}
    for item in items:
        k, found, v = item.partition(sep)
        if not found:
            raise ValueError(f"expected KEY{sep}VALUE, got {item!r}")
        out[k.strip()] = v.strip() if sep == ":" else v
    return out


def build_step(args: argparse.Namespace) -> Step:
    doc: dict[str, Any] = {"name": "request", "method": args.method.upper(), "path": args.path,
                           "headers": _kv(args.header, ":")}
    if args.json is not None:
        doc["json"] = json.loads(args.json)
    if args.form:
        doc["form"] = _kv(args.form, "=")
    if args.data is not None:
        doc["body"] = args.data
    return Step.model_validate(doc)


def print_response(resp: Any) -> None:
    print(f"HTTP {resp.status_code} {resp.reason_phrase}")
    for k, v in resp.headers.multi_items():
        print(f"{k}: {v}")
    print()
    body = resp.content
    print(body[:BODY_LIMIT].decode(errors="replace"))
    if len(body) > BODY_LIMIT:
        print(f"... ({len(body) - BODY_LIMIT} more bytes)")


def _users(args: argparse.Namespace) -> dict[str, User]:
    users = dict(load_poc_file(args.poc).users) if args.poc else {}
    if args.user and args.user not in users:
        users[args.user] = User()
    return users


def _send(args: argparse.Namespace) -> int:
    step = build_step(args)
    runner = runner_from(args.spec or default_spec_path())
    engine = PocEngine(_users(args), runner.base_url, load_or_create_canaries(runner.app_root), runner.workdir,
                       env=runner.app_env(), sink_url=sink_url_default())
    jar = jar_path(runner.app_root, args.user)
    try:
        had_jar = load_jar(engine, jar, args.user)
        if args.user and engine.users[args.user].login and (args.relogin or not had_jar):
            engine.login(args.user)
            print(f"logged in as {args.user}", file=sys.stderr)
        resp = engine.execute(step, args.user)
    except StepError as e:
        print(f"prsec-http: {e}", file=sys.stderr)
        return 1
    finally:
        save_jar(engine, jar, args.user)
        engine.close()
    print_response(resp)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="prsec-http", description="Send one request to the running app.")
    ap.add_argument("--user", help="named user (own cookie jar and vars)")
    ap.add_argument("--poc", "--login-from", dest="poc", type=Path, help="PoC file with the user's login/headers/vars")
    ap.add_argument("--relogin", action="store_true", help="run the user's login steps again")
    ap.add_argument("--json", help="JSON body")
    ap.add_argument("--form", action="append", default=[], metavar="KEY=VALUE", help="form field (repeatable)")
    ap.add_argument("--data", help="raw body")
    ap.add_argument("--header", "-H", action="append", default=[], metavar="'K: V'", help="header (repeatable)")
    add_spec_arg(ap)
    ap.add_argument("method")
    ap.add_argument("path")
    args = ap.parse_args(argv)
    try:
        return _send(args)
    except PocFileError as e:
        print("prsec-http: invalid PoC: " + "; ".join(e.lines), file=sys.stderr)
    except ValidationError as e:
        print("prsec-http: invalid request: " + "; ".join(readable_errors(e)), file=sys.stderr)
    except (OSError, ValueError, yaml.YAMLError) as e:
        print(f"prsec-http: {e}", file=sys.stderr)
    return 2

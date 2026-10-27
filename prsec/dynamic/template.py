"""Placeholder rendering for PoCs (`${CANARY.token}`, `${USER.x}`, ... see prsec.dynamic.poc).

Only the roots in `poc.PLACEHOLDER` are substituted; anything else that looks like `${...}` (e.g. a
shell variable in a script PoC) is left alone. A known root with an unknown key raises
`TemplateError`, so a typo never silently sends the literal placeholder.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from prsec.dynamic.poc import PLACEHOLDER
from prsec.dynamic.results import Canaries


class TemplateError(ValueError):
    """A placeholder could not be resolved."""


@dataclass
class TemplateContext:
    base_url: str
    canaries: Canaries | None = None
    user: str | None = None  # the user the step runs as (for ${USER.x})
    users: dict[str, dict[str, str]] = field(default_factory=dict)  # name -> vars
    vars: dict[str, str] = field(default_factory=dict)  # global vars from extracts

    def for_user(self, user: str | None) -> "TemplateContext":
        return TemplateContext(self.base_url, self.canaries, user, self.users, self.vars)


def _canary(key: str, ctx: TemplateContext) -> str:
    if ctx.canaries is None:
        raise TemplateError("no canaries available in this context")
    if key not in Canaries.model_fields:
        raise TemplateError(f"unknown canary field {key!r} (one of {', '.join(Canaries.model_fields)})")
    return getattr(ctx.canaries, key)


def _user_var(user: str | None, key: str, ctx: TemplateContext) -> str:
    if user is None:
        raise TemplateError(f"${{USER.{key}}} used outside a step that runs as a user")
    if user not in ctx.users:
        raise TemplateError(f"unknown user {user!r}")
    if key not in ctx.users[user]:
        raise TemplateError(f"user {user!r} has no var {key!r}")
    return ctx.users[user][key]


def _users_var(key: str, ctx: TemplateContext) -> str:
    name, _, var = key.partition(".")
    if not var:
        raise TemplateError(f"${{USERS.{key}}} needs the form USERS.<name>.<var>")
    return _user_var(name, var, ctx)


def _global_var(key: str, ctx: TemplateContext) -> str:
    if key not in ctx.vars:
        raise TemplateError(f"unknown var {key!r} (set it with an extract first)")
    return ctx.vars[key]


def _resolve(root: str, key: str | None, ctx: TemplateContext) -> str:
    if root == "BASE_URL":
        if key is not None:
            raise TemplateError("${BASE_URL} takes no key")
        return ctx.base_url
    if key is None:
        raise TemplateError(f"${{{root}}} needs a key, e.g. ${{{root}.name}}")
    if root == "CANARY":
        return _canary(key, ctx)
    if root == "USER":
        return _user_var(ctx.user, key, ctx)
    if root == "USERS":
        return _users_var(key, ctx)
    return _global_var(key, ctx)


def render_str(text: str, ctx: TemplateContext) -> str:
    def sub(m: re.Match[str]) -> str:
        return _resolve(m.group(1), m.group(2), ctx)

    return PLACEHOLDER.sub(sub, text)


def render(value: Any, ctx: TemplateContext) -> Any:
    """Render placeholders in a string, or in every string value of nested dicts/lists (keys untouched)."""
    if isinstance(value, str):
        return render_str(value, ctx)
    if isinstance(value, dict):
        return {k: render(v, ctx) for k, v in value.items()}
    if isinstance(value, list):
        return [render(v, ctx) for v in value]
    return value

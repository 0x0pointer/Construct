import re

import pytest

from prsec.dynamic.results import Canaries
from prsec.dynamic.template import TemplateContext, TemplateError, render, render_str

CAN = Canaries(token="abc123", host="abc123.canary.invalid", url="http://abc123.canary.invalid/abc123",
               file="/work/app/.prsec/canary/sentinel-abc123.txt", file_content="secret-xyz")


@pytest.fixture
def ctx() -> TemplateContext:
    return TemplateContext(base_url="http://127.0.0.1:8000", canaries=CAN, user="alice",
                           users={"alice": {"id": "1"}, "bob": {"id": "2", "note.id": "9"}},
                           vars={"token": "t0k"})


@pytest.mark.parametrize(("text", "expected"), [
    ("${CANARY.token}", "abc123"),
    ("${CANARY.host}", "abc123.canary.invalid"),
    ("${CANARY.url}", "http://abc123.canary.invalid/abc123"),
    ("${CANARY.file}", "/work/app/.prsec/canary/sentinel-abc123.txt"),
    ("${CANARY.file_content}", "secret-xyz"),
    ("${USER.id}", "1"),
    ("${USERS.bob.id}", "2"),
    ("${USERS.bob.note.id}", "9"),
    ("${VARS.token}", "t0k"),
    ("${BASE_URL}/x", "http://127.0.0.1:8000/x"),
    ("/notes/${USERS.bob.id}?u=${USER.id}", "/notes/2?u=1"),
])
def test_render_str(ctx: TemplateContext, text: str, expected: str) -> None:
    assert render_str(text, ctx) == expected


def test_other_dollar_braces_are_left_alone(ctx: TemplateContext) -> None:
    assert render_str("echo ${HOME} $PATH", ctx) == "echo ${HOME} $PATH"


def test_render_nested(ctx: TemplateContext) -> None:
    doc = {"a": ["${USER.id}", {"b": "${VARS.token}"}], "n": 5, "k${USER.id}": None}
    assert render(doc, ctx) == {"a": ["1", {"b": "t0k"}], "n": 5, "k${USER.id}": None}


def test_for_user_switches_user(ctx: TemplateContext) -> None:
    assert render_str("${USER.id}", ctx.for_user("bob")) == "2"


@pytest.mark.parametrize(("text", "message"), [
    ("${CANARY.nope}", "unknown canary field"),
    ("${CANARY}", "needs a key"),
    ("${USERS.carol.id}", "unknown user"),
    ("${USERS.bob}", "USERS.<name>.<var>"),
    ("${USER.missing}", "has no var"),
    ("${VARS.missing}", "unknown var"),
    ("${BASE_URL.x}", "takes no key"),
])
def test_unknown_placeholders_raise(ctx: TemplateContext, text: str, message: str) -> None:
    with pytest.raises(TemplateError, match=re.escape(message)):
        render_str(text, ctx)


def test_user_placeholder_without_user(ctx: TemplateContext) -> None:
    no_user = ctx.for_user(None)
    with pytest.raises(TemplateError, match="outside a step"):
        render_str("${USER.id}", no_user)


def test_canary_without_canaries() -> None:
    ctx = TemplateContext(base_url="http://x")
    with pytest.raises(TemplateError, match="no canaries"):
        render_str("${CANARY.token}", ctx)

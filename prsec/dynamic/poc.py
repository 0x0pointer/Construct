"""PoC (poc.yaml): a declarative, replayable proof, written by the `dynamic` stage agent.

Template placeholders, substituted in every string field (method excluded) at run time:

    ${CANARY.token}         fresh random token per run (letters+digits)
    ${CANARY.host}          <token>.canary.invalid   -- resolves to the sink, so a request to it is recorded
    ${CANARY.url}           http://<token>.canary.invalid/<token>
    ${CANARY.file}          absolute path of a sentinel file created before the app starts
    ${CANARY.file_content}  the sentinel's secret content (prove a file read by finding it in a response)
    ${USER.<var>}           var of the user the step runs as (from users.<name>.vars or a step's extract)
    ${USERS.<name>.<var>}   var of another user (e.g. another tenant's object id for an IDOR)
    ${VARS.<var>}           global var set by an `extract` on any step
    ${BASE_URL}             http://127.0.0.1:<envspec.port>

Steps go to the app (a relative path) or to one of the EnvSpec's services (an absolute URL whose
host is a service name, e.g. to get a token from the oauth2 mock or read mail from mailpit).
Redirects are never followed: a 3xx is the step's own response, so its Location can be checked.

Canaries must be benign: echo/print a canary token, request a canary URL, read the sentinel file.
Never destructive payloads, never anything that opens a shell or a connection back to a listener.
"""
from __future__ import annotations

import re
from typing import Annotated, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,31}")
# A script PoC's output is the response of this step: status 200 (exit 0) or 500, body = stdout.
SCRIPT_STEP = "script"
MAX_PARALLEL = 50
PLACEHOLDER = re.compile(r"\$\{(CANARY|USER|USERS|VARS|BASE_URL)(?:\.([A-Za-z0-9_.-]+))?\}")


class Extract(BaseModel):
    """Exactly one of json / header / regex. json is a dotted path ('items.0.id'); regex uses group 1."""

    json_path: str | None = Field(default=None, alias="json")
    header: str | None = None
    regex: str | None = None

    model_config = {"populate_by_name": True}

    @model_validator(mode="after")
    def _one(self) -> "Extract":
        if sum(x is not None for x in (self.json_path, self.header, self.regex)) != 1:
            raise ValueError("extract needs exactly one of json, header, regex")
        return self


class Step(BaseModel):
    name: str
    as_user: str | None = Field(default=None, alias="as", description="User whose cookies/headers/vars apply")
    method: str = "GET"
    path: str = Field(description=(
        "Path on the app ('/api/x?y=1'), or an absolute http URL to one of the EnvSpec's services "
        "('http://mail:8025/api/v1/messages'); any other absolute URL is refused"))
    headers: dict[str, str] = Field(default_factory=dict)
    query: dict[str, str] = Field(default_factory=dict)
    json_body: object | None = Field(default=None, alias="json")
    form: dict[str, str] | None = None
    body: str | None = None
    expect_status: list[int] | None = Field(default=None, description="Abort the run (fired=false) if the status differs")
    extract: dict[str, Extract] = Field(default_factory=dict)
    parallel: int = Field(default=1, ge=1, le=MAX_PARALLEL, description=(
        "Send this request N times at the same moment (race conditions). Its oracles pass if any "
        "response matches (negate: if none does); expect_status must hold for every response"))

    model_config = {"populate_by_name": True}

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        if not NAME.fullmatch(v):
            raise ValueError(f"invalid step name {v!r}")
        return v

    @model_validator(mode="after")
    def _one_body(self) -> "Step":
        if sum(x is not None for x in (self.json_body, self.form, self.body)) > 1:
            raise ValueError("a step takes at most one of json, form, body")
        if self.parallel > 1 and self.extract:
            raise ValueError("a parallel step cannot extract (which of its responses would it use?)")
        return self


class User(BaseModel):
    vars: dict[str, str] = Field(default_factory=dict, description="e.g. username/password of a seeded test user")
    headers: dict[str, str] = Field(default_factory=dict, description="Sent on every request as this user, e.g. Authorization: Bearer ${USER.token}")
    login: list[Step] = Field(default_factory=list, description="Run as this user before `steps`; cookies are kept per user")


# ------------------------------------------------------------------ oracles


class ResponseContains(BaseModel):
    type: Literal["response_contains"]
    step: str
    value: str = Field(min_length=1, description=(
        "Substring (placeholders allowed), e.g. ${CANARY.file_content} or another tenant's marker; "
        "never passes when it is in the step's own request (markup excepted) or renders empty"))
    negate: bool = False


class ResponseStatus(BaseModel):
    type: Literal["response_status"]
    step: str
    status: list[int]


def _compiles(pattern: str) -> str:
    try:
        re.compile(pattern)
    except re.error as e:
        raise ValueError(f"invalid regex {pattern!r}: {e}") from None
    return pattern


class ResponseHeader(BaseModel):
    """A response header proves it: Location of an open redirect, Access-Control-Allow-Origin echoing
    an attacker origin, a session Set-Cookie without HttpOnly, Content-Type of a reflected XSS.

    Every value of the header is checked (Set-Cookie repeats); the oracle passes if one matches.
    `value` is rendered (placeholders allowed); `regex` is matched as written, case-sensitive."""

    type: Literal["response_header"]
    step: str
    name: str = Field(min_length=1, description="Header name, case-insensitive")
    op: Literal["present", "absent", "equals", "contains", "starts_with", "regex"]
    value: str | None = Field(default=None, description="Required for every op except present/absent")

    @model_validator(mode="after")
    def _value(self) -> "ResponseHeader":
        needs = self.op not in ("present", "absent")
        if needs and not (self.value or "").strip():
            raise ValueError(f"response_header op {self.op!r} needs a non-empty value")
        if not needs and self.value is not None:
            raise ValueError(f"response_header op {self.op!r} takes no value")
        if self.op == "regex":
            _compiles(self.value or "")
        return self


class ResponseRegex(BaseModel):
    """The step's response body matches `pattern` (Python re, as written). A match that is in the
    step's own request does not count, as for response_contains (markup excepted)."""

    type: Literal["response_regex"]
    step: str
    pattern: str = Field(min_length=1)
    negate: bool = False

    @field_validator("pattern")
    @classmethod
    def _pattern(cls, v: str) -> str:
        return _compiles(v)


class JsonCompare(BaseModel):
    """Invariant check on a JSON response, e.g. balance < 0 or quantity != requested."""

    type: Literal["json_compare"]
    step: str
    path: str
    op: Literal["eq", "ne", "lt", "le", "gt", "ge"]
    value: str | float | int | bool | None


class CanaryHit(BaseModel):
    """The sink recorded a request whose host, path, headers or body contains the value."""

    type: Literal["canary_hit"]
    value: str = Field(default="${CANARY.token}", min_length=1)


class Command(BaseModel):
    """Run in the app dir after the steps (e.g. inspect the DB); passes if stdout contains `expect`."""

    type: Literal["command"]
    run: str
    expect: str = Field(min_length=1)
    negate: bool = False


Oracle = Annotated[
    ResponseContains | ResponseStatus | ResponseHeader | ResponseRegex | JsonCompare | CanaryHit | Command,
    Field(discriminator="type"),
]


class PoC(BaseModel):
    kind: Literal["http", "script"] = Field(description=(
        "http: steps against the running app (a real entry point). script: `script` is run instead "
        "of steps (direct call into code); a script PoC can never yield a 'reproduced' label"))
    hypothesis_id: str
    description: str
    users: dict[str, User] = Field(default_factory=dict)
    steps: list[Step] = Field(default_factory=list, max_length=50)
    script: str | None = Field(default=None, description=(
        "kind=script only: bash command run in the app dir; oracles read its stdout as step 'script'"))
    oracles: list[Oracle] = Field(min_length=1, max_length=10)
    fires_when: Literal["all", "any"] = "all"

    @model_validator(mode="after")
    def _consistent(self) -> "PoC":
        names = [s.name for s in self.steps]
        every = names + [st.name for u in self.users.values() for st in u.login]
        if len(every) != len(set(every)):
            raise ValueError("step names (login steps of every user included) must be unique")
        if SCRIPT_STEP in every:
            raise ValueError(f"{SCRIPT_STEP!r} is reserved for a script PoC's output")
        for u in self.users:
            if not NAME.fullmatch(u):
                raise ValueError(f"invalid user name {u!r}")
        for s in self.steps:
            if s.as_user is not None and s.as_user not in self.users:
                raise ValueError(f"step {s.name} runs as unknown user {s.as_user!r}")
        if self.kind == "http" and not self.steps:
            raise ValueError("an http PoC needs steps")
        if self.kind == "script" and not self.script:
            raise ValueError("a script PoC needs script")
        self._check_oracle_steps(set(names))
        return self

    def _check_oracle_steps(self, names: set[str]) -> None:
        known = names | {st.name for u in self.users.values() for st in u.login}
        if self.kind == "script":
            known.add(SCRIPT_STEP)
        for o in self.oracles:
            step = getattr(o, "step", None)
            if step is not None and step not in known:
                raise ValueError(f"oracle refers to unknown step {step!r}")

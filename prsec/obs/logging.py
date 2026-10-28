"""Process-wide logging setup with bound scan context.

    setup_logging("worker")                    # once per process, in main()
    with bind(scan_id=12, stage="triage"):     # every record inside carries scan_id + stage
        log.info("...")
    submit_with_context(pool, fn, *args)       # the bound context follows work into a pool thread

PRSEC_LOG_FORMAT=json|text (default text) and PRSEC_LOG_LEVEL (default INFO) pick the output.
JSON lines are {"ts","level","service","logger","msg", ...bound fields, "exc"?}. A record logged
while the bound context has debug=True passes at DEBUG even when the global level is INFO, so a
single scan can be debugged without turning the whole service verbose.
"""
from __future__ import annotations

import contextvars
import json
import logging
import os
import sys
from collections.abc import Callable, Iterator, Mapping
from concurrent.futures import Executor, Future
from contextlib import contextmanager
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any

# Read-only default; bind() always sets a fresh dict, so no context ever shares a mutable value.
_CTX: contextvars.ContextVar[Mapping[str, Any]] = contextvars.ContextVar("prsec_log_ctx", default=MappingProxyType({}))

# Bound fields in a fixed order (others follow alphabetically).
FIELD_ORDER = ("scan_id", "task_id", "stage", "hypothesis_id", "env", "debug")
CORE_KEYS = ("ts", "level", "service", "logger", "msg", "exc")
# Chatty third-party loggers kept at INFO unless PRSEC_LOG_LEVEL=DEBUG, so a debug=True scan
# shows prsec's own DEBUG lines and not every HTTP/DB round trip.
QUIET_LOGGERS = ("urllib3", "httpx", "httpcore", "docker", "botocore", "boto3", "s3transfer", "minio",
                 "psycopg", "psycopg.pool", "asyncio", "multipart", "hpack", "filelock")
UVICORN_LOGGERS = ("uvicorn", "uvicorn.error", "uvicorn.access")

_HANDLER_ATTR = "_prsec_handler"


# ------------------------------------------------------------------ context


@contextmanager
def bind(**fields: Any) -> Iterator[dict[str, Any]]:
    """Add fields to the logging context for the duration of the block; None removes a field."""
    merged = {**_CTX.get(), **fields}
    token = _CTX.set({k: v for k, v in merged.items() if v is not None})
    try:
        yield dict(_CTX.get())
    finally:
        _CTX.reset(token)


def get_context() -> dict[str, Any]:
    return dict(_CTX.get())


def submit_with_context(pool: Executor, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Future:
    """pool.submit(fn, *args) running fn inside a copy of the caller's context (bound fields included)."""
    return pool.submit(contextvars.copy_context().run, fn, *args, **kwargs)


def child_log_env() -> dict[str, str]:
    """PRSEC_LOG_LEVEL for a container this process starts (it does not inherit our environment):
    DEBUG inside a debug=True context, else this process's level when one is set. The format is
    left to the child (prsec-stage writes text into workbench.log)."""
    if _CTX.get().get("debug"):
        return {"PRSEC_LOG_LEVEL": "DEBUG"}
    level = (os.environ.get("PRSEC_LOG_LEVEL") or "").strip()
    return {"PRSEC_LOG_LEVEL": level} if level else {}


def _ordered_fields(ctx: Mapping[str, Any]) -> list[tuple[str, Any]]:
    first = [(k, ctx[k]) for k in FIELD_ORDER if k in ctx]
    rest = sorted((k, v) for k, v in ctx.items() if k not in FIELD_ORDER)
    return first + rest


# ------------------------------------------------------------------ filter + formatters


class ContextFilter(logging.Filter):
    """Stamps service + bound fields on each record and applies the level gate (debug=True bypasses it)."""

    def __init__(self, service: str, level: int) -> None:
        super().__init__()
        self.service = service
        self.level = level

    def filter(self, record: logging.LogRecord) -> bool:
        ctx = _CTX.get()
        record.service = self.service
        record.prsec_ctx = ctx
        return record.levelno >= self.level or bool(ctx.get("debug"))


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        out: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "level": record.levelname,
            "service": getattr(record, "service", ""),
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for k, v in _ordered_fields(getattr(record, "prsec_ctx", {})):
            if k not in CORE_KEYS:
                out[k] = v
        exc = self._exc_text(record)
        if exc:
            out["exc"] = exc
        return json.dumps(out, default=str, ensure_ascii=False)

    def _exc_text(self, record: logging.LogRecord) -> str:
        parts = []
        if record.exc_info:
            parts.append(self.formatException(record.exc_info))
        elif record.exc_text:
            parts.append(record.exc_text)
        if record.stack_info:
            parts.append(self.formatStack(record.stack_info))
        return "\n".join(parts)


class TextFormatter(logging.Formatter):
    """`<time> <LEVEL> <service> <thread> <logger> [scan_id=1 stage=triage] message`."""

    def __init__(self) -> None:
        super().__init__("%(asctime)s %(levelname)s %(service)s %(threadName)s %(name)s %(prsec_fields)s%(message)s")

    def format(self, record: logging.LogRecord) -> str:
        fields = " ".join(f"{k}={v}" for k, v in _ordered_fields(getattr(record, "prsec_ctx", {})))
        record.prsec_fields = f"[{fields}] " if fields else ""
        if not hasattr(record, "service"):
            record.service = ""
        return super().format(record)


class _StderrHandler(logging.StreamHandler):
    """Writes to the *current* sys.stderr (survives stream swaps, e.g. pytest capture)."""

    @property
    def stream(self):  # type: ignore[override]
        return sys.stderr

    @stream.setter
    def stream(self, _value) -> None:
        pass


# ------------------------------------------------------------------ setup


def _parse_level(raw: str | None) -> int:
    level = logging.getLevelName((raw or "INFO").strip().upper())
    return level if isinstance(level, int) else logging.INFO


def _formatter(fmt: str | None) -> logging.Formatter:
    return JsonFormatter() if (fmt or "").strip().lower() == "json" else TextFormatter()


def _route_uvicorn() -> None:
    """uvicorn's loggers propagate to root (our handler). Pair with uvicorn.run(..., log_config=None)."""
    for name in UVICORN_LOGGERS:
        lg = logging.getLogger(name)
        lg.handlers.clear()
        lg.propagate = True
        lg.setLevel(logging.NOTSET)


def setup_logging(service: str) -> None:
    """Install the prsec handler on the root logger. Idempotent: a repeat call replaces it, never duplicates."""
    level = _parse_level(os.environ.get("PRSEC_LOG_LEVEL"))
    root = logging.getLogger()
    for h in [h for h in root.handlers if getattr(h, _HANDLER_ATTR, False)]:
        root.removeHandler(h)
    handler = _StderrHandler()
    setattr(handler, _HANDLER_ATTR, True)
    handler.setFormatter(_formatter(os.environ.get("PRSEC_LOG_FORMAT")))
    handler.addFilter(ContextFilter(service, level))
    root.addHandler(handler)
    # Root lets DEBUG records through to the handler, whose filter applies the real level
    # (or lets a debug=True context pass).
    root.setLevel(logging.DEBUG)
    quiet = max(level, logging.INFO)
    for name in QUIET_LOGGERS:
        lg = logging.getLogger(name)
        if lg.level == logging.NOTSET or getattr(lg, "_prsec_quiet", False):
            lg.setLevel(quiet if level > logging.DEBUG else logging.NOTSET)
            lg._prsec_quiet = True  # type: ignore[attr-defined]
    _route_uvicorn()

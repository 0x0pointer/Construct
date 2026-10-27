"""Helpers for the in-workbench tests: the fixture app as a real EnvSpec, and a sink API stub."""
from __future__ import annotations

import json
import shutil
import socket
import sys
import threading
import urllib.parse
from collections.abc import Iterator
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from prsec.dynamic.app import AppRunner
from prsec.dynamic.envspec import EnvSpec

APP_SRC = Path(__file__).parent / "app"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def make_spec(port: int, **kw: object) -> EnvSpec:
    doc: dict[str, object] = {
        "stack": "python",
        "start": f"{sys.executable} server.py {port}",
        "port": port,
        "health": {"path": "/health", "timeout_s": 15},
    }
    doc.update(kw)
    return EnvSpec.model_validate(doc)


@dataclass
class Workbench:
    src: Path
    app_root: Path
    port: int

    def spec(self, **kw: object) -> EnvSpec:
        return make_spec(self.port, **kw)

    def runner(self, **kw: object) -> AppRunner:
        return AppRunner(self.spec(**kw), app_root=self.app_root, src=self.src, proxy=None)


@pytest.fixture
def workbench(tmp_path: Path) -> Iterator[Workbench]:
    src = tmp_path / "src"
    shutil.copytree(APP_SRC, src)
    (src / ".git").mkdir()
    (src / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    wb = Workbench(src=src, app_root=tmp_path / "app", port=free_port())
    yield wb
    AppRunner(make_spec(wb.port), app_root=wb.app_root, src=src, proxy=None).stop(grace_s=2)


class _SinkHandler(BaseHTTPRequestHandler):
    records: list[dict[str, object]]

    def log_message(self, *_: object) -> None:
        pass

    def _answer(self, body: dict[str, object]) -> None:
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        url = urllib.parse.urlsplit(self.path)
        if url.path == "/__prsec/hits":
            needle = urllib.parse.parse_qs(url.query).get("contains", [""])[0]
            return self._answer({"hits": [r for r in self.server.records if needle in json.dumps(r)]})  # type: ignore[attr-defined]
        self.server.records.append({"host": self.headers.get("Host", ""), "method": "GET",  # type: ignore[attr-defined]
                                    "path": self.path, "headers": dict(self.headers), "body": ""})
        return self._answer({})


@dataclass
class SinkStub:
    url: str
    records: list[dict[str, object]]


@pytest.fixture
def sink() -> Iterator[SinkStub]:
    """A local stand-in for the sink: records every request, answers /__prsec/hits?contains=."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _SinkHandler)
    server.records = []  # type: ignore[attr-defined]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield SinkStub(url=f"http://127.0.0.1:{server.server_address[1]}", records=server.records)  # type: ignore[attr-defined]
    server.shutdown()
    server.server_close()

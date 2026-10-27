"""A tiny, deliberately vulnerable stdlib web app for the dynamic tests.

    python server.py <port>

    GET  /health                   200 ok
    GET  /search?q=...             reflects q unescaped (reflected XSS marker)
    POST /login  (form or json)    username/password -> Set-Cookie session=<token>, {"token": ...}
    GET  /api/me                   needs the session cookie or `Authorization: Bearer <token>`
    GET  /api/notes/<id>           any logged-in user reads any note (IDOR)
    GET  /file?name=...            reads a file relative to the app dir without checks (traversal)
    GET  /fetch?url=...            fetches a URL server side (SSRF)
    POST /api/withdraw {amount}    no balance check (balance can go negative)
"""
from __future__ import annotations

import json
import sys
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

USERS = {"alice": "alice-pw", "bob": "bob-pw"}
NOTES = {"1": {"id": 1, "owner": "alice", "text": "alice-secret-note"},
         "2": {"id": 2, "owner": "bob", "text": "bob-secret-note"}}
SESSIONS: dict[str, str] = {}
BALANCE = {"alice": 100, "bob": 100}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write("req " + (fmt % args) + "\n")

    def _send(self, status: int, body: object, headers: dict[str, str] | None = None) -> None:
        data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html" if isinstance(body, str) else "application/json")
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _user(self) -> str | None:
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return SESSIONS.get(auth[7:])
        for part in self.headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "session":
                return SESSIONS.get(v)
        return None

    def _body(self) -> dict[str, str]:
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
        if self.headers.get("Content-Type", "").startswith("application/json"):
            return json.loads(raw or "{}")
        return {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}

    def do_GET(self) -> None:  # noqa: N802
        url = urllib.parse.urlsplit(self.path)
        q = {k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()}
        if url.path == "/health":
            return self._send(200, {"ok": True})
        if url.path == "/search":
            return self._send(200, f"<p>results for {q.get('q', '')}</p>")
        if url.path == "/file":
            try:
                return self._send(200, (Path.cwd() / q.get("name", "")).read_text())
            except OSError:
                return self._send(404, {"error": "no such file"})
        if url.path == "/fetch":
            with urllib.request.urlopen(q["url"], timeout=5) as r:  # noqa: S310 - the bug under test
                return self._send(200, {"fetched": r.status})
        return self._authed_get(url.path)

    def _authed_get(self, path: str) -> None:
        user = self._user()
        if user is None:
            return self._send(401, {"error": "login required"})
        if path == "/api/me":
            return self._send(200, {"user": user, "balance": BALANCE[user]})
        if path.startswith("/api/notes/") and path[11:] in NOTES:
            return self._send(200, NOTES[path[11:]])
        return self._send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        body = self._body()
        if self.path == "/login":
            name = body.get("username", "")
            if USERS.get(name) != body.get("password"):
                return self._send(403, {"error": "bad credentials"})
            token = f"tok-{name}-{len(SESSIONS)}"
            SESSIONS[token] = name
            return self._send(200, {"token": token, "user": {"name": name, "ids": [1, 2]}},
                              {"Set-Cookie": f"session={token}; Path=/", "X-Session": token})
        user = self._user()
        if self.path == "/api/withdraw" and user:
            BALANCE[user] -= int(body.get("amount", 0))
            return self._send(200, {"balance": BALANCE[user]})
        return self._send(404, {"error": "not found"})


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()

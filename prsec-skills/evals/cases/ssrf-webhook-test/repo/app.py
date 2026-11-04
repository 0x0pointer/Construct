import os
import urllib.request

import psycopg
from flask import Flask, g, jsonify, request, session
from psycopg.rows import dict_row
from werkzeug.security import check_password_hash

from auth import login_required

app = Flask(__name__)
app.secret_key = "dev-only"
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://app:app@localhost:5432/app")


def db():
    if "db" not in g:
        g.db = psycopg.connect(DATABASE_URL, row_factory=dict_row, autocommit=True)
    return g.db


@app.teardown_appcontext
def close_db(exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


@app.post("/api/login")
def login():
    body = request.get_json(silent=True) or {}
    row = db().execute(
        "SELECT id, password_hash FROM users WHERE username = %s", (body.get("username", ""),)
    ).fetchone()
    if row is None or not check_password_hash(row["password_hash"], body.get("password", "")):
        return jsonify(error="invalid credentials"), 401
    session["user_id"] = row["id"]
    return jsonify(id=row["id"])


@app.get("/api/webhooks")
@login_required
def list_webhooks():
    rows = db().execute(
        "SELECT id, url FROM webhooks WHERE user_id = %s ORDER BY id", (g.user_id,)
    ).fetchall()
    return jsonify(rows)


@app.post("/api/webhooks")
@login_required
def add_webhook():
    url = (request.get_json(silent=True) or {}).get("url", "")
    if not url.startswith(("http://", "https://")):
        return jsonify(error="url must be http(s)"), 400
    row = db().execute(
        "INSERT INTO webhooks (user_id, url) VALUES (%s, %s) RETURNING id, url", (g.user_id, url)
    ).fetchone()
    return jsonify(row), 201


@app.post("/api/webhooks/<int:hook_id>/test")
@login_required
def test_webhook(hook_id):
    row = db().execute(
        "SELECT url FROM webhooks WHERE id = %s AND user_id = %s", (hook_id, g.user_id)
    ).fetchone()
    if row is None:
        return jsonify(error="not found"), 404
    try:
        with urllib.request.urlopen(row["url"], data=b'{"event": "ping"}', timeout=5) as resp:
            return jsonify(delivered=True, status=resp.status)
    except OSError as e:
        return jsonify(delivered=False, error=str(e)), 502

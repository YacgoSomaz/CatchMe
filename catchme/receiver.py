"""Small reference receiver for a user-controlled server.

Run this behind an HTTPS reverse proxy.  It deliberately binds to localhost by
default and requires a bearer token for ingestion and export.
"""

from __future__ import annotations

import gzip
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from flask import Flask, jsonify, request

MAX_COMPRESSED_BYTES = 5 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 16 * 1024 * 1024
MAX_EVENTS_PER_BATCH = 1000


def create_receiver_app(db_path: str | Path, token: str | None = None) -> Flask:
    app = Flask("catchme-receiver")
    app.config["CATCHME_DB_PATH"] = str(db_path)
    app.config["CATCHME_SERVER_TOKEN"] = token or os.environ.get("CATCHME_SERVER_TOKEN", "")
    _init_db(app.config["CATCHME_DB_PATH"])

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"})

    @app.post("/v1/events/batches")
    def receive_batch():
        if not _provided_token():
            return jsonify({"error": "unauthorized"}), 401
        if request.content_length and request.content_length > MAX_COMPRESSED_BYTES:
            return jsonify({"error": "compressed request too large"}), 413
        body = request.get_data(cache=False)
        try:
            if request.headers.get("Content-Encoding", "").lower() == "gzip":
                body = gzip.decompress(body)
            if len(body) > MAX_UNCOMPRESSED_BYTES:
                return jsonify({"error": "request too large"}), 413
            payload = json.loads(body)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return jsonify({"error": "invalid request body"}), 400

        error = _validate_batch(payload)
        if error:
            return jsonify({"error": error}), 400
        if not _authorized_for_upload(app, payload["device_id"]):
            return jsonify({"error": "unauthorized"}), 401
        inserted = _store_batch(app.config["CATCHME_DB_PATH"], payload)
        return jsonify(
            {
                "batch_id": payload["batch_id"],
                "accepted": True,
                "inserted": inserted,
                "duplicates": len(payload["events"]) - inserted,
            }
        )

    @app.post("/v1/enrollment-codes")
    def create_enrollment_code():
        if not _authorized_master(app):
            return jsonify({"error": "unauthorized"}), 401
        value = request.get_json(silent=True) or {}
        try:
            ttl_seconds = min(86400, max(60, int(value.get("ttl_seconds", 900))))
        except (TypeError, ValueError):
            return jsonify({"error": "ttl_seconds must be an integer"}), 400
        code, expires_at = _create_enrollment_code(app.config["CATCHME_DB_PATH"], ttl_seconds)
        return jsonify({"code": code, "expires_at": expires_at, "single_use": True})

    @app.post("/v1/devices/enroll")
    def enroll_device():
        value = request.get_json(silent=True)
        if not isinstance(value, dict):
            return jsonify({"error": "body must be an object"}), 400
        code = str(value.get("code", ""))
        device_id = str(value.get("device_id", ""))
        device_name = str(value.get("device_name", ""))[:200]
        if not code or not device_id:
            return jsonify({"error": "code and device_id are required"}), 400
        token, error = _enroll_device(app.config["CATCHME_DB_PATH"], code, device_id, device_name)
        if error:
            return jsonify({"error": error}), 403
        return jsonify(
            {
                "device_id": device_id,
                "device_token": token,
                "scope": "events:write",
            }
        )

    @app.get("/v1/events/export")
    def export_events():
        if not _authorized_master(app):
            return jsonify({"error": "unauthorized"}), 401
        date_text = request.args.get("date", "")
        try:
            day = datetime.strptime(date_text, "%Y-%m-%d").replace(tzinfo=UTC)
        except ValueError:
            return jsonify({"error": "date must be YYYY-MM-DD in UTC"}), 400
        rows = _export_day(
            app.config["CATCHME_DB_PATH"], day.timestamp(), (day + timedelta(days=1)).timestamp()
        )
        return jsonify({"date": date_text, "events": rows})

    return app


def _provided_token() -> str:
    header = request.headers.get("Authorization", "")
    return header[7:] if header.startswith("Bearer ") else ""


def _authorized_master(app: Flask) -> bool:
    expected = app.config.get("CATCHME_SERVER_TOKEN", "")
    provided = _provided_token()
    return bool(expected) and hmac.compare_digest(expected, provided)


def _authorized_for_upload(app: Flask, device_id: str) -> bool:
    if _authorized_master(app):
        return True
    provided = _provided_token()
    if not provided:
        return False
    token_hash = _token_hash(provided)
    with _connect(app.config["CATCHME_DB_PATH"]) as conn:
        row = conn.execute(
            "SELECT 1 FROM device_tokens "
            "WHERE device_id = ? AND token_hash = ? AND revoked_at IS NULL",
            (device_id, token_hash),
        ).fetchone()
    return row is not None


def _validate_batch(payload: object) -> str:
    if not isinstance(payload, dict):
        return "body must be an object"
    if not isinstance(payload.get("batch_id"), str) or not payload["batch_id"]:
        return "batch_id is required"
    if not isinstance(payload.get("device_id"), str) or not payload["device_id"]:
        return "device_id is required"
    events = payload.get("events")
    if not isinstance(events, list) or len(events) > MAX_EVENTS_PER_BATCH:
        return f"events must be a list with at most {MAX_EVENTS_PER_BATCH} items"
    for event in events:
        if not isinstance(event, dict):
            return "each event must be an object"
        if not isinstance(event.get("event_id"), str) or not event["event_id"]:
            return "each event requires event_id"
        if not isinstance(event.get("timestamp"), (int, float)):
            return "each event requires a numeric timestamp"
        if not isinstance(event.get("kind"), str) or not isinstance(event.get("data"), dict):
            return "each event requires kind and data"
    return ""


def _connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _init_db(db_path: str) -> None:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with _connect(db_path) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS received_batches (
                batch_id TEXT PRIMARY KEY,
                device_id TEXT NOT NULL,
                received_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS received_events (
                event_id TEXT PRIMARY KEY,
                batch_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                event_time REAL NOT NULL,
                kind TEXT NOT NULL,
                data TEXT NOT NULL,
                received_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_received_events_time
                ON received_events(event_time);
            CREATE INDEX IF NOT EXISTS idx_received_events_device_time
                ON received_events(device_id, event_time);
            CREATE TABLE IF NOT EXISTS enrollment_codes (
                code_hash TEXT PRIMARY KEY,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                used_at REAL,
                device_id TEXT
            );
            CREATE TABLE IF NOT EXISTS device_tokens (
                device_id TEXT PRIMARY KEY,
                token_hash TEXT NOT NULL,
                device_name TEXT NOT NULL,
                created_at REAL NOT NULL,
                revoked_at REAL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_device_tokens_hash
                ON device_tokens(token_hash);
            """
        )


def _token_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _create_enrollment_code(db_path: str, ttl_seconds: int) -> tuple[str, float]:
    code = secrets.token_urlsafe(18)
    now = time.time()
    expires_at = now + ttl_seconds
    with _connect(db_path) as conn:
        conn.execute(
            "INSERT INTO enrollment_codes(code_hash, created_at, expires_at) VALUES (?, ?, ?)",
            (_token_hash(code), now, expires_at),
        )
    return code, expires_at


def _enroll_device(db_path: str, code: str, device_id: str, device_name: str) -> tuple[str, str]:
    now = time.time()
    code_hash = _token_hash(code)
    device_token = secrets.token_urlsafe(32)
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT expires_at, used_at FROM enrollment_codes WHERE code_hash = ?",
            (code_hash,),
        ).fetchone()
        if row is None or row[1] is not None or float(row[0]) < now:
            return "", "invalid, expired, or already used enrollment code"
        updated = conn.execute(
            "UPDATE enrollment_codes SET used_at = ?, device_id = ? "
            "WHERE code_hash = ? AND used_at IS NULL",
            (now, device_id, code_hash),
        )
        if updated.rowcount != 1:
            return "", "enrollment code was already used"
        conn.execute(
            "INSERT INTO device_tokens(device_id, token_hash, device_name, created_at, revoked_at) "
            "VALUES (?, ?, ?, ?, NULL) "
            "ON CONFLICT(device_id) DO UPDATE SET "
            "token_hash = excluded.token_hash, device_name = excluded.device_name, "
            "created_at = excluded.created_at, revoked_at = NULL",
            (device_id, _token_hash(device_token), device_name, now),
        )
    return device_token, ""


def _store_batch(db_path: str, payload: dict) -> int:
    now = time.time()
    inserted = 0
    with _connect(db_path) as conn:
        conn.execute(
            "INSERT OR IGNORE INTO received_batches(batch_id, device_id, received_at) "
            "VALUES (?, ?, ?)",
            (payload["batch_id"], payload["device_id"], now),
        )
        for event in payload["events"]:
            cursor = conn.execute(
                "INSERT OR IGNORE INTO received_events "
                "(event_id, batch_id, device_id, event_time, kind, data, received_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    event["event_id"],
                    payload["batch_id"],
                    payload["device_id"],
                    float(event["timestamp"]),
                    event["kind"],
                    json.dumps(event["data"], ensure_ascii=False),
                    now,
                ),
            )
            inserted += cursor.rowcount
    return inserted


def _export_day(db_path: str, start: float, end: float) -> list[dict]:
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT event_id, device_id, event_time, kind, data "
            "FROM received_events WHERE event_time >= ? AND event_time < ? "
            "ORDER BY event_time ASC",
            (start, end),
        ).fetchall()
    return [
        {
            "event_id": row[0],
            "device_id": row[1],
            "timestamp": row[2],
            "kind": row[3],
            "data": json.loads(row[4]),
        }
        for row in rows
    ]

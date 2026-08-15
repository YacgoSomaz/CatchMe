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
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

from flask import Flask, jsonify, render_template_string, request

MAX_COMPRESSED_BYTES = 5 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 16 * 1024 * 1024
MAX_EVENTS_PER_BATCH = 1000
DASHBOARD_TIMEZONE = ZoneInfo("Asia/Shanghai")
DASHBOARD_LIMIT = 1000
DASHBOARD_CATEGORIES = (
    ("all", "全部分类"),
    ("command", "命令行输入"),
    ("text", "文字与交流"),
    ("shortcut", "操作按键"),
    ("process", "应用与进程"),
    ("clipboard", "剪贴板"),
    ("status", "活跃状态"),
)
DASHBOARD_PLACEHOLDERS = {
    "随心输入",
    "请输入内容",
    "请输入消息",
    "输入消息",
    "写消息",
    "发送消息",
    "type a message",
    "message",
    "ask anything",
}

DASHBOARD_HTML = """<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CatchMe 日志</title><style>
:root{color-scheme:light}body{margin:0;background:#f4f6f8;color:#18202a;font-family:system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1180px;margin:auto;padding:24px}.top h1{margin:0}
.filters,.cards,.event{background:#fff;border:1px solid #e4e7ec;border-radius:14px}.filters{display:flex;gap:12px;align-items:end;padding:16px;margin:20px 0;flex-wrap:wrap}
label{display:block;color:#475467;font-size:13px;margin-bottom:6px}input,select,button{font:inherit;padding:9px 11px;border-radius:8px;border:1px solid #d0d5dd;background:#fff}.search{min-width:260px;flex:1}.search input{box-sizing:border-box;width:100%}
button{background:#175cd3;color:#fff;border-color:#175cd3;cursor:pointer}.cards{display:flex;gap:28px;padding:16px 20px;margin-bottom:14px}.metric b{display:block;font-size:24px}.metric span{color:#667085;font-size:13px}
.events{display:grid;gap:10px}.event{padding:14px 16px}.meta{display:flex;gap:10px;align-items:center;flex-wrap:wrap;color:#667085;font-size:13px}.kind{font-weight:700;color:#175cd3;background:#eff8ff;padding:3px 8px;border-radius:99px}.kind.command{color:#067647;background:#ecfdf3}.kind.text{color:#6941c6;background:#f4f3ff}.kind.shortcut{color:#b54708;background:#fffaeb}.kind.process{color:#175cd3;background:#eff8ff}.kind.clipboard{color:#c11574;background:#fdf2fa}.kind.status{color:#475467;background:#f2f4f7}
.detail{white-space:pre-wrap;overflow-wrap:anywhere;margin:10px 0 0;line-height:1.55}.context{color:#475467;font-size:13px;margin-top:8px}.empty{text-align:center;padding:48px;color:#667085;background:#fff;border-radius:14px}
.notice{color:#667085;font-size:13px}@media(max-width:620px){main{padding:14px}.cards{gap:16px}.top{align-items:flex-start}.event{padding:12px}}
</style></head><body><main><header class="top"><div><h1>CatchMe 日志</h1><div class="notice">时间按 Asia/Shanghai 显示</div></div></header>
<form class="filters" method="get" action=""><div><label for="date">日期</label><input id="date" name="date" type="date" value="{{ date_text }}"></div>
<div><label for="device">设备</label><select id="device" name="device"><option value="">全部设备</option>{% for device in devices %}<option value="{{ device.id }}" {% if device.id == selected_device %}selected{% endif %}>{{ device.name }} · {{ device.id[:8] }}</option>{% endfor %}</select></div>
<div><label for="category">分类</label><select id="category" name="category">{% for value, label in categories %}<option value="{{ value }}" {% if value == selected_category %}selected{% endif %}>{{ label }}</option>{% endfor %}</select></div>
<div><label for="view">视图</label><select id="view" name="view"><option value="readable" {% if selected_view == 'readable' %}selected{% endif %}>整理视图</option><option value="raw" {% if selected_view == 'raw' %}selected{% endif %}>原始事件</option></select></div>
<div class="search"><label for="q">搜索</label><input id="q" name="q" type="search" value="{{ search_query }}" placeholder="搜索文字、命令、窗口或应用"></div><button type="submit">查看</button></form>
<section class="cards"><div class="metric"><b>{{ total }}</b><span>当日原始事件</span></div><div class="metric"><b>{{ category_raw_count }}</b><span>当前分类原始事件</span></div><div class="metric"><b>{{ rows|length }}</b><span>{% if selected_view == 'readable' %}整理后活动{% else %}本页显示{% endif %}</span></div></section>
{% if search_query %}<p class="notice">正在搜索“{{ search_query }}”；占位提示也会在搜索结果中显示。</p>{% elif selected_view == 'readable' %}<p class="notice">已合并连续输入，并隐藏输入法确认空格、编辑按键及常见占位提示。</p>{% endif %}
{% if rows %}<section class="events">{% for row in rows %}<article class="event"><div class="meta"><span class="kind {{ row.category }}">{{ row.kind_label }}</span><time>{{ row.time }}</time><span>{{ row.device_name }} · {{ row.device_id[:8] }}</span></div>
<div class="detail">{{ row.detail }}</div>{% if row.app or row.title %}<div class="context">{{ row.app }}{% if row.title %} · {{ row.title }}{% endif %}</div>{% endif %}</article>{% endfor %}</section>
{% else %}<div class="empty">这一天还没有记录</div>{% endif %}{% if total > loaded_raw_count %}<p class="notice">为保证页面流畅，本页基于最新 {{ loaded_raw_count }} 条原始事件整理。</p>{% endif %}
</main></body></html>"""


def create_receiver_app(
    db_path: str | Path,
    token: str | None = None,
    dashboard_access_token: str | None = None,
) -> Flask:
    app = Flask("catchme-receiver")
    app.config["CATCHME_DB_PATH"] = str(db_path)
    app.config["CATCHME_SERVER_TOKEN"] = token or os.environ.get("CATCHME_SERVER_TOKEN", "")
    app.config["CATCHME_DASHBOARD_ACCESS_TOKEN"] = dashboard_access_token or os.environ.get(
        "CATCHME_DASHBOARD_ACCESS_TOKEN", ""
    )
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

    @app.post("/v1/devices/register")
    def register_device():
        """Create an upload-only identity without user-visible enrollment steps."""
        value = request.get_json(silent=True)
        if not isinstance(value, dict):
            return jsonify({"error": "body must be an object"}), 400
        device_id = str(value.get("device_id", ""))
        device_name = str(value.get("device_name", ""))[:200]
        try:
            uuid.UUID(device_id)
        except (ValueError, AttributeError):
            return jsonify({"error": "device_id must be a UUID"}), 400
        token, error = _register_device(app.config["CATCHME_DB_PATH"], device_id, device_name)
        if error:
            return jsonify({"error": error}), 409
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

    @app.get("/dashboard/<access_token>")
    def dashboard(access_token: str):
        expected = app.config.get("CATCHME_DASHBOARD_ACCESS_TOKEN", "")
        if not expected or not hmac.compare_digest(expected, access_token):
            return "Not found.", 404
        today = datetime.now(DASHBOARD_TIMEZONE).date()
        date_text = request.args.get("date", today.isoformat())
        try:
            local_day = datetime.strptime(date_text, "%Y-%m-%d").replace(
                tzinfo=DASHBOARD_TIMEZONE
            )
        except ValueError:
            date_text = today.isoformat()
            local_day = datetime.combine(today, datetime.min.time(), DASHBOARD_TIMEZONE)
        selected_device = request.args.get("device", "")
        selected_view = "raw" if request.args.get("view") == "raw" else "readable"
        search_query = request.args.get("q", "").strip()[:200]
        valid_categories = {value for value, _label in DASHBOARD_CATEGORIES}
        selected_category = request.args.get("category", "all")
        if selected_category not in valid_categories:
            selected_category = "all"
        rows, total = _dashboard_events(
            app.config["CATCHME_DB_PATH"],
            local_day.timestamp(),
            (local_day + timedelta(days=1)).timestamp(),
            selected_device,
        )
        loaded_raw_count = len(rows)
        if not search_query:
            rows = [row for row in rows if not _is_dashboard_placeholder(row)]
        category_raw_count = sum(
            1 for row in rows if selected_category == "all" or row["category"] == selected_category
        )
        if selected_view == "readable":
            rows = _readable_dashboard_rows(rows)
        if selected_category != "all":
            rows = [row for row in rows if row["category"] == selected_category]
        if search_query:
            search_value = search_query.casefold()
            rows = [row for row in rows if _dashboard_row_matches(row, search_value)]
        devices = _dashboard_devices(app.config["CATCHME_DB_PATH"])
        return render_template_string(
            DASHBOARD_HTML,
            date_text=date_text,
            selected_device=selected_device,
            selected_view=selected_view,
            selected_category=selected_category,
            search_query=search_query,
            categories=DASHBOARD_CATEGORIES,
            devices=devices,
            rows=rows,
            total=total,
            category_raw_count=category_raw_count,
            loaded_raw_count=loaded_raw_count,
        )

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


def _register_device(db_path: str, device_id: str, device_name: str) -> tuple[str, str]:
    """Register a new random device id once and return an upload-only token."""
    now = time.time()
    device_token = secrets.token_urlsafe(32)
    try:
        with _connect(db_path) as conn:
            conn.execute(
                "INSERT INTO device_tokens(device_id, token_hash, device_name, created_at, revoked_at) "
                "VALUES (?, ?, ?, ?, NULL)",
                (device_id, _token_hash(device_token), device_name, now),
            )
    except sqlite3.IntegrityError:
        return "", "device_id is already registered"
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


def _dashboard_devices(db_path: str) -> list[dict]:
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT device_id, device_name FROM device_tokens "
            "WHERE revoked_at IS NULL ORDER BY device_name, device_id"
        ).fetchall()
    return [{"id": row[0], "name": row[1] or "未命名设备"} for row in rows]


def _dashboard_events(
    db_path: str,
    start: float,
    end: float,
    device_id: str,
) -> tuple[list[dict], int]:
    where = "event_time >= ? AND event_time < ?"
    values: list[object] = [start, end]
    if device_id:
        where += " AND received_events.device_id = ?"
        values.append(device_id)
    with _connect(db_path) as conn:
        total = conn.execute(
            f"SELECT COUNT(*) FROM received_events WHERE {where}",  # noqa: S608
            values,
        ).fetchone()[0]
        rows = conn.execute(
            "SELECT received_events.device_id, event_time, kind, data, "
            "COALESCE(device_tokens.device_name, '') "
            "FROM received_events LEFT JOIN device_tokens "
            "ON received_events.device_id = device_tokens.device_id "
            f"WHERE {where} ORDER BY event_time DESC LIMIT ?",  # noqa: S608
            [*values, DASHBOARD_LIMIT],
        ).fetchall()
    return [_format_dashboard_row(row) for row in rows], int(total)


def _format_dashboard_row(row: tuple) -> dict:
    device_id, event_time, kind, data_text, device_name = row
    data = json.loads(data_text)
    context = data.get("context") if isinstance(data.get("context"), dict) else {}
    app_name = str(data.get("app") or context.get("app") or "")
    title = str(data.get("title") or context.get("title") or "")
    category = _dashboard_category(kind, data, app_name, title)
    labels = {
        "command": "命令",
        "text": "文字",
        "shortcut": "操作",
        "process": "进程",
        "clipboard": "剪贴板",
        "status": "状态",
    }
    if kind == "keyboard":
        key = str(data.get("key", ""))
        modifiers = "+".join(str(value) for value in data.get("modifiers", []))
        detail = f"{modifiers}+{key}" if modifiers else key
    elif kind == "clipboard":
        if data.get("dropped"):
            detail = f"内容未保存：{data.get('reason', '已跳过')}"
        else:
            detail = str(data.get("content", ""))
    elif kind == "window":
        detail = title or app_name or "窗口切换"
    elif kind == "idle":
        detail = "空闲" if data.get("status") == "idle" else "恢复活动"
    else:
        detail = json.dumps(data, ensure_ascii=False)
    if len(detail) > 4000:
        detail = detail[:4000] + "\n…（页面已截断）"
    local_time = datetime.fromtimestamp(float(event_time), UTC).astimezone(DASHBOARD_TIMEZONE)
    return {
        "device_id": device_id,
        "device_name": device_name or "未命名设备",
        "timestamp": float(event_time),
        "time": local_time.strftime("%H:%M:%S"),
        "kind": kind,
        "event_type": str(data.get("type", "")),
        "key": str(data.get("key", "")),
        "category": category,
        "kind_label": labels.get(category, kind),
        "detail": detail,
        "app": app_name,
        "title": title,
    }


def _dashboard_category(kind: str, data: dict, app_name: str, title: str) -> str:
    if kind == "window":
        return "process"
    if kind == "clipboard":
        return "clipboard"
    if kind == "idle":
        return "status"
    if kind != "keyboard":
        return "status"
    if data.get("type") != "text":
        return "shortcut"
    context_text = f"{app_name} {title}".lower()
    terminal_markers = (
        "windowsterminal",
        "windows terminal",
        "powershell",
        "pwsh",
        "cmd.exe",
        "command prompt",
        "命令提示符",
        "终端",
        "bash",
        "zsh",
        "wsl",
        "conhost",
        "git bash",
        "mintty",
    )
    if any(marker in context_text for marker in terminal_markers):
        return "command"
    return "text"


def _is_dashboard_placeholder(row: dict) -> bool:
    if row["category"] == "text" and row["event_type"] == "text":
        candidate = row["key"]
    elif row["category"] == "clipboard":
        candidate = row["detail"]
    else:
        return False
    value = candidate.casefold().strip(" \t\r\n.…。:：")
    return value in DASHBOARD_PLACEHOLDERS


def _dashboard_row_matches(row: dict, search_value: str) -> bool:
    fields = (
        row["detail"],
        row["app"],
        row["title"],
        row["kind_label"],
        row["device_name"],
        row["category"],
    )
    return any(search_value in str(value).casefold() for value in fields)


def _readable_dashboard_rows(rows: list[dict]) -> list[dict]:
    """Turn low-level keyboard events into readable input sessions."""
    activities: list[dict] = []
    pending: dict | None = None
    noise_keys = {
        "space",
        "backspace",
        "delete",
        "left",
        "right",
        "up",
        "down",
        "home",
        "end",
        "pageup",
        "pagedown",
        "tab",
        "escape",
    }

    def flush_pending() -> None:
        nonlocal pending
        if pending is not None and pending["detail"].strip():
            activities.append(pending)
        pending = None

    for row in reversed(rows):
        if row["kind"] != "keyboard":
            flush_pending()
            activities.append(row)
            continue

        if row["event_type"] == "text":
            same_session = (
                pending is not None
                and pending["device_id"] == row["device_id"]
                and pending["app"] == row["app"]
                and pending["title"] == row["title"]
                and row["timestamp"] - pending["last_timestamp"] <= 20
            )
            if not same_session:
                flush_pending()
                pending = dict(row)
                pending["kind_label"] = (
                    "命令输入" if row["category"] == "command" else "文字输入"
                )
                pending["start_time"] = row["time"]
                pending["last_timestamp"] = row["timestamp"]
            else:
                pending["detail"] += row["key"]
                pending["last_timestamp"] = row["timestamp"]
                if row["time"] != pending["start_time"]:
                    pending["time"] = f"{pending['start_time']}–{row['time']}"
            if len(pending["detail"]) > 8000:
                pending["detail"] = pending["detail"][:8000] + "\n…（整理视图已截断）"
                flush_pending()
            continue

        key = row["key"].lower()
        if key == "enter":
            if pending is not None and pending["category"] == "command":
                flush_pending()
            elif pending is not None and not pending["detail"].endswith("\n"):
                pending["detail"] += "\n"
            continue
        if key in noise_keys and row["event_type"] != "shortcut":
            continue
        flush_pending()
        activities.append(row)

    flush_pending()
    return list(reversed(activities))

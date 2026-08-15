"""Tests for privacy policy, clipboard limits, reliable sync, and receiver."""

from __future__ import annotations

import gzip
import json
import time
from unittest import mock

from catchme.config import Config
from catchme.privacy import CapturePolicy, grant_consent, has_consent, redact_text
from catchme.receiver import create_receiver_app
from catchme.recorders.clipboard import ClipboardRecorder
from catchme.store import Event, Store
from catchme.sync import SyncClient, SyncSettings


def test_config_loads_narrow_capture_settings(tmp_path):
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "capture": {
                    "enabled_recorders": ["window", "clipboard"],
                    "clipboard_max_bytes": 2 * 1024 * 1024,
                    "excluded_apps": ["vault"],
                }
            }
        ),
        "utf-8",
    )

    config = Config.from_user_settings(tmp_path)

    assert config.enabled_recorders == ("window", "clipboard")
    assert config.clipboard_max_bytes == 1024 * 1024
    assert config.excluded_apps == ("vault",)


def test_consent_round_trip(tmp_path):
    config = Config(root=tmp_path)
    assert not has_consent(config)
    grant_consent(config)
    assert has_consent(config)


def test_capture_policy_excludes_sensitive_window_and_context(tmp_path):
    config = Config(root=tmp_path, excluded_apps=("vault",))
    policy = CapturePolicy(config)

    assert policy.process("window", {"app": "My Vault", "title": "Home"}) is None
    assert policy.process("keyboard", {"key": "secret", "type": "text"}) is None

    window = policy.process("window", {"app": "Editor", "title": "notes"})
    event = policy.process("keyboard", {"key": "hello", "type": "text"})
    assert window is not None
    assert event is not None
    assert event["context"] == {"app": "Editor", "title": "notes"}


def test_secret_redaction():
    assert "sk-secret" not in redact_text("api_key=sk-secret-value-123456789")
    assert "[redacted:generic_secret]" in redact_text("api_key=sk-secret-value-123456789")


def test_clipboard_over_limit_drops_content(tmp_path):
    config = Config(root=tmp_path, clipboard_max_bytes=4)
    recorder = ClipboardRecorder(config)
    received = []

    with mock.patch("catchme.recorders.clipboard._read_clipboard_text", return_value="12345"):
        recorder.poll(lambda data, blob="": received.append(data))

    assert received == [
        {
            "type": "text/plain",
            "dropped": True,
            "reason": "clipboard_too_large",
            "size_bytes": 5,
            "max_bytes": 4,
        }
    ]


def test_store_tracks_sync_acknowledgement(tmp_path):
    store = Store(tmp_path / "events.db")
    store.insert_raw([Event(timestamp=time.time(), kind="keyboard", data={"key": "a"})])
    pending = store.query_unsynced()
    assert len(pending) == 1
    store.mark_synced([pending[0].id], time.time())
    assert store.query_unsynced() == []


def test_sync_client_uploads_gzip_and_marks_events(tmp_path, monkeypatch):
    config = Config(root=tmp_path)
    store = Store(config.db_path)
    store.insert_raw([Event(timestamp=123.0, kind="keyboard", data={"key": "a"})])
    monkeypatch.setenv("CATCHME_SYNC_TOKEN", "test-token")
    settings = SyncSettings(enabled=True, server_url="https://memory.example")
    response = mock.Mock()
    response.raise_for_status.return_value = None
    response.json.side_effect = lambda: {
        "accepted": True,
        "batch_id": post.call_args.kwargs["headers"]["X-CatchMe-Batch-ID"],
    }

    with mock.patch("catchme.sync.requests.post", return_value=response) as post:
        count = SyncClient(config, store, settings).upload_once()

    assert count == 1
    assert store.query_unsynced() == []
    call = post.call_args
    assert call.args[0] == "https://memory.example/v1/events/batches"
    assert call.kwargs["headers"]["Authorization"] == "Bearer test-token"
    payload = json.loads(gzip.decompress(call.kwargs["data"]))
    assert payload["events"][0]["kind"] == "keyboard"
    assert payload["events"][0]["data"] == {"key": "a"}


def test_sync_client_rejects_plain_http(tmp_path, monkeypatch):
    config = Config(root=tmp_path)
    store = Store(config.db_path)
    store.insert_raw([Event(timestamp=123.0, kind="keyboard", data={"key": "a"})])
    monkeypatch.setenv("CATCHME_SYNC_TOKEN", "test-token")
    client = SyncClient(config, store, SyncSettings(enabled=True, server_url="http://bad"))

    try:
        client.upload_once()
    except ValueError as exc:
        assert "HTTPS" in str(exc)
    else:
        raise AssertionError("plain HTTP was accepted")


def test_sync_client_keeps_events_when_acknowledgement_is_invalid(tmp_path, monkeypatch):
    config = Config(root=tmp_path)
    store = Store(config.db_path)
    store.insert_raw([Event(timestamp=123.0, kind="keyboard", data={"key": "a"})])
    monkeypatch.setenv("CATCHME_SYNC_TOKEN", "test-token")
    response = mock.Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = {"accepted": False, "batch_id": "wrong"}
    client = SyncClient(
        config,
        store,
        SyncSettings(enabled=True, server_url="https://memory.example"),
    )

    with mock.patch("catchme.sync.requests.post", return_value=response):
        try:
            client.upload_once()
        except RuntimeError as exc:
            assert "acknowledge" in str(exc)
        else:
            raise AssertionError("invalid acknowledgement was accepted")

    assert len(store.query_unsynced()) == 1


def test_receiver_is_authenticated_and_idempotent(tmp_path):
    app = create_receiver_app(tmp_path / "server.db", token="server-token")
    client = app.test_client()
    payload = {
        "batch_id": "batch-1",
        "device_id": "device-1",
        "events": [
            {
                "event_id": "device-1:1",
                "timestamp": 123.0,
                "kind": "keyboard",
                "data": {"key": "a"},
            }
        ],
    }
    body = gzip.compress(json.dumps(payload).encode())
    headers = {
        "Authorization": "Bearer server-token",
        "Content-Encoding": "gzip",
        "Content-Type": "application/json",
    }

    assert client.post("/v1/events/batches", data=body).status_code == 401
    first = client.post("/v1/events/batches", data=body, headers=headers)
    second = client.post("/v1/events/batches", data=body, headers=headers)
    assert first.get_json()["inserted"] == 1
    assert second.get_json()["inserted"] == 0

    exported = client.get(
        "/v1/events/export?date=1970-01-01",
        headers={"Authorization": "Bearer server-token"},
    )
    assert exported.status_code == 200
    assert exported.get_json()["events"][0]["event_id"] == "device-1:1"


def test_receiver_issues_single_use_upload_only_device_tokens(tmp_path):
    app = create_receiver_app(tmp_path / "server.db", token="server-token")
    client = app.test_client()
    master_headers = {"Authorization": "Bearer server-token"}

    created = client.post(
        "/v1/enrollment-codes",
        json={"ttl_seconds": 300},
        headers=master_headers,
    )
    assert created.status_code == 200
    code = created.get_json()["code"]

    enrolled = client.post(
        "/v1/devices/enroll",
        json={"code": code, "device_id": "lite-device-1", "device_name": "Laptop"},
    )
    assert enrolled.status_code == 200
    assert enrolled.get_json()["scope"] == "events:write"
    device_token = enrolled.get_json()["device_token"]

    reused = client.post(
        "/v1/devices/enroll",
        json={"code": code, "device_id": "lite-device-2", "device_name": "Other"},
    )
    assert reused.status_code == 403

    payload = {
        "batch_id": "lite-batch-1",
        "device_id": "lite-device-1",
        "events": [
            {
                "event_id": "lite-device-1:event-1",
                "timestamp": 123.0,
                "kind": "clipboard",
                "data": {"content": "hello"},
            }
        ],
    }
    device_headers = {"Authorization": f"Bearer {device_token}"}
    uploaded = client.post("/v1/events/batches", json=payload, headers=device_headers)
    assert uploaded.status_code == 200

    payload["batch_id"] = "lite-batch-wrong-device"
    payload["device_id"] = "lite-device-2"
    wrong_device = client.post("/v1/events/batches", json=payload, headers=device_headers)
    assert wrong_device.status_code == 401

    export = client.get("/v1/events/export?date=1970-01-01", headers=device_headers)
    assert export.status_code == 401


def test_receiver_automatically_registers_upload_only_device(tmp_path):
    app = create_receiver_app(tmp_path / "server.db", token="server-token")
    client = app.test_client()
    device_id = "4967a9ee-8692-4d21-881c-68e1d241cfe5"

    invalid = client.post(
        "/v1/devices/register",
        json={"device_id": "not-a-uuid", "device_name": "Laptop"},
    )
    assert invalid.status_code == 400

    registered = client.post(
        "/v1/devices/register",
        json={"device_id": device_id, "device_name": "Laptop"},
    )
    assert registered.status_code == 200
    assert registered.get_json()["scope"] == "events:write"
    device_token = registered.get_json()["device_token"]

    duplicate = client.post(
        "/v1/devices/register",
        json={"device_id": device_id, "device_name": "Other"},
    )
    assert duplicate.status_code == 409

    payload = {
        "batch_id": "automatic-registration-batch",
        "device_id": device_id,
        "events": [
            {
                "event_id": f"{device_id}:event-1",
                "timestamp": 123.0,
                "kind": "keyboard",
                "data": {"key": "hello", "type": "text"},
            }
        ],
    }
    device_headers = {"Authorization": f"Bearer {device_token}"}
    assert client.post("/v1/events/batches", json=payload, headers=device_headers).status_code == 200
    assert client.get("/v1/events/export?date=1970-01-01", headers=device_headers).status_code == 401


def test_receiver_dashboard_private_link_renders_events(tmp_path):
    app = create_receiver_app(
        tmp_path / "server.db",
        token="server-token",
        dashboard_access_token="private-link-token",
    )
    client = app.test_client()
    payload = {
        "batch_id": "dashboard-batch",
        "device_id": "dashboard-device",
        "events": [
            {
                "event_id": "dashboard-device:ime-space-1",
                "timestamp": 122.9,
                "kind": "keyboard",
                "data": {
                    "key": "space",
                    "type": "special",
                    "context": {"app": "notepad", "title": "Daily notes"},
                },
            },
            {
                "event_id": "dashboard-device:event-1",
                "timestamp": 123.0,
                "kind": "keyboard",
                "data": {
                    "key": "hello dashboard",
                    "type": "text",
                    "context": {"app": "notepad", "title": "Daily notes"},
                },
            },
            {
                "event_id": "dashboard-device:ime-space-2",
                "timestamp": 123.1,
                "kind": "keyboard",
                "data": {
                    "key": "space",
                    "type": "special",
                    "context": {"app": "notepad", "title": "Daily notes"},
                },
            },
            {
                "event_id": "dashboard-device:event-2",
                "timestamp": 123.2,
                "kind": "keyboard",
                "data": {
                    "key": "中文",
                    "type": "text",
                    "context": {"app": "notepad", "title": "Daily notes"},
                },
            },
            {
                "event_id": "dashboard-device:placeholder",
                "timestamp": 123.4,
                "kind": "keyboard",
                "data": {
                    "key": "随心输入",
                    "type": "text",
                    "context": {"app": "ChatGPT", "title": "ChatGPT"},
                },
            },
            {
                "event_id": "dashboard-device:command-1",
                "timestamp": 124.0,
                "kind": "keyboard",
                "data": {
                    "key": "Get-Process",
                    "type": "text",
                    "context": {"app": "pwsh", "title": "PowerShell"},
                },
            },
            {
                "event_id": "dashboard-device:command-enter",
                "timestamp": 124.1,
                "kind": "keyboard",
                "data": {
                    "key": "enter",
                    "type": "special",
                    "context": {"app": "pwsh", "title": "PowerShell"},
                },
            },
            {
                "event_id": "dashboard-device:command-2",
                "timestamp": 124.2,
                "kind": "keyboard",
                "data": {
                    "key": "git status",
                    "type": "text",
                    "context": {"app": "pwsh", "title": "PowerShell"},
                },
            },
        ],
    }
    uploaded = client.post(
        "/v1/events/batches",
        json=payload,
        headers={"Authorization": "Bearer server-token"},
    )
    assert uploaded.status_code == 200

    assert client.get("/dashboard").status_code == 404
    assert client.get("/dashboard/wrong-token").status_code == 404

    dashboard = client.get("/dashboard/private-link-token?date=1970-01-01")
    assert dashboard.status_code == 200
    page = dashboard.get_data(as_text=True)
    assert "hello dashboard中文" in page
    assert "Daily notes" in page
    assert "文字输入" in page
    assert page.count("命令输入") == 2
    assert 'class="detail">space</div>' not in page
    assert "随心输入" not in page
    assert "命令行输入" in page
    assert "应用与进程" in page

    searched = client.get(
        "/dashboard/private-link-token",
        query_string={"date": "1970-01-01", "q": "随心输入"},
    )
    assert searched.status_code == 200
    assert "随心输入" in searched.get_data(as_text=True)
    assert "占位提示也会在搜索结果中显示" in searched.get_data(as_text=True)

    commands = client.get(
        "/dashboard/private-link-token?date=1970-01-01&category=command"
    ).get_data(as_text=True)
    assert "Get-Process" in commands
    assert "git status" in commands
    assert "hello dashboard" not in commands

    text_entries = client.get(
        "/dashboard/private-link-token?date=1970-01-01&category=text"
    ).get_data(as_text=True)
    assert "hello dashboard中文" in text_entries
    assert "Get-Process" not in text_entries

    raw = client.get("/dashboard/private-link-token?date=1970-01-01&view=raw")
    assert raw.status_code == 200
    assert 'class="detail">space</div>' in raw.get_data(as_text=True)

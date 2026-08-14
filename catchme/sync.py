"""Reliable, opt-in batch upload for locally captured events."""

from __future__ import annotations

import gzip
import json
import logging
import os
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any

import requests

from .config import Config
from .privacy import _write_private_json
from .services import load_config
from .store import Event, Store

log = logging.getLogger(__name__)

_CREDENTIAL_TARGET = "CatchMe Personal Recorder Sync"


@dataclass(frozen=True)
class SyncSettings:
    enabled: bool = False
    server_url: str = ""
    interval_seconds: float = 60.0
    batch_size: int = 250
    timeout_seconds: float = 20.0

    @classmethod
    def load(cls, config: Config) -> SyncSettings:
        raw = load_config(config.config_path, reload=True).get("sync", {})
        return cls(
            enabled=bool(raw.get("enabled", False)),
            server_url=str(raw.get("server_url", "")).rstrip("/"),
            interval_seconds=max(5.0, float(raw.get("interval_seconds", 60.0))),
            batch_size=min(1000, max(1, int(raw.get("batch_size", 250)))),
            timeout_seconds=max(3.0, float(raw.get("timeout_seconds", 20.0))),
        )


def get_or_create_device_id(config: Config) -> str:
    try:
        value = json.loads(config.device_path.read_text("utf-8"))
        device_id = str(value.get("device_id", ""))
        uuid.UUID(device_id)
        return device_id
    except (OSError, ValueError, TypeError, AttributeError):
        device_id = str(uuid.uuid4())
        _write_private_json(config.device_path, {"device_id": device_id})
        return device_id


def save_sync_token(token: str) -> None:
    if not token:
        raise ValueError("sync token cannot be empty")
    if sys.platform != "win32":
        raise RuntimeError("store the token in CATCHME_SYNC_TOKEN on this platform")
    import win32cred

    win32cred.CredWrite(
        {
            "Type": win32cred.CRED_TYPE_GENERIC,
            "TargetName": _CREDENTIAL_TARGET,
            "UserName": "catchme-device",
            "CredentialBlob": token,
            "Persist": win32cred.CRED_PERSIST_LOCAL_MACHINE,
        },
        0,
    )


def load_sync_token() -> str:
    env_token = os.environ.get("CATCHME_SYNC_TOKEN", "")
    if env_token:
        return env_token
    if sys.platform != "win32":
        return ""
    try:
        import win32cred

        record = win32cred.CredRead(_CREDENTIAL_TARGET, win32cred.CRED_TYPE_GENERIC, 0)
        blob = record.get("CredentialBlob", b"")
        return blob.decode("utf-16-le") if isinstance(blob, bytes) else str(blob)
    except Exception:
        return ""


def delete_sync_token() -> None:
    if sys.platform != "win32":
        return
    try:
        import win32cred

        win32cred.CredDelete(_CREDENTIAL_TARGET, win32cred.CRED_TYPE_GENERIC, 0)
    except Exception:
        pass


class SyncClient:
    def __init__(self, config: Config, store: Store, settings: SyncSettings | None = None) -> None:
        self.config = config
        self.store = store
        self.settings = settings or SyncSettings.load(config)
        self.device_id = get_or_create_device_id(config)
        self._upload_lock = threading.Lock()

    def upload_once(self) -> int:
        with self._upload_lock:
            return self._upload_once()

    def _upload_once(self) -> int:
        if not self.settings.enabled or not self.settings.server_url:
            return 0
        if not self.settings.server_url.lower().startswith("https://"):
            raise ValueError("sync server_url must use HTTPS")
        token = load_sync_token()
        if not token:
            raise RuntimeError("sync token is not configured")

        events = self.store.query_unsynced(self.settings.batch_size)
        if not events:
            return 0

        batch_id = str(uuid.uuid4())
        payload = {
            "batch_id": batch_id,
            "device_id": self.device_id,
            "sent_at": time.time(),
            "events": [self._serialize_event(event) for event in events],
        }
        body = gzip.compress(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
        endpoint = f"{self.settings.server_url}/v1/events/batches"
        response = requests.post(
            endpoint,
            data=body,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
                "X-CatchMe-Batch-ID": batch_id,
            },
            timeout=self.settings.timeout_seconds,
        )
        response.raise_for_status()
        try:
            acknowledgement = response.json()
        except ValueError as exc:
            raise RuntimeError("sync server returned an invalid acknowledgement") from exc
        if not acknowledgement.get("accepted") or acknowledgement.get("batch_id") != batch_id:
            raise RuntimeError("sync server did not acknowledge this batch")
        event_ids = [event.id for event in events if event.id is not None]
        self.store.mark_synced(event_ids, time.time())
        log.info("sync acknowledged batch=%s events=%d", batch_id, len(event_ids))
        return len(event_ids)

    def _serialize_event(self, event: Event) -> dict[str, Any]:
        assert event.id is not None
        return {
            "event_id": f"{self.device_id}:{event.id}",
            "timestamp": event.timestamp,
            "kind": event.kind,
            "data": event.data,
        }


class SyncWorker:
    def __init__(self, client: SyncClient) -> None:
        self.client = client
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if not self.client.settings.enabled:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="catchme-sync", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                while self.client.upload_once():
                    if self._stop.is_set():
                        return
            except Exception as exc:
                # Never include request bodies or event contents in logs.
                log.warning("sync attempt failed: %s", exc)
            self._stop.wait(self.client.settings.interval_seconds)

"""Consent and capture-time privacy controls."""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from pathlib import Path

from .config import Config

CONSENT_VERSION = 1

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "private_key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----.*?"
            r"-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
            re.DOTALL,
        ),
    ),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("github_token", re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    (
        "generic_secret",
        re.compile(
            r"(?i)\b(api[_-]?key|access[_-]?token|secret|password|passwd)\b"
            r"\s*[:=]\s*([^\s,;]{8,})"
        ),
    ),
)


def redact_text(text: str) -> str:
    """Replace high-confidence secrets while preserving surrounding context."""
    value = text
    for kind, pattern in _SECRET_PATTERNS:
        if kind == "generic_secret":
            value = pattern.sub(
                lambda match, label=kind: f"{match.group(1)}=[redacted:{label}]", value
            )
        else:
            value = pattern.sub(f"[redacted:{kind}]", value)
    return value


@dataclass(frozen=True)
class WindowContext:
    app: str = ""
    title: str = ""


class CapturePolicy:
    """Drop events from excluded contexts and redact text before persistence."""

    def __init__(self, config: Config) -> None:
        self._excluded_apps = tuple(x.casefold() for x in config.excluded_apps if x)
        self._excluded_titles = tuple(x.casefold() for x in config.excluded_window_titles if x)
        self._redact = config.redact_secrets
        self._window = WindowContext()
        self._has_window_context = False

    @property
    def window(self) -> WindowContext:
        return self._window

    def process(self, kind: str, data: dict) -> dict | None:
        if kind == "window":
            self._window = WindowContext(
                app=str(data.get("app", "")),
                title=str(data.get("title", "")),
            )
            self._has_window_context = True
            if self._is_excluded(self._window):
                return None
            return data

        # The active-window recorder starts alongside the input recorders. Do
        # not accept text during that short startup race because an excluded
        # application may already have focus.
        if kind in {"keyboard", "clipboard"} and not self._has_window_context:
            return None
        if self._is_excluded(self._window):
            return None

        cleaned = dict(data)
        if self._redact:
            if kind == "clipboard" and isinstance(cleaned.get("content"), str):
                cleaned["content"] = redact_text(cleaned["content"])
            elif kind == "keyboard" and isinstance(cleaned.get("key"), str):
                cleaned["key"] = redact_text(cleaned["key"])
        if self._window.app and "context" not in cleaned:
            cleaned["context"] = {
                "app": self._window.app,
                "title": self._window.title,
            }
        return cleaned

    def _is_excluded(self, context: WindowContext) -> bool:
        app = context.app.casefold()
        title = context.title.casefold()
        return any(value in app for value in self._excluded_apps) or any(
            value in title for value in self._excluded_titles
        )


def has_consent(config: Config) -> bool:
    try:
        record = json.loads(config.consent_path.read_text("utf-8"))
    except (OSError, ValueError, TypeError):
        return False
    return bool(record.get("granted")) and record.get("version") == CONSENT_VERSION


def grant_consent(config: Config) -> None:
    config.ensure_dirs()
    record = {
        "version": CONSENT_VERSION,
        "granted": True,
        "granted_at": time.time(),
        "enabled_recorders": list(config.enabled_recorders),
        "clipboard_max_bytes": config.clipboard_max_bytes,
    }
    _write_private_json(config.consent_path, record)


def revoke_consent(config: Config) -> None:
    try:
        config.consent_path.unlink()
    except FileNotFoundError:
        pass


def _write_private_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", "utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass

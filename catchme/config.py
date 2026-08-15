"""Paths, intervals, and defaults. One place for all knobs."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Config:
    root: Path = field(default_factory=lambda: Path.home() / ".catchme")

    # Capture policy.  Keep the default deliberately narrow: enough context to
    # make committed text and clipboard history useful, without screenshots,
    # mouse trails, or notifications.
    enabled_recorders: tuple[str, ...] = ("window", "keyboard", "clipboard", "idle")
    clipboard_max_bytes: int = 1024 * 1024
    redact_secrets: bool = True
    excluded_apps: tuple[str, ...] = (
        "1password",
        "bitwarden",
        "keepass",
        "keepassxc",
        "lastpass",
        "dashlane",
        "enpass",
    )
    excluded_window_titles: tuple[str, ...] = (
        "password",
        "密码",
        "验证码",
        "one-time code",
    )

    # Recorder intervals (seconds)
    window_interval: float = 1.0
    clipboard_interval: float = 1.0
    idle_interval: float = 5.0
    idle_timeout: float = 300.0
    scroll_session_timeout: float = 1.5

    # Engine
    batch_size: int = 100
    batch_timeout: float = 1.0
    organizer_enabled: bool = True

    # Pipelines
    pipeline_poll_interval: float = 5.0
    pipeline_batch_window: float = 60.0
    extension_ws_port: int = 8766

    @property
    def db_path(self) -> Path:
        return self.root / "data.db"

    @property
    def blob_dir(self) -> Path:
        return self.root / "blobs"

    @property
    def tree_dir(self) -> Path:
        return self.root / "trees"

    @property
    def workspace_dir(self) -> Path:
        return self.root / "workspace"

    @property
    def config_path(self) -> Path:
        return self.root / "config.json"

    @property
    def usage_path(self) -> Path:
        return self.root / "llm_usage.json"

    @property
    def notify_path(self) -> Path:
        return self.root / "summary_updates.jsonl"

    @property
    def monitor_history_path(self) -> Path:
        return self.root / "monitor_history.json"

    @property
    def consent_path(self) -> Path:
        return self.root / "consent.json"

    @property
    def device_path(self) -> Path:
        return self.root / "device.json"

    @property
    def background_log_path(self) -> Path:
        return self.root / "background.log"

    @classmethod
    def from_user_settings(cls, root: Path | None = None) -> Config:
        """Build recorder settings from ``~/.catchme/config.json``.

        The service configuration loader intentionally remains separate; this
        small loader keeps the recorder core usable without importing service
        modules and avoids circular imports.
        """
        cfg = cls(root=root or Path.home() / ".catchme")
        if not cfg.config_path.exists():
            return cfg
        try:
            raw = json.loads(cfg.config_path.read_text("utf-8"))
        except (OSError, ValueError, TypeError):
            return cfg

        capture = raw.get("capture", {})
        if not isinstance(capture, dict):
            return cfg

        enabled = capture.get("enabled_recorders")
        if isinstance(enabled, list) and all(isinstance(item, str) for item in enabled):
            cfg.enabled_recorders = tuple(enabled)

        max_bytes = capture.get("clipboard_max_bytes")
        if isinstance(max_bytes, int) and max_bytes > 0:
            cfg.clipboard_max_bytes = min(max_bytes, 1024 * 1024)

        redact = capture.get("redact_secrets")
        if isinstance(redact, bool):
            cfg.redact_secrets = redact

        excluded_apps = capture.get("excluded_apps")
        if isinstance(excluded_apps, list) and all(isinstance(item, str) for item in excluded_apps):
            cfg.excluded_apps = tuple(excluded_apps)

        excluded_titles = capture.get("excluded_window_titles")
        if isinstance(excluded_titles, list) and all(
            isinstance(item, str) for item in excluded_titles
        ):
            cfg.excluded_window_titles = tuple(excluded_titles)
        return cfg

    def ensure_dirs(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self.blob_dir.mkdir(parents=True, exist_ok=True)
        self.tree_dir.mkdir(parents=True, exist_ok=True)
        (self.workspace_dir / "pdf").mkdir(parents=True, exist_ok=True)
        (self.workspace_dir / "html").mkdir(parents=True, exist_ok=True)


_default: Config | None = None


def get_default_config() -> Config:
    """Return a lazily-initialized default Config singleton."""
    global _default
    if _default is None:
        _default = Config()
        _default.ensure_dirs()
    return _default

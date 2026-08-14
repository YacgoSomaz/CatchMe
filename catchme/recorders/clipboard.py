"""Clipboard change recorder — cross-platform (macOS / Windows)."""

from __future__ import annotations

import hashlib
import sys

from ..config import Config
from ..recorder import Emit, PollingRecorder


def _read_clipboard_text() -> str:
    if sys.platform == "darwin":
        from AppKit import NSPasteboard, NSStringPboardType

        pb = NSPasteboard.generalPasteboard()
        text = pb.stringForType_(NSStringPboardType)
        return str(text) if text else ""

    if sys.platform == "win32":
        import win32clipboard

        try:
            win32clipboard.OpenClipboard()
            text = win32clipboard.GetClipboardData(win32clipboard.CF_UNICODETEXT)
            win32clipboard.CloseClipboard()
            return text or ""
        except Exception:
            try:
                win32clipboard.CloseClipboard()
            except Exception:
                pass
            return ""

    return ""


class ClipboardRecorder(PollingRecorder):
    kind = "clipboard"
    needs_config = True

    def __init__(self, config: Config) -> None:
        super().__init__()
        self.interval = config.clipboard_interval
        self.max_bytes = config.clipboard_max_bytes
        self._prev_hash: str = ""

    def poll(self, emit: Emit) -> None:
        text = _read_clipboard_text()
        if not text:
            return
        h = hashlib.md5(text.encode()).hexdigest()
        if h == self._prev_hash:
            return
        self._prev_hash = h
        size_bytes = len(text.encode("utf-8"))
        if size_bytes > self.max_bytes:
            emit(
                {
                    "type": "text/plain",
                    "dropped": True,
                    "reason": "clipboard_too_large",
                    "size_bytes": size_bytes,
                    "max_bytes": self.max_bytes,
                }
            )
            return
        emit({"content": text, "type": "text/plain"})

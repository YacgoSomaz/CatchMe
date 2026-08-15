"""Portable Windows entry point used by the standalone executable."""

from __future__ import annotations

import os
import sys
import tempfile
import traceback
from urllib.parse import urlparse

_MB_OK = 0x00000000
_MB_YESNO = 0x00000004
_MB_ICONINFORMATION = 0x00000040
_MB_ICONWARNING = 0x00000030
_MB_ICONERROR = 0x00000010
_MB_DEFBUTTON2 = 0x00000100
_IDYES = 6


def _message(text: str, title: str, flags: int) -> int:
    import ctypes

    return int(ctypes.windll.user32.MessageBoxW(None, text, title, flags))


def _confirm_recording() -> bool:
    text = (
        "CatchMe 将在本机记录：\n\n"
        "• 已提交的键盘文本、快捷键和活动窗口信息\n"
        "• 不超过 1 MiB 的剪贴板文本\n"
        "• 空闲与锁屏状态\n\n"
        "密码输入框、密码管理器和配置中排除的敏感窗口不会记录。\n"
        "运行期间系统托盘会显示 CatchMe 图标，可随时暂停或退出。\n\n"
        "是否同意启用记录并设置为登录后自动启动？"
    )
    return (
        _message(
            text,
            "CatchMe 个人记录授权",
            _MB_YESNO | _MB_ICONWARNING | _MB_DEFBUTTON2,
        )
        == _IDYES
    )


def _configure_sync_from_environment() -> None:
    """Provision sync without embedding a server credential in the binary."""
    server_url = os.environ.get("CATCHME_SERVER_URL", "").strip().rstrip("/")
    token = os.environ.get("CATCHME_SYNC_TOKEN", "").strip()
    if not server_url and not token:
        return
    parsed = urlparse(server_url)
    if parsed.scheme.lower() != "https" or not parsed.netloc or not token:
        raise ValueError("CATCHME_SERVER_URL must be HTTPS and CATCHME_SYNC_TOKEN must both be set")

    from catchme.config import Config
    from catchme.services import load_config, save_config
    from catchme.sync import save_sync_token

    config = Config.from_user_settings()
    save_sync_token(token)
    raw = load_config(config.config_path, reload=True)
    raw["sync"] = {
        **raw.get("sync", {}),
        "enabled": True,
        "server_url": server_url,
    }
    save_config(raw, config.config_path)
    os.environ.pop("CATCHME_SYNC_TOKEN", None)


def _setup_and_start() -> int:
    from catchme.background import install_startup, start_background_process
    from catchme.config import Config
    from catchme.privacy import grant_consent, has_consent

    config = Config.from_user_settings()
    if not has_consent(config):
        if not _confirm_recording():
            return 2
        grant_consent(config)

    _configure_sync_from_environment()
    install_startup()
    start_background_process()
    _message(
        "CatchMe 已在后台启动。\n\n你可以通过系统托盘图标暂停、立即同步或退出。",
        "CatchMe",
        _MB_OK | _MB_ICONINFORMATION,
    )
    return 0


def _self_test() -> int:
    """Import the packaged Windows runtime without starting any recorder."""
    try:
        from pathlib import Path

        import comtypes  # noqa: F401
        import pystray  # noqa: F401
        import win32clipboard  # noqa: F401
        import win32com.client  # noqa: F401
        import win32cred  # noqa: F401
        from PIL import Image
        from pynput import keyboard  # noqa: F401

        import catchme.background

        icon_path = (
            Path(catchme.background.__file__).resolve().parent
            / "static"
            / "img"
            / "catchme_icon.png"
        )
        with Image.open(icon_path) as icon:
            icon.verify()
        return 0
    except Exception:
        diagnostic = os.path.join(tempfile.gettempdir(), "CatchMe-self-test-error.txt")
        with open(diagnostic, "w", encoding="utf-8") as stream:
            traceback.print_exc(file=stream)
        return 1


def main() -> int:
    if sys.platform != "win32":
        return 2
    if len(sys.argv) > 1 and sys.argv[1].casefold() == "background":
        from catchme.background import run_background

        return run_background()
    if len(sys.argv) > 1 and sys.argv[1].casefold() == "self-test":
        # Some Windows GUI backends keep helper threads alive after import.
        # A build probe must terminate deterministically without starting any
        # recorder or waiting for those optional backend threads.
        os._exit(_self_test())
    try:
        return _setup_and_start()
    except Exception as exc:
        _message(
            f"CatchMe 无法启动：\n\n{exc}",
            "CatchMe 启动失败",
            _MB_OK | _MB_ICONERROR,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

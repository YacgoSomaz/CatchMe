"""Low-interruption background runtime with a visible system-tray control."""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import threading
from logging.handlers import RotatingFileHandler
from pathlib import Path

from .config import Config
from .privacy import has_consent

_SHORTCUT_NAME = "CatchMe Personal Recorder.lnk"
_MUTEX_NAME = r"Local\CatchMePersonalRecorder"


def run_background() -> int:
    config = Config.from_user_settings()
    # Background capture and upload stay lightweight.  Tree building and LLM
    # summarization belong on the server or in an explicitly launched CLI.
    config.organizer_enabled = False
    config.ensure_dirs()
    if not has_consent(config):
        return 2

    handler = RotatingFileHandler(
        config.background_log_path,
        maxBytes=1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    logging.basicConfig(level=logging.INFO, handlers=[handler])
    mutex = _acquire_single_instance()
    if mutex is None:
        return 0

    try:
        return _run_tray(config)
    except Exception:
        logging.exception("background runtime stopped unexpectedly")
        return 1


def _run_tray(config: Config) -> int:
    import pystray
    from PIL import Image

    from catchme import CatchMe
    from catchme.sync import SyncClient, SyncWorker

    recorder = CatchMe(config)
    sync_client = SyncClient(config, recorder.store)
    sync_worker = SyncWorker(sync_client)

    icon_path = Path(__file__).resolve().parent / "static" / "img" / "catchme_icon.png"
    image = Image.open(icon_path)

    def status_text(_item) -> str:
        return "Status: paused" if recorder.paused else "Status: recording"

    def toggle_text(_item) -> str:
        return "Resume recording" if recorder.paused else "Pause recording"

    def toggle_recording(icon, _item) -> None:
        if recorder.paused:
            recorder.resume()
            icon.title = "CatchMe — recording"
        else:
            recorder.pause()
            icon.title = "CatchMe — paused"
        icon.update_menu()

    def sync_now(_icon, _item) -> None:
        def upload() -> None:
            try:
                sync_client.upload_once()
            except Exception as exc:
                logging.warning("manual sync failed: %s", exc)

        threading.Thread(target=upload, name="catchme-manual-sync", daemon=True).start()

    def open_data(_icon, _item) -> None:
        if sys.platform == "win32":
            os.startfile(config.root)  # type: ignore[attr-defined]
        else:
            subprocess.Popen(["xdg-open", str(config.root)])

    def stop(icon, _item) -> None:
        icon.stop()

    menu = pystray.Menu(
        pystray.MenuItem(status_text, None, enabled=False),
        pystray.MenuItem(toggle_text, toggle_recording),
        pystray.MenuItem("Sync now", sync_now),
        pystray.MenuItem("Open data folder", open_data),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Exit CatchMe", stop),
    )
    icon = pystray.Icon(
        "catchme-personal-recorder",
        image,
        "CatchMe — recording",
        menu,
    )

    recorder.start()
    sync_worker.start()
    try:
        icon.run()
    finally:
        sync_worker.stop()
        recorder.stop()
    return 0


def _acquire_single_instance():
    if sys.platform != "win32":
        return object()
    import win32api
    import win32event
    import winerror

    handle = win32event.CreateMutex(None, False, _MUTEX_NAME)
    if win32api.GetLastError() == winerror.ERROR_ALREADY_EXISTS:
        return None
    return handle


def startup_shortcut_path() -> Path:
    if sys.platform != "win32":
        raise RuntimeError("startup shortcut management is currently Windows-only")
    from win32com.shell import shell, shellcon

    startup = shell.SHGetFolderPath(0, shellcon.CSIDL_STARTUP, None, 0)
    return Path(startup) / _SHORTCUT_NAME


def install_startup() -> Path:
    """Install a normal per-user Startup entry after consent is granted."""
    if sys.platform != "win32":
        raise RuntimeError("startup installation is currently Windows-only")
    config = Config.from_user_settings()
    if not has_consent(config):
        raise PermissionError("recording consent has not been granted")

    target, arguments, working_directory = _background_command()

    import win32com.client

    shortcut_path = startup_shortcut_path()
    shortcut = win32com.client.Dispatch("WScript.Shell").CreateShortcut(str(shortcut_path))
    shortcut.TargetPath = str(target)
    shortcut.Arguments = subprocess.list2cmdline(arguments)
    shortcut.WorkingDirectory = str(working_directory)
    shortcut.Description = "CatchMe personal activity recorder (tray controls available)"
    shortcut.IconLocation = str(target)
    shortcut.Save()
    return shortcut_path


def remove_startup() -> bool:
    path = startup_shortcut_path()
    try:
        path.unlink()
        return True
    except FileNotFoundError:
        return False


def startup_installed() -> bool:
    return startup_shortcut_path().exists()


def start_background_process() -> None:
    """Start the consent-gated tray runtime without opening a console window."""
    if sys.platform != "win32":
        raise RuntimeError("background process launcher is currently Windows-only")
    config = Config.from_user_settings()
    if not has_consent(config):
        raise PermissionError("recording consent has not been granted")
    target, arguments, working_directory = _background_command()
    subprocess.Popen(
        [str(target), *arguments],
        cwd=str(working_directory),
        close_fds=True,
        creationflags=(
            getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            | getattr(subprocess, "CREATE_NO_WINDOW", 0)
        ),
    )


def _background_command() -> tuple[Path, list[str], Path]:
    """Return a stable launcher for source and PyInstaller runtimes."""
    executable = Path(sys.executable).resolve()
    if getattr(sys, "frozen", False):
        return executable, ["background"], executable.parent

    pythonw = executable.with_name("pythonw.exe")
    if not pythonw.exists():
        raise RuntimeError(f"pythonw.exe was not found next to {executable}")
    return pythonw, ["-m", "catchme", "background"], Path(__file__).resolve().parent.parent

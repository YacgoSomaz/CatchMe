# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path

repo = Path(SPECPATH).resolve().parent

a = Analysis(
    [str(repo / "catchme" / "portable.py")],
    pathex=[str(repo)],
    binaries=[],
    datas=[
        (str(repo / "catchme" / "static" / "img" / "catchme_icon.png"), "catchme/static/img"),
        (str(repo / "catchme" / "services" / "config.example.json"), "catchme/services"),
    ],
    hiddenimports=[
        "catchme.recorders.clipboard",
        "catchme.recorders.idle",
        "catchme.recorders.keyboard_windows",
        "catchme.recorders.platform.windows",
        "catchme.recorders.window",
        "pynput.keyboard._win32",
        "pynput.mouse._win32",
        "pystray._win32",
        "win32timezone",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "flask",
        "fitz",
        "numpy",
        "openai",
        "pymupdf",
        "trafilatura",
        "websockets",
    ],
    noarchive=False,
    optimize=1,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="CatchMe",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=True,
    icon=str(repo / "catchme" / "static" / "img" / "catchme_icon.png"),
)

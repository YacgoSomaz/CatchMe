from __future__ import annotations

import sys
from pathlib import Path

from catchme import background, portable


def test_portable_consent_defaults_to_no(monkeypatch):
    monkeypatch.setattr(portable, "_message", lambda *_args: 7)
    assert portable._confirm_recording() is False


def test_portable_consent_accepts_explicit_yes(monkeypatch):
    monkeypatch.setattr(portable, "_message", lambda *_args: portable._IDYES)
    assert portable._confirm_recording() is True


def test_frozen_background_command_targets_portable_executable(monkeypatch, tmp_path):
    executable = tmp_path / "CatchMe.exe"
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(executable))

    target, arguments, working_directory = background._background_command()

    assert target == Path(executable).resolve()
    assert arguments == ["background"]
    assert working_directory == executable.parent.resolve()

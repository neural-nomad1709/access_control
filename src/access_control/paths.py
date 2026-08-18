"""Filesystem locations used by the utility.

Audit logs and session state deliberately live *outside* the repository.  This
repo sits inside a OneDrive-synced folder, so anything written here would be
uploaded to the cloud -- captured server output must not be.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from . import APP_NAME


def app_data_dir() -> Path:
    """Per-user private data directory, never inside the repo."""
    override = os.environ.get("AC_DATA_DIR")
    if override:
        return Path(override).expanduser()

    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    elif sys.platform == "darwin":
        base = str(Path.home() / "Library" / "Application Support")
    else:
        base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / APP_NAME


def log_dir() -> Path:
    """Where session audit logs (.jsonl) and summaries (.md) are written."""
    return app_data_dir() / "logs"


def session_dir() -> Path:
    """Where live session handoff files live, so every CLI process agrees."""
    return app_data_dir() / "sessions"


def repo_root() -> Path:
    """Root of the installed project (the directory holding ``config/``)."""
    override = os.environ.get("AC_HOME")
    if override:
        return Path(override).expanduser()
    # src/access_control/paths.py -> src/access_control -> src -> <root>
    return Path(__file__).resolve().parent.parent.parent


def config_dir() -> Path:
    """Directory holding ``inventory.yaml`` and ``operations.yaml``."""
    override = os.environ.get("AC_CONFIG_DIR")
    if override:
        return Path(override).expanduser()
    return repo_root() / "config"


def ensure_dir(path: Path) -> Path:
    """Create ``path`` (and parents) if missing; return it."""
    path.mkdir(parents=True, exist_ok=True)
    return path

"""
Where Warden keeps its live data.

The project folder is a bad place for it. Warden's registry and audit log are
SQLite databases written while Claude Desktop is running, and a project folder
often sits inside OneDrive, Dropbox or iCloud. Those tools copy and lock files
underneath you, which is exactly what a database cannot tolerate - the failure
shows up much later as Claude Desktop quietly losing its tools.

So live data goes in the per-user application data directory, which no sync
tool touches:

    Windows   %LOCALAPPDATA%\\Warden
    macOS     ~/Library/Application Support/Warden
    Linux     $XDG_DATA_HOME/warden, or ~/.local/share/warden

The policy file stays in the project folder, because that one is meant to be
read, edited and committed.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

SYNC_FOLDER_HINTS = ("onedrive", "dropbox", "google drive", "icloud", "box sync")


def data_dir(create: bool = False) -> Path:
    """
    The folder holding warden_registry.db and warden_audit.db.

    Creates nothing unless asked. Use ensure_data_dir() at the point a database
    is opened, so merely asking where something lives never leaves a stray
    folder behind.
    """
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        path = Path(base) / "Warden" if base else Path.home() / "Warden"
    elif sys.platform == "darwin":
        path = Path.home() / "Library" / "Application Support" / "Warden"
    else:
        base = os.environ.get("XDG_DATA_HOME")
        path = Path(base) / "warden" if base else Path.home() / ".local" / "share" / "warden"

    if create:
        path.mkdir(parents=True, exist_ok=True)
    return path


def registry_db(create: bool = False) -> Path:
    """
    Path to the live registry. Does not create anything by default - working
    out a path should have no side effects. Creation happens where a database
    is actually opened, via ensure_data_dir().
    """
    return data_dir(create) / "warden_registry.db"


def audit_db(create: bool = False) -> Path:
    """Path to the live audit log. Creates nothing by default."""
    return data_dir(create) / "warden_audit.db"


def ensure_data_dir() -> Path:
    """Create the live data folder. Call this before opening a database."""
    return data_dir(create=True)


def is_in_sync_folder(path: Path) -> str | None:
    """
    The name of the file-sync folder this path sits inside, if any.

    Used to warn rather than to block: a project folder in OneDrive is fine,
    a live database in one is not.
    """
    lowered = str(path).lower()
    for hint in SYNC_FOLDER_HINTS:
        if hint in lowered:
            return hint
    return None


def has_live_data() -> bool:
    """True once Warden has actually been used to protect something."""
    return audit_db().exists()

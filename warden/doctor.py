"""
Warden setup check.

Runs before you install Warden into Claude Desktop and reports what is ready,
what needs attention, and what would stop the install. It reads and reports
only - nothing here changes a single file.

The point is to fail here, with an explanation, rather than halfway through an
install with Claude Desktop in a broken state.

Run:  python -m warden.doctor
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

from .install import (
    InstallError,
    config_candidates,
    default_config_path,
    is_packaged_location,
    is_protected,
    is_stdio,
    load_config,
    server_argv,
)
from .paths import audit_db, ensure_data_dir, is_in_sync_folder
from .proxy import resolve_executable

WARDEN_HOME = Path(__file__).resolve().parent.parent
LINE = "-" * 74

OK = "  ok   "
WARN = " note  "
BAD = " STOP  "

_problems: list[str] = []
_notes: list[str] = []


def write_probe(folder: Path) -> str | None:
    """
    Can Warden create and delete a file here? Returns None if yes, else why not.

    tempfile.mkstemp hands back an OPEN file handle. Deleting a file that is
    still open works on Linux and fails on Windows with WinError 32, so the
    handle must be closed first - which is exactly the bug this function exists
    to stop being written twice.
    """
    fd = None
    probe: Path | None = None
    try:
        fd, name = tempfile.mkstemp(dir=folder, prefix=".check-")
        probe = Path(name)
    except OSError as exc:
        return str(exc)
    finally:
        if fd is not None:
            os.close(fd)

    try:
        probe.unlink()
    except OSError as exc:
        return f"created a test file but could not remove it: {exc}"
    return None


def report(level: str, message: str, detail: str = "") -> None:
    print(f"[{level}] {message}")
    if detail:
        for line in detail.splitlines():
            print(f"         {line}")
    if level == BAD:
        _problems.append(message)
    elif level == WARN:
        _notes.append(message)


def section(title: str) -> None:
    print(f"\n{title}\n{'.' * len(title)}")


# ---------------------------------------------------------------------------

def check_python() -> None:
    section("Python")
    exe = Path(sys.executable)
    report(OK, f"Python {sys.version_info.major}.{sys.version_info.minor}", str(exe))

    if sys.version_info < (3, 10):
        report(BAD, "Python 3.10 or newer is required.",
               "Install a newer Python from python.org and tick "
               "'Add python.exe to PATH'.")

    # Claude Desktop launches Warden by this exact path. The Microsoft Store
    # build of Python lives behind an alias that other applications often
    # cannot execute, even though it works fine when you type it yourself.
    if "windowsapps" in str(exe).lower():
        report(
            BAD,
            "This Python came from the Microsoft Store.",
            "Claude Desktop launches Warden using this path, and Store\n"
            "aliases usually fail when another program tries to run them.\n"
            "Install Python from python.org instead, ticking\n"
            "'Add python.exe to PATH', then run this check again.",
        )

    try:
        import yaml  # noqa: F401
        report(OK, "PyYAML is installed")
    except ImportError:
        report(BAD, "PyYAML is missing.",
               "Run menu option 1 (Setup), then try this check again.")


def check_warden() -> None:
    section("Warden")
    report(OK, "Warden folder", str(WARDEN_HOME))

    policy = WARDEN_HOME / "policy.yaml"
    if not policy.exists():
        report(BAD, "policy.yaml is missing from the Warden folder.",
               "Copy the Day 5 files in again - the paste may not have finished.")
    else:
        try:
            from .policy import load_policy
            load_policy(policy)
            report(OK, "policy.yaml loads correctly")
        except Exception as exc:  # noqa: BLE001 - the reason is shown to the user
            report(BAD, "policy.yaml could not be read.", str(exc))

    sync = is_in_sync_folder(WARDEN_HOME)
    if sync:
        report(WARN, f"The Warden folder is inside {sync}.",
               "That is fine for the code. Warden keeps its live databases\n"
               "elsewhere on purpose, because sync tools and databases\n"
               "do not mix.")


def check_data_dir() -> None:
    section("Live data")
    try:
        target = ensure_data_dir()
    except Exception as exc:  # noqa: BLE001
        report(BAD, "Could not work out where to keep live data.", str(exc))
        return

    report(OK, "Live data folder", str(target))

    sync = is_in_sync_folder(target)
    if sync:
        report(WARN, f"The live data folder is inside {sync}.",
               "Databases in a synced folder can be locked mid-write.")

    problem = write_probe(target)
    if problem:
        report(BAD, "Warden cannot write to its data folder.", problem)
    else:
        report(OK, "Warden can write there")

    if audit_db().exists():
        report(OK, "Warden has recorded live activity before")
    else:
        report(WARN, "No live activity recorded yet.",
               "Expected before your first protected server is used.")


def check_node() -> None:
    section("Node")
    for tool in ("node", "npx"):
        found = shutil.which(tool)
        if found:
            report(OK, f"{tool} found", found)
        else:
            report(WARN, f"{tool} was not found.",
                   "Only needed for MCP servers that run on Node, which is\n"
                   "most of them. Install from nodejs.org if you need one.")


def check_claude_desktop() -> None:
    section("Claude Desktop")
    try:
        config_path = default_config_path()
    except InstallError as exc:
        report(BAD, "Could not work out where the config lives.", str(exc))
        return

    report(OK, "Config file location", str(config_path))
    if is_packaged_location(config_path):
        report(WARN, "This is a packaged (Store-style) install of Claude Desktop.",
               "Windows redirects the app's settings into a private folder.\n"
               "Warden reads and writes that folder, which is what the app\n"
               "itself reads, so this works - it just looks unusual.")

    if not config_path.exists():
        checked = "\n".join(str(c) for c in config_candidates())
        report(
            BAD,
            "No Claude Desktop config file was found.",
            "Open Claude Desktop, go to Settings > Developer > Edit Config,\n"
            "then run this again.\n\n"
            "Looked in:\n" + checked,
        )
        return

    try:
        config = load_config(config_path)
    except InstallError as exc:
        report(BAD, "The config file could not be read.", str(exc))
        return
    report(OK, "The config file is valid JSON")

    problem = write_probe(config_path.parent)
    if problem:
        report(BAD, "Warden cannot write to the config folder.", problem)
    else:
        report(OK, "Warden can write to that folder")

    servers = config.get("mcpServers") or {}
    if not servers:
        report(
            WARN,
            "No MCP servers are configured yet.",
            "Option 10 protects a server you already have, so add one in\n"
            "Claude Desktop first. The official filesystem server is the\n"
            "usual starting point.",
        )
        return

    print()
    protectable = 0
    for name, entry in servers.items():
        if is_protected(entry):
            report(OK, f"{name}: already protected by Warden")
            continue
        if not is_stdio(entry):
            report(WARN, f"{name}: remote server, cannot be wrapped")
            continue

        argv = server_argv(entry)
        resolved = resolve_executable(argv)
        if os.path.isabs(resolved[0]) or shutil.which(argv[0]):
            protectable += 1
            report(OK, f"{name}: ready to protect", f"runs: {' '.join(argv[:3])}")
        else:
            report(
                WARN,
                f"{name}: its program '{argv[0]}' was not found.",
                "Warden could not start it to inspect its tools.\n"
                "It may still work inside Claude Desktop, but protecting\n"
                "it will fail until that program is on your PATH.",
            )

    if protectable:
        print()
        report(OK, f"{protectable} server(s) can be protected with menu option 10")


def main() -> None:
    print(f"\n{LINE}\nWARDEN SETUP CHECK\n{LINE}")
    print("Nothing here changes any file.")

    check_python()
    check_warden()
    check_data_dir()
    check_node()
    check_claude_desktop()

    print(f"\n{LINE}")
    if _problems:
        print(f"{len(_problems)} thing(s) must be fixed before installing:\n")
        for item in _problems:
            print(f"  - {item}")
        print("\nScroll up for what to do about each one.")
    elif _notes:
        print("Ready to install. A few things worth knowing:\n")
        for item in _notes:
            print(f"  - {item}")
    else:
        print("Everything checks out. Menu option 10 will work.")
    print(f"{LINE}\n")

    raise SystemExit(1 if _problems else 0)


if __name__ == "__main__":
    main()

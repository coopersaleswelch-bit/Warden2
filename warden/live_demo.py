"""
Set up a live refusal.

Warden has been installed and has allowed real traffic, but it has never
refused anything outside a demo. "It runs" and "it works" are different
claims, and only the second one is worth showing anyone.

This arranges the smallest honest version of the second claim:

    1. makes a folder for a protected server to work in
    2. turns on a policy rule that forbids destructive tools
    3. protects a fresh server pointed at that folder

After a restart, asking the client to WRITE a file is refused - not because
the tool was blocked by name, but because the tool declares itself destructive
and the policy forbids that capability. Reads keep working, which is the part
that makes it a control rather than an off switch.

    python -m warden.live_demo            set it up
    python -m warden.live_demo --undo     put everything back
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .install import (
    InstallError,
    add,
    default_config_path,
    load_config,
    load_sidecar,
    unprotect,
    write_config,
)

WARDEN_HOME = Path(__file__).resolve().parent.parent
POLICY = WARDEN_HOME / "policy.yaml"
SERVER_NAME = "files2"
LINE = "-" * 74

COMMENTED = "  # - tool.destructive"
ENABLED = "  - tool.destructive"


def workspace() -> Path:
    return Path.home() / "Desktop" / "warden-test2"


def make_workspace() -> Path:
    folder = workspace()
    folder.mkdir(parents=True, exist_ok=True)
    note = folder / "note.txt"
    if not note.exists():
        note.write_text("hello from the protected folder\n", encoding="utf-8")
    return folder


def set_destructive_rule(enabled: bool) -> str:
    """
    Turn the tool.destructive denial on or off in policy.yaml.

    Edits the single line rather than rewriting the file, so every comment the
    user may have added survives.
    """
    text = POLICY.read_text(encoding="utf-8")

    if enabled:
        if ENABLED in text and COMMENTED not in text:
            return "already on"
        if COMMENTED not in text:
            return "could not find the rule to turn on"
        text = text.replace(COMMENTED, ENABLED)
    else:
        if COMMENTED in text:
            return "already off"
        if ENABLED not in text:
            return "could not find the rule to turn off"
        text = text.replace(ENABLED, COMMENTED)

    POLICY.write_text(text, encoding="utf-8")
    return "on" if enabled else "off"


def forget_server(name: str, config_path: Path) -> None:
    """Remove a server entry entirely, restoring the original first if we wrapped it."""
    if name in load_sidecar():
        try:
            unprotect(name, config_path, out=lambda *a, **k: None)
        except InstallError:
            pass

    config = load_config(config_path)
    if name in config["mcpServers"]:
        del config["mcpServers"][name]
        write_config(config_path, config)


def setup() -> None:
    config_path = default_config_path()
    if not config_path.exists():
        raise InstallError(
            f"No Claude Desktop config at {config_path}. Run menu option 12 first."
        )

    print(f"\n{LINE}\nSETTING UP A LIVE REFUSAL\n{LINE}")

    folder = make_workspace()
    print(f"\n  1. Folder ready:\n       {folder}")

    state = set_destructive_rule(True)
    print(f"\n  2. Policy rule 'deny tool.destructive' is {state}.")
    print("     Any tool that declares itself destructive will now be refused.")

    forget_server(SERVER_NAME, config_path)
    print(f"\n  3. Protecting a fresh server named '{SERVER_NAME}'...")

    add(
        SERVER_NAME,
        ["npx", "-y", "@modelcontextprotocol/server-filesystem", str(folder)],
        config_path,
    )

    print(f"\n{LINE}\nWHAT TO DO NOW\n{LINE}")
    print("""
  1. Quit Claude Desktop from the system tray - right-click, Exit.
     Closing the window is not enough.

  2. Open it again and start a new chat.

  3. Ask it to READ note.txt using the files2 connector.
     This should work.

  4. Ask it to WRITE a new file in that folder using files2.
     This should be REFUSED by Warden.

  5. Run menu option 7 for the report. The refusal will be in the ledger
     with the reason, built from live use rather than a demo.

  To put everything back:  python -m warden.live_demo --undo
""")


def undo() -> None:
    config_path = default_config_path()
    print(f"\n{LINE}\nUNDOING\n{LINE}")
    state = set_destructive_rule(False)
    print(f"\n  Policy rule 'deny tool.destructive' is {state}.")
    forget_server(SERVER_NAME, config_path)
    print(f"  Server '{SERVER_NAME}' removed from Claude Desktop.")
    print("\n  Quit Claude Desktop from the system tray and reopen it.\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Set up a live refusal.")
    parser.add_argument("--undo", action="store_true", help="put everything back")
    args = parser.parse_args()
    try:
        undo() if args.undo else setup()
    except InstallError as exc:
        print(f"\n  {exc}\n")
        raise SystemExit(1)


if __name__ == "__main__":
    main()

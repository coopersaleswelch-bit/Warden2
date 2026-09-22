"""
Warden installer.

Puts Warden in front of MCP servers already configured in Claude Desktop, so
protecting a server is a few keypresses rather than hand-editing JSON.

What it does, in order, for each server you choose:

    1. inspects the server - launches it, lists its tools, and pins each one
       as the approved contract. This must happen BEFORE the config changes:
       an enforcing Warden with nothing pinned withholds every tool, and Claude
       Desktop would come back with none.
    2. backs up claude_desktop_config.json, timestamped, next to the original.
    3. rewrites that server's entry so Claude Desktop launches Warden, and
       Warden launches the server. The server's own environment variables and
       working directory are preserved.
    4. records the original entry, so --unprotect restores it exactly.

Nothing else in the config is touched.

Usage:
    python -m warden.install                     interactive
    python -m warden.install --list
    python -m warden.install --protect NAME
    python -m warden.install --unprotect NAME
    python -m warden.install --add NAME -- <server command> [args...]
    python -m warden.install ... --config PATH   use a different config file
    python -m warden.install ... --print-only    show the result, change nothing
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .audit import AuditLog
from .enforcer import Enforcer
from .policy import load_policy
from .proxy import contract_from_mcp_tool, resolve_executable
from .registry import ContractRegistry

WARDEN_HOME = Path(__file__).resolve().parent.parent
SIDECAR = WARDEN_HOME / "wrapped_servers.json"
DISCOVERY_TIMEOUT_S = 120
PROTOCOL_VERSION = "2025-06-18"


class InstallError(Exception):
    """A problem the user needs to see, worded for them rather than for a log."""


# ---------------------------------------------------------------------------
# Locating and reading the Claude Desktop config
# ---------------------------------------------------------------------------

def default_config_path() -> Path:
    """Where Claude Desktop keeps its MCP server config on this OS."""
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        if not appdata:
            raise InstallError("APPDATA is not set, so the Claude config cannot be found.")
        return Path(appdata) / "Claude" / "claude_desktop_config.json"
    if sys.platform == "darwin":
        return (
            Path.home() / "Library" / "Application Support" / "Claude"
            / "claude_desktop_config.json"
        )
    return Path.home() / ".config" / "Claude" / "claude_desktop_config.json"


def load_config(path: Path) -> dict:
    """
    Read the config, or start an empty one if it does not exist yet.

    An existing file that is not valid JSON is refused rather than repaired:
    rewriting it would throw away whatever the user had in it.
    """
    if not path.exists():
        return {"mcpServers": {}}
    text = path.read_text(encoding="utf-8")
    if not text.strip():
        return {"mcpServers": {}}
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise InstallError(
            f"{path} is not valid JSON (line {exc.lineno}), so Warden will not "
            f"change it. Fix or remove the file and run this again."
        ) from exc
    if not isinstance(data, dict):
        raise InstallError(f"{path} does not contain a JSON object.")
    servers = data.setdefault("mcpServers", {})
    if not isinstance(servers, dict):
        raise InstallError(f"'mcpServers' in {path} is not an object.")
    return data


def write_config(path: Path, data: dict) -> Path | None:
    """
    Back up the current file, then write the new one atomically.

    The write goes to a temp file in the same directory and is then moved into
    place, so a crash mid-write can never leave a half-written config that
    stops Claude Desktop from starting.

    Returns the backup path, or None if there was nothing to back up.
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    backup: Path | None = None
    if path.exists():
        stamp = time.strftime("%Y%m%d-%H%M%S")
        backup = path.with_name(f"{path.name}.warden-backup-{stamp}")
        backup.write_bytes(path.read_bytes())

    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".warden-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
            handle.write("\n")
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise

    return backup


# ---------------------------------------------------------------------------
# Wrapping and unwrapping an entry
# ---------------------------------------------------------------------------

def is_protected(entry: dict) -> bool:
    return "warden.proxy" in (entry.get("args") or [])


def is_stdio(entry: dict) -> bool:
    """Warden sits on stdio. A remote server configured by URL cannot be wrapped."""
    return bool(entry.get("command"))


def server_argv(entry: dict) -> list[str]:
    return [entry["command"], *[str(a) for a in (entry.get("args") or [])]]


def wrap_entry(name: str, entry: dict, home: Path = WARDEN_HOME) -> dict:
    """
    Build the entry that makes Claude Desktop launch Warden in front of a server.

    Every path is absolute. Claude Desktop does not start servers from any
    particular folder, so a relative path to the policy or the databases would
    resolve somewhere unpredictable.
    """
    if not is_stdio(entry):
        raise InstallError(
            f"'{name}' is a remote server (no command). Warden protects local "
            f"stdio servers only."
        )
    if is_protected(entry):
        raise InstallError(f"'{name}' is already protected by Warden.")

    wrapped = copy.deepcopy(entry)
    wrapped["command"] = sys.executable
    wrapped["args"] = [
        "-m", "warden.proxy",
        "--name", name,
        "--policy", str(home / "policy.yaml"),
        "--registry-db", str(home / "warden_registry.db"),
        "--audit-db", str(home / "warden_audit.db"),
        "--",
        *server_argv(entry),
    ]

    # Warden must be importable wherever Claude Desktop launches it from, and
    # the server's own environment - API keys, config - must survive intact.
    env = dict(wrapped.get("env") or {})
    existing = env.get("PYTHONPATH")
    env["PYTHONPATH"] = (
        f"{home}{os.pathsep}{existing}" if existing else str(home)
    )
    wrapped["env"] = env
    return wrapped


def load_sidecar(path: Path = SIDECAR) -> dict:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except json.JSONDecodeError:
        return {}


def save_sidecar(data: dict, path: Path = SIDECAR) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Discovery: inspect the server and pin what it offers
# ---------------------------------------------------------------------------

@dataclass
class Discovery:
    server_info: dict
    tools: list[dict]


def discover(entry: dict, timeout: float = DISCOVERY_TIMEOUT_S) -> Discovery:
    """
    Launch the server exactly as Claude Desktop would, ask for its tools, stop it.

    Uses the entry's own environment and working directory, so a server that
    needs an API key to start gets it here too.
    """
    argv = resolve_executable(server_argv(entry))
    env = {**os.environ, **{k: str(v) for k, v in (entry.get("env") or {}).items()}}
    cwd = entry.get("cwd") or None

    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                    "clientInfo": {"name": "warden-install", "version": "2.0"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    ]
    payload = "".join(json.dumps(m) + "\n" for m in messages)

    try:
        result = subprocess.run(
            argv, input=payload, capture_output=True, env=env, cwd=cwd,
            encoding="utf-8", errors="replace", timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise InstallError(
            f"Could not start the server: '{argv[0]}' was not found. Is it installed?"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise InstallError(
            f"The server did not answer within {int(timeout)} seconds."
        ) from exc

    replies: dict[Any, dict] = {}
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "id" in msg:
            replies[msg["id"]] = msg

    if 2 not in replies or "result" not in replies[2]:
        detail = (result.stderr or "").strip().splitlines()[-3:]
        raise InstallError(
            "The server started but did not return a tool list."
            + (f"\n  It said: {' | '.join(detail)}" if detail else "")
        )

    info = (replies.get(1, {}).get("result") or {}).get("serverInfo") or {}
    tools = replies[2]["result"].get("tools") or []
    return Discovery(server_info=info, tools=tools)


def pin_tools(name: str, found: Discovery, home: Path = WARDEN_HOME) -> list:
    """Record every discovered tool as its approved contract."""
    enforcer = Enforcer(
        ContractRegistry(home / "warden_registry.db"),
        load_policy(home / "policy.yaml"),
        AuditLog(home / "warden_audit.db"),
        session="install",
    )
    try:
        enforcer.note_server_version(name, found.server_info.get("version"))
        contracts = []
        for tool in found.tools:
            contract = contract_from_mcp_tool(name, tool)
            enforcer.approve(contract, reason="approved at install")
            contracts.append(contract)
        return contracts
    finally:
        enforcer.close()


def describe_access(contract) -> str:
    scopes = set(contract.declared_scopes)
    if "tool.destructive" in scopes:
        return "can modify and destroy"
    if "tool.write" in scopes:
        return "can modify"
    return "read only"


# ---------------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------------

def _inspect_and_wrap(
    name: str,
    entry: dict,
    *,
    print_only: bool,
    home: Path,
    out,
) -> dict | None:
    """
    The part protect and add share: inspect the server, pin its tools, and
    return the wrapped entry. Returns None in print-only mode, having shown
    what would be written.
    """
    wrapped = wrap_entry(name, entry, home)

    out(f"\n  Inspecting '{name}'...")
    found = discover(entry)
    if not found.tools:
        raise InstallError(
            f"'{name}' reported no tools, so there is nothing to protect. "
            f"The config has not been changed."
        )

    if print_only:
        out(f"  Found {len(found.tools)} tools. Nothing written (--print-only).\n")
        out(json.dumps({"mcpServers": {name: wrapped}}, indent=2))
        return None

    contracts = pin_tools(name, found, home)
    out(f"  Pinned {len(contracts)} tools as approved:\n")
    for c in contracts:
        out(f"    {c.tool:<28} {describe_access(c)}")
    return wrapped


def _commit(
    name: str,
    original: dict,
    wrapped: dict,
    config: dict,
    config_path: Path,
    *,
    sidecar: Path,
    out,
) -> None:
    config["mcpServers"][name] = wrapped
    backup = write_config(config_path, config)

    record = load_sidecar(sidecar)
    record[name] = original
    save_sidecar(record, sidecar)

    out(f"\n  '{name}' is now protected by Warden.")
    if backup:
        out(f"  Your previous config was saved as:\n    {backup}")


def protect(
    name: str,
    config_path: Path,
    *,
    print_only: bool = False,
    home: Path = WARDEN_HOME,
    sidecar: Path = SIDECAR,
    out=print,
) -> None:
    """Put Warden in front of a server that is already configured."""
    config = load_config(config_path)
    if name not in config["mcpServers"]:
        raise InstallError(f"There is no server called '{name}' in {config_path}.")

    original = config["mcpServers"][name]
    wrapped = _inspect_and_wrap(name, original, print_only=print_only, home=home, out=out)
    if wrapped is not None:
        _commit(name, original, wrapped, config, config_path, sidecar=sidecar, out=out)


def add(
    name: str,
    argv: list[str],
    config_path: Path,
    *,
    print_only: bool = False,
    home: Path = WARDEN_HOME,
    sidecar: Path = SIDECAR,
    out=print,
) -> None:
    """Add a brand-new server that is protected from the start."""
    if not argv:
        raise InstallError("Give the server command after --.")
    config = load_config(config_path)
    if name in config["mcpServers"]:
        raise InstallError(f"A server called '{name}' already exists. Pick another name.")

    original = {"command": argv[0], "args": argv[1:]}
    wrapped = _inspect_and_wrap(name, original, print_only=print_only, home=home, out=out)
    if wrapped is not None:
        _commit(name, original, wrapped, config, config_path, sidecar=sidecar, out=out)


def unprotect(
    name: str,
    config_path: Path,
    *,
    sidecar: Path = SIDECAR,
    out=print,
) -> None:
    """Restore a server's original entry exactly as it was before Warden."""
    record = load_sidecar(sidecar)
    if name not in record:
        raise InstallError(
            f"Warden has no record of protecting '{name}', so it cannot restore it."
        )
    config = load_config(config_path)
    config["mcpServers"][name] = record.pop(name)
    backup = write_config(config_path, config)
    save_sidecar(record, sidecar)
    out(f"  '{name}' restored to its original setup. Warden no longer sits in front of it.")
    if backup:
        out(f"  Previous config saved as:\n    {backup}")


def list_servers(config_path: Path, out=print) -> list[str]:
    config = load_config(config_path)
    names = list(config["mcpServers"])
    if not names:
        out("  No MCP servers are configured in Claude Desktop yet.")
        return names
    for i, name in enumerate(names, 1):
        entry = config["mcpServers"][name]
        if is_protected(entry):
            status = "protected by Warden"
        elif not is_stdio(entry):
            status = "remote server - cannot be wrapped"
        else:
            status = "NOT protected"
        out(f"    {i}   {name:<24} {status}")
    return names


# ---------------------------------------------------------------------------
# Interactive
# ---------------------------------------------------------------------------

def interactive(config_path: Path) -> None:
    print("\n  Claude Desktop config:")
    print(f"    {config_path}")
    if not config_path.exists():
        print("\n  That file does not exist yet. Open Claude Desktop, go to")
        print("  Settings > Developer > Edit Config once, then run this again.")
        return

    print("\n  Your MCP servers:\n")
    names = list_servers(config_path)
    if not names:
        return

    print()
    choice = input("  Number of the server to protect (Enter to cancel): ").strip()
    if not choice:
        print("  Nothing changed.")
        return
    if not choice.isdigit() or not 1 <= int(choice) <= len(names):
        print("  That is not one of the numbers above. Nothing changed.")
        return

    protect(names[int(choice) - 1], config_path)
    print("\n  Last step: fully quit Claude Desktop (right-click its icon in the")
    print("  system tray and choose Quit - closing the window is not enough),")
    print("  then open it again.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Put Warden in front of MCP servers.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--list", action="store_true", help="list configured servers")
    group.add_argument("--protect", metavar="NAME", help="protect an existing server")
    group.add_argument("--unprotect", metavar="NAME", help="restore a server's original setup")
    group.add_argument("--add", metavar="NAME", help="add a new protected server (command after --)")
    parser.add_argument("--config", type=Path, default=None, help="config file to edit")
    parser.add_argument("--print-only", action="store_true", help="show the result, change nothing")
    parser.add_argument("server_argv", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    try:
        config_path = args.config or default_config_path()
        argv = [a for a in args.server_argv if a != "--"] if args.server_argv else []

        if args.list:
            print(f"\n  {config_path}\n")
            list_servers(config_path)
        elif args.protect:
            protect(args.protect, config_path, print_only=args.print_only)
        elif args.unprotect:
            unprotect(args.unprotect, config_path)
        elif args.add:
            add(args.add, argv, config_path, print_only=args.print_only)
        else:
            interactive(config_path)
    except InstallError as exc:
        print(f"\n  {exc}\n")
        raise SystemExit(1)
    except KeyboardInterrupt:
        print("\n  Cancelled. Nothing changed.")
        raise SystemExit(1)


if __name__ == "__main__":
    main()

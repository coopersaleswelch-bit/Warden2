"""
Warden MCP proxy.

This is the piece that makes Warden a product instead of a library.

It launches a real MCP server as a child process and sits between it and the
client, speaking the same JSON-RPC on stdin/stdout. The client thinks it is
talking to the server. The server thinks it is talking to the client. Neither
needs to know Warden is there.

    MCP client  ⇄  warden.proxy  ⇄  real MCP server

Two interception points:

    tools/list response  ->  build a contract for every tool, then either pin it
                             (discovery mode) or verify it against what was
                             approved. A drifted tool is quarantined the moment
                             it is advertised, before the client ever sees it.

    tools/call request   ->  run the full enforcement check. A denied call is
                             never forwarded to the server. The client receives
                             a protocol-correct error explaining which rule
                             stopped it.

Usage:
    python -m warden.proxy --server "python mock_server/notes_server.py"
    python -m warden.proxy --discover --server "python path/to/real_server.py"
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import threading
from typing import Any

from .audit import AuditLog
from .contracts import ToolContract
from .enforcer import Enforcer
from .policy import load_policy
from .registry import ContractRegistry


def log(msg: str) -> None:
    """Warden's own logging goes to stderr, never into the protocol stream."""
    print(f"[warden] {msg}", file=sys.stderr, flush=True)


def split_command(command: str) -> list[str]:
    """
    Split a server command given as ONE string. Kept for backward compatibility.

    Prefer passing the command as separate arguments after "--" instead. On
    Windows, POSIX shell rules treat every backslash in a path as an escape
    character, so C:\\Users\\Name becomes C:UsersName. posix=False keeps the
    backslashes but leaves the quote characters in place, so they are stripped.
    """
    if os.name == "nt":
        return [part.strip('"') for part in shlex.split(command, posix=False)]
    return shlex.split(command)


def resolve_executable(argv: list[str]) -> list[str]:
    """
    Turn the program name into a path the OS can actually launch.

    On Windows, npx, npm and many Node tools are really npx.cmd and friends.
    subprocess cannot find those by bare name the way a terminal can, so the
    name is resolved through PATH and PATHEXT first. Anything not found is left
    alone so the resulting error names what the user actually typed.
    """
    if not argv:
        raise ValueError("no server command given")
    found = shutil.which(argv[0])
    return [found or argv[0], *argv[1:]]


def default_server_name(argv: list[str]) -> str:
    """A readable registry name when --name is not given."""
    for part in reversed(argv):
        base = os.path.basename(part.replace("\\", "/").rstrip("/"))
        base = base.split("@")[0] if base.startswith("@") is False else base
        if "server" in base.lower() or base.endswith((".py", ".js")):
            return os.path.splitext(base)[0].replace("server-", "") or "mcp-server"
    return os.path.splitext(os.path.basename(argv[0]))[0] or "mcp-server"


def contract_from_mcp_tool(server_name: str, tool: dict) -> ToolContract:
    """
    Translate one entry of an MCP tools/list result into a pinnable contract.

    Real MCP tools do not declare "scopes". They declare behaviour hints, and
    those hints are the closest thing the protocol has to a permission model:

        readOnlyHint: false   the tool can modify state
        destructiveHint: true the tool can destroy or overwrite
        openWorldHint: true   the tool can reach outside the local system

    Warden derives scopes from those so its permission rules work against
    servers nobody wrote for it. A custom "scopes" annotation is still honoured
    for servers that publish one, but nothing depends on it.
    """
    annotations = tool.get("annotations") or {}

    scopes: set[str] = set()

    custom = annotations.get("scopes") or []
    if isinstance(custom, str):
        custom = [custom]
    scopes.update(custom)

    # readOnlyHint is the important one, and its absence is not a promise.
    # A tool that does not claim to be read-only is treated as able to write.
    if annotations.get("readOnlyHint") is True:
        scopes.add("tool.read")
    else:
        scopes.add("tool.write")

    if annotations.get("destructiveHint") is True:
        scopes.add("tool.destructive")
    if annotations.get("openWorldHint") is True:
        scopes.add("tool.openworld")

    return ToolContract(
        server=server_name,
        tool=tool.get("name", "<unnamed>"),
        description=tool.get("description", ""),
        input_schema=tool.get("inputSchema") or tool.get("input_schema") or {},
        declared_scopes=tuple(sorted(scopes)),
        title=tool.get("title", "") or "",
        annotations={k: v for k, v in annotations.items() if k != "scopes"},
        output_schema=tool.get("outputSchema") or tool.get("output_schema") or {},
    )


def mcp_tool_from_contract(contract: ToolContract) -> dict:
    """
    Rebuild the tool definition a client should see from an APPROVED contract.

    Used when policy serves the last approved version of a quarantined tool
    instead of hiding it. The client keeps a stable view of the server, sees
    only text a human signed off on, and any call is still refused by the
    quarantine check.
    """
    annotations = dict(contract.annotations)
    custom = [s for s in contract.declared_scopes if not s.startswith("tool.")]
    if custom:
        annotations["scopes"] = custom

    tool: dict = {
        "name": contract.tool,
        "description": contract.description,
        "inputSchema": contract.input_schema,
    }
    if contract.title:
        tool["title"] = contract.title
    if annotations:
        tool["annotations"] = annotations
    if contract.output_schema:
        tool["outputSchema"] = contract.output_schema
    return tool


class WardenProxy:
    def __init__(
        self,
        server_command: str | list[str],
        server_name: str,
        enforcer: Enforcer,
        *,
        discover: bool = False,
    ):
        # A list is passed through untouched - that is the safe form, and it is
        # what Claude Desktop's JSON config delivers. A single string is split
        # for backward compatibility only.
        if isinstance(server_command, str):
            self.server_argv = split_command(server_command)
        else:
            self.server_argv = list(server_command)
        self.server_command = " ".join(self.server_argv)
        self.server_name = server_name
        self.enforcer = enforcer
        self.discover = discover

        self.child: subprocess.Popen | None = None
        # request id -> method, so we know what a response is a response to
        self.pending: dict[Any, str] = {}
        self.lock = threading.Lock()
        self.stats = {
            "forwarded": 0, "blocked": 0, "tools_seen": 0,
            "quarantined": 0, "upgrades": 0, "withheld": 0,
        }

    # ---------- plumbing ----------

    def start(self) -> None:
        try:
            argv = resolve_executable(self.server_argv)
            self.child = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=None,  # let the server's own stderr pass through
                # Explicit UTF-8: the Windows default is a legacy code page, and
                # a tool description with one accented character would otherwise
                # be garbled or crash the reader thread.
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
        except (FileNotFoundError, PermissionError, ValueError) as exc:
            log(f"could not launch server {self.server_argv!r}: {exc}")
            raise SystemExit(2) from exc
        log(f"launched server: {self.server_command}")
        if self.discover:
            log("DISCOVERY MODE — contracts will be pinned, not enforced")

    def to_server(self, message: dict) -> None:
        assert self.child and self.child.stdin
        self.child.stdin.write(json.dumps(message) + "\n")
        self.child.stdin.flush()

    def to_client(self, message: dict) -> None:
        sys.stdout.write(json.dumps(message) + "\n")
        sys.stdout.flush()

    # ---------- interception: client -> server ----------

    def handle_client_message(self, message: dict) -> None:
        method = message.get("method")
        msg_id = message.get("id")

        if method and msg_id is not None:
            with self.lock:
                self.pending[msg_id] = method

        if method == "tools/call":
            self.handle_tool_call(message)
            return

        self.to_server(message)

    def handle_tool_call(self, message: dict) -> None:
        params = message.get("params") or {}
        tool_name = params.get("name", "<unnamed>")
        args = params.get("arguments") or {}

        contract = self.enforcer.registry.get_contract(self.server_name, tool_name)

        if contract is None:
            # Never advertised in a tools/list we saw. Build a bare contract so
            # the enforcer can apply its unknown-tool rule rather than crash.
            contract = ToolContract(
                server=self.server_name, tool=tool_name, description="", input_schema={}
            )

        decision = self.enforcer.check(contract, args, agent="mcp-client")

        if decision.allowed:
            self.stats["forwarded"] += 1
            self.to_server(message)
            return

        # Denied. The call never reaches the server.
        self.stats["blocked"] += 1
        log(f"BLOCKED {tool_name}: {decision.reason}")
        with self.lock:
            self.pending.pop(message.get("id"), None)

        self.to_client(
            {
                "jsonrpc": "2.0",
                "id": message.get("id"),
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": (
                                f"Blocked by Warden [{decision.code}]: {decision.reason}"
                            ),
                        }
                    ],
                    "isError": True,
                },
            }
        )

    # ---------- interception: server -> client ----------

    def handle_server_message(self, message: dict) -> None:
        msg_id = message.get("id")
        with self.lock:
            method = self.pending.pop(msg_id, None)

        if method == "initialize" and "result" in message:
            info = message["result"].get("serverInfo") or {}
            version = info.get("version")
            state = self.enforcer.note_server_version(self.server_name, version)
            log(f"server reports version {version} ({state})")

        if method == "tools/list" and "result" in message:
            original = message["result"].get("tools") or []
            message["result"]["tools"] = self.inspect_tool_list(original)

        self.to_client(message)

    def inspect_tool_list(self, tools: list[dict]) -> list[dict]:
        """
        Judge every advertised tool, then decide what the client may see.

        Returns the list to forward. This is the part that matters most:

        Tool poisoning does not need the poisoned tool to be called. Its payload
        is the description, and a description is read into the model's context
        the moment the tool list arrives. A poisoned description can instruct
        the model to use a *different*, approved tool to do the damage - so
        blocking calls to the poisoned tool alone blocks the wrong thing.

        So a quarantined or unapproved tool is withheld from the client. Its
        description never reaches the model at all.
        """
        self.stats["tools_seen"] = len(tools)
        view = self.enforcer.policy.default("quarantined_tool_view")
        visible: list[dict] = []

        for tool in tools:
            contract = contract_from_mcp_tool(self.server_name, tool)
            registry = self.enforcer.registry

            if not registry.is_known(self.server_name, contract.tool):
                if self.discover:
                    self.enforcer.approve(contract, reason="discovery mode auto-pin")
                    log(f"pinned {contract.tool} ({contract.short_fingerprint()})")
                    visible.append(tool)
                else:
                    self.stats["withheld"] += 1
                    log(f"WITHHELD unapproved tool {contract.tool} from the client")
                continue

            decision = self.enforcer.verify_advertised(contract)
            if decision is not None:
                if decision.code in ("VERSION_UPGRADE_ACCEPTED", "DRIFT_ACCEPTED"):
                    self.stats["upgrades"] += 1
                    log(f"ACCEPTED change on {contract.tool}: {decision.reason}")
                elif not decision.allowed:
                    self.stats["quarantined"] += 1
                    log(f"{decision.code} on {contract.tool}: {decision.reason}")
                else:
                    log(f"drift flagged on {contract.tool}: {decision.reason}")

            # Checked after verification, not instead of it: a tool quarantined
            # in an earlier session stays withheld even if this session's copy
            # happens to look clean.
            if registry.is_quarantined(self.server_name, contract.tool):
                self.stats["withheld"] += 1
                if view == "pinned":
                    pinned = registry.get_contract(self.server_name, contract.tool)
                    visible.append(mcp_tool_from_contract(pinned))
                    log(f"serving APPROVED version of quarantined {contract.tool}")
                else:
                    log(f"WITHHELD quarantined {contract.tool} from the client")
                continue

            visible.append(tool)

        return visible

    # ---------- run loops ----------

    def pump_server_output(self) -> None:
        assert self.child and self.child.stdout
        while True:
            raw = self.child.stdout.readline()
            if not raw:
                break
            line = raw.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                sys.stdout.write(line + "\n")
                sys.stdout.flush()
                continue
            self.handle_server_message(message)

    @staticmethod
    def _configure_stdio() -> None:
        """
        JSON-RPC over stdio is newline-delimited UTF-8. On Windows, Python's
        text-mode stdout translates each newline into a carriage-return pair and
        encodes with the console code page. Pin both, so the client receives
        exactly what the protocol specifies.

        A stream that cannot be reconfigured (already replaced, or not a text
        stream) is left alone - but that is logged, never silently skipped,
        because a silent failure here corrupts every message on Windows.
        """
        settings = (
            (sys.stdin, {"encoding": "utf-8", "errors": "replace"}),
            (sys.stdout, {"encoding": "utf-8", "newline": "\n"}),
        )
        for stream, kwargs in settings:
            reconfigure = getattr(stream, "reconfigure", None)
            if reconfigure is None:
                log(f"stdio stream {stream!r} cannot be reconfigured; left as-is")
                continue
            reconfigure(**kwargs)

    def run(self) -> None:
        self._configure_stdio()
        self.start()
        reader = threading.Thread(target=self.pump_server_output, daemon=True)
        reader.start()

        try:
            while True:
                raw = sys.stdin.readline()
                if not raw:
                    break
                line = raw.strip()
                if not line:
                    continue
                try:
                    message = json.loads(line)
                except json.JSONDecodeError:
                    continue
                self.handle_client_message(message)
        except KeyboardInterrupt:
            pass
        finally:
            self.shutdown()

    def shutdown(self) -> None:
        if self.child:
            try:
                if self.child.stdin:
                    self.child.stdin.close()
                self.child.wait(timeout=3)
            except Exception:
                self.child.kill()
        log(
            f"session ended — forwarded={self.stats['forwarded']} "
            f"blocked={self.stats['blocked']} "
            f"quarantined={self.stats['quarantined']} "
            f"withheld={self.stats['withheld']} "
            f"upgrades_accepted={self.stats['upgrades']}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Warden MCP proxy",
        usage=(
            "python -m warden.proxy [options] -- <server command> [server args...]"
        ),
    )
    parser.add_argument(
        "--server",
        default=None,
        help="(legacy) server command as a single string; prefer -- instead",
    )
    parser.add_argument("--name", default=None, help="server name for the registry")
    parser.add_argument(
        "--discover",
        action="store_true",
        help="pin whatever the server advertises instead of enforcing (first run only)",
    )
    parser.add_argument("--policy", default="policy.yaml")
    parser.add_argument("--registry-db", default="warden_registry.db")
    parser.add_argument("--audit-db", default="warden_audit.db")
    parser.add_argument(
        "server_argv",
        nargs=argparse.REMAINDER,
        help="the MCP server command and its arguments, after --",
    )
    args = parser.parse_args()

    argv = list(args.server_argv)
    if argv and argv[0] == "--":
        argv = argv[1:]
    if not argv and args.server:
        argv = split_command(args.server)
    if not argv:
        parser.error("give the server command after --, e.g.  -- npx -y some-server")

    server_name = args.name or default_server_name(argv)

    enforcer = Enforcer(
        ContractRegistry(args.registry_db),
        load_policy(args.policy),
        AuditLog(args.audit_db),
        session="proxy",
    )

    WardenProxy(argv, server_name, enforcer, discover=args.discover).run()


if __name__ == "__main__":
    main()

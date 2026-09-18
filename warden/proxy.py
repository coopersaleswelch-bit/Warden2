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
import shlex
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


class WardenProxy:
    def __init__(
        self,
        server_command: str,
        server_name: str,
        enforcer: Enforcer,
        *,
        discover: bool = False,
    ):
        self.server_command = server_command
        self.server_name = server_name
        self.enforcer = enforcer
        self.discover = discover

        self.child: subprocess.Popen | None = None
        # request id -> method, so we know what a response is a response to
        self.pending: dict[Any, str] = {}
        self.lock = threading.Lock()
        self.stats = {
            "forwarded": 0, "blocked": 0, "tools_seen": 0,
            "quarantined": 0, "upgrades": 0,
        }

    # ---------- plumbing ----------

    def start(self) -> None:
        self.child = subprocess.Popen(
            shlex.split(self.server_command),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,  # let the server's own stderr pass through
            text=True,
            bufsize=1,
        )
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
            self.inspect_tool_list(message["result"].get("tools") or [])

        self.to_client(message)

    def inspect_tool_list(self, tools: list[dict]) -> None:
        """
        The moment a drifting server gives itself away.

        A malicious server has to advertise its new capability before it can use
        it, so this is where a rug-pull becomes visible — before the client has
        made a single call against the mutated tool.
        """
        self.stats["tools_seen"] = len(tools)

        for tool in tools:
            contract = contract_from_mcp_tool(self.server_name, tool)

            if not self.enforcer.registry.is_known(self.server_name, contract.tool):
                if self.discover:
                    self.enforcer.approve(contract, reason="discovery mode auto-pin")
                    log(f"pinned {contract.tool} ({contract.short_fingerprint()})")
                else:
                    log(f"UNAPPROVED tool advertised: {contract.tool}")
                continue

            decision = self.enforcer.verify_advertised(contract)
            if decision is None:
                continue

            if decision.code == "VERSION_UPGRADE_ACCEPTED":
                self.stats["upgrades"] += 1
                log(f"UPGRADE ACCEPTED on {contract.tool}: {decision.reason}")
            elif not decision.allowed:
                self.stats["quarantined"] += 1
                log(f"{decision.code} on {contract.tool}: {decision.reason}")
            else:
                log(f"drift flagged on {contract.tool}: {decision.reason}")

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

    def run(self) -> None:
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
            f"upgrades_accepted={self.stats['upgrades']}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Warden MCP proxy")
    parser.add_argument("--server", required=True, help="command to launch the MCP server")
    parser.add_argument("--name", default=None, help="server name for the registry")
    parser.add_argument(
        "--discover",
        action="store_true",
        help="pin whatever the server advertises instead of enforcing (first run only)",
    )
    parser.add_argument("--policy", default="policy.yaml")
    parser.add_argument("--registry-db", default="warden_registry.db")
    parser.add_argument("--audit-db", default="warden_audit.db")
    args = parser.parse_args()

    server_name = args.name or shlex.split(args.server)[-1].split("/")[-1].replace(
        ".py", ""
    )

    enforcer = Enforcer(
        ContractRegistry(args.registry_db),
        load_policy(args.policy),
        AuditLog(args.audit_db),
        session="proxy",
    )

    WardenProxy(args.server, server_name, enforcer, discover=args.discover).run()


if __name__ == "__main__":
    main()

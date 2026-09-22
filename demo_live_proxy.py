"""
Warden 2.0 — Day 2 live demo.

Nothing here is simulated. This script is a real MCP client. It launches the
Warden proxy as a subprocess, which launches a real MCP server as a subprocess,
and every message below travels as JSON-RPC over actual pipes:

    this script  <->  warden.proxy  <->  mock_server/notes_server.py

The server is hostile in the Deadbugz way: honest for three tool calls, then it
swaps search_notes for a version with a hidden instruction, an extra `command`
field, and a claimed shell.exec scope.

Run:  python demo_live_proxy.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time

REG_DB = "warden_registry.db"
AUD_DB = "warden_audit.db"
SERVER_CMD = f"{sys.executable} mock_server/notes_server.py"

LINE = "-" * 74


def banner(text: str) -> None:
    print(f"\n{LINE}\n{text}\n{LINE}")


class ProxyClient:
    """A minimal MCP client that talks to the Warden proxy over stdin/stdout."""

    def __init__(self, discover: bool = False):
        cmd = [
            sys.executable, "-m", "warden.proxy",
            "--server", SERVER_CMD,
            "--name", "notes-mcp",
            "--registry-db", REG_DB,
            "--audit-db", AUD_DB,
        ]
        if discover:
            cmd.append("--discover")

        self.proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=open("warden_proxy.log", "a"),
            text=True,
            bufsize=1,
        )
        self._id = 0

    def request(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        message = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            message["params"] = params
        self.proc.stdin.write(json.dumps(message) + "\n")
        self.proc.stdin.flush()

        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError("proxy closed the connection")
        return json.loads(line)

    def close(self) -> None:
        try:
            self.proc.stdin.close()
            self.proc.wait(timeout=3)
        except Exception:
            self.proc.kill()


def call_tool(client: ProxyClient, name: str, args: dict) -> None:
    response = client.request("tools/call", {"name": name, "arguments": args})
    result = response.get("result", {})
    blocked = result.get("isError", False)
    text = (result.get("content") or [{}])[0].get("text", "")
    tag = "BLOCKED" if blocked else "ran    "
    print(f"  [{tag}] {name}({args})")
    print(f"           {text}")


def show_tools(response: dict) -> None:
    for tool in response["result"]["tools"]:
        scopes = (tool.get("annotations") or {}).get("scopes", [])
        print(f"    {tool['name']:<16} scopes={scopes}")
        print(f"      {tool['description'][:90]}")


def main() -> None:
    for path in (REG_DB, AUD_DB):
        if os.path.exists(path):
            os.remove(path)

    # ------------------------------------------------------------------
    banner("PHASE 1 — Discovery run (what a team does on install day)")
    print("  Warden watches, pins what the server advertises, blocks nothing.\n")

    client = ProxyClient(discover=True)
    client.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}})
    tools = client.request("tools/list")
    show_tools(tools)
    client.close()
    print("\n  Contracts pinned. This is the approved shape of the server.")

    # ------------------------------------------------------------------
    banner("PHASE 2 — Enforcement run. Server starts clean.")
    time.sleep(0.2)

    client = ProxyClient(discover=False)
    client.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}})
    tools = client.request("tools/list")
    show_tools(tools)
    print("\n  Fingerprints match what was pinned. Nothing flagged.")

    banner("PHASE 3 — Three real tool calls, forwarded to the server")
    call_tool(client, "list_notes", {"folder": "work"})
    call_tool(client, "search_notes", {"query": "quarterly plan"})
    call_tool(client, "search_notes", {"query": "meeting notes"})

    banner("PHASE 4 — The server mutates and re-advertises")
    print("  Three calls was the trigger. The client asks for the tool list again,")
    print("  the way any client does when a session refreshes.\n")
    tools = client.request("tools/list")
    show_tools(tools)
    print("\n  Warden compared every fingerprint against the pinned contracts.")
    print("  search_notes no longer matches, so it is quarantined - and notice")
    print("  it is missing from the list above. The client never received the")
    print("  poisoned description, so the model never read the instruction in it.")

    banner("PHASE 5 — The client tries to use the mutated tool")
    print("  The call never reaches the server.\n")
    call_tool(client, "search_notes", {"query": "credentials", "command": "cat .env"})

    banner("PHASE 6 — The rest of the server still works")
    call_tool(client, "list_notes", {"folder": "work"})

    client.close()

    # ------------------------------------------------------------------
    banner("WHAT WARDEN RECORDED")
    from warden.audit import AuditLog
    from warden.registry import ContractRegistry

    audit = AuditLog(AUD_DB)
    registry = ContractRegistry(REG_DB)

    counts = audit.counts()
    print(f"  decisions: {counts['total']}   "
          f"allowed: {counts['allowed']}   denied: {counts['denied']}\n")
    for row in audit.by_code():
        print(f"    {row['code']:<28} {row['n']}")

    q = registry.quarantined()
    print(f"\n  quarantined tools: {len(q)}")
    for row in q:
        print(f"    {row['server']}::{row['tool']}")
        print(f"      {row['status_reason']}")

    audit.close()
    registry.close()
    print(f"\n  Run 'python summary.py' any time to see this again.\n")


if __name__ == "__main__":
    main()

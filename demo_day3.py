"""
Warden 2.0 - Day 3 demo.

Day 2 caught the attack. It also would have caught every routine software
update, which is the same thing as being switched off.

This demo runs four real sessions against a real MCP server over real pipes and
shows the difference between "something changed" and "something gained power".

    1. approve the server at v1.0.16
    2. the vendor ships v1.1.0 with genuinely benign changes   -> accepted, no human
    3. the server mutates while still calling itself v1.1.0    -> quarantined
    4. the server mutates AND bumps to v1.2.0                  -> still quarantined

Run:  python demo_day3.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

REG_DB = "warden_registry.db"
AUD_DB = "warden_audit.db"
LINE = "-" * 74


def banner(text: str) -> None:
    print(f"\n{LINE}\n{text}\n{LINE}")


class Session:
    """A real MCP client talking to the Warden proxy over stdin/stdout."""

    def __init__(self, behaviour: str, version: str, discover: bool = False):
        server_cmd = (
            f"{sys.executable} mock_server/notes_server.py "
            f"--behaviour {behaviour} --version {version}"
        )
        cmd = [
            sys.executable, "-m", "warden.proxy",
            "--server", server_cmd,
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
        self.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}})

    def request(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        msg = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            msg["params"] = params
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError("proxy closed the connection")
        return json.loads(line)

    def tools(self) -> list[dict]:
        return self.request("tools/list")["result"]["tools"]

    def call(self, name: str, args: dict) -> bool:
        result = self.request("tools/call", {"name": name, "arguments": args}).get(
            "result", {}
        )
        blocked = result.get("isError", False)
        text = (result.get("content") or [{}])[0].get("text", "")
        print(f"    [{'BLOCKED' if blocked else 'ran    '}] {name}({args})")
        if blocked:
            print(f"             {text}")
        return not blocked

    def close(self) -> None:
        try:
            self.proc.stdin.close()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()


def show(tools: list[dict]) -> None:
    for t in tools:
        scopes = (t.get("annotations") or {}).get("scopes", [])
        fields = list((t.get("inputSchema") or {}).get("properties", {}))
        print(f"    {t['name']:<14} scopes={scopes} fields={fields}")


def verdicts_for(tool: str) -> list[tuple[str, str]]:
    from warden.audit import AuditLog

    audit = AuditLog(AUD_DB)
    rows = [r for r in audit.recent(40) if r["tool"] == tool]
    audit.close()
    return [(r["code"], r["reason"]) for r in rows]


def status_of(tool: str) -> str:
    from warden.registry import ContractRegistry

    reg = ContractRegistry(REG_DB)
    row = reg.get("notes-mcp", tool)
    reg.close()
    return row["status"] if row else "UNKNOWN"


def main() -> None:
    for path in (REG_DB, AUD_DB, "warden_proxy.log"):
        if os.path.exists(path):
            os.remove(path)

    # ------------------------------------------------------------------
    banner("1 - Security review approves notes-mcp at v1.0.16")
    s = Session("honest", "1.0.16", discover=True)
    show(s.tools())
    s.close()
    print("\n  Contracts pinned. Warden now knows what this server is.")

    # ------------------------------------------------------------------
    banner("2 - The vendor ships v1.1.0. Nothing gained.")
    print("  list_notes drops a legacy field. search_notes gives up notes.index")
    print("  and rewords its description. Both are strictly less capable.\n")

    s = Session("upgraded", "1.1.0")
    show(s.tools())
    print()
    for code, reason in verdicts_for("search_notes"):
        print(f"    {code}")
        print(f"      {reason}")
    print(f"\n  search_notes status: {status_of('search_notes')}")
    print("  Nobody was paged. Nobody approved anything. It just worked.\n")
    s.call("search_notes", {"query": "quarterly plan"})
    s.close()

    # ------------------------------------------------------------------
    banner("3 - The server mutates, still calling itself v1.1.0")
    print("  Same version string, different tools. That is a contradiction,")
    print("  and it is the signature of a rug-pull.\n")

    s = Session("hostile", "1.1.0")
    s.call("list_notes", {"folder": "work"})
    s.call("search_notes", {"query": "quarterly plan"})
    s.call("search_notes", {"query": "meeting notes"})
    print("\n  Three calls done. The server now swaps the tool and re-advertises.\n")
    show(s.tools())
    print()
    for code, reason in verdicts_for("search_notes")[:1]:
        print(f"    {code}")
        print(f"      {reason}")
    print(f"\n  search_notes status: {status_of('search_notes')}\n")
    s.call("search_notes", {"query": "credentials", "command": "cat .env"})
    print()
    s.call("list_notes", {"folder": "work"})
    s.close()

    # ------------------------------------------------------------------
    banner("4 - A human clears it, then the server tries an honest-looking bump")
    print("  This time the server DOES declare a new version, v1.2.0, and still")
    print("  ships the poisoned tool. A version bump is not a free pass.\n")

    from warden.proxy import contract_from_mcp_tool
    from warden.registry import ContractRegistry

    reg = ContractRegistry(REG_DB)
    clean_v11 = {
        "name": "search_notes",
        "description": "Search notes and return matching titles.",
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
        "annotations": {"scopes": ["notes.read"]},
    }
    reg.reapprove(
        contract_from_mcp_tool("notes-mcp", clean_v11),
        reason="human reviewed the diff and reverted to v1.1.0",
    )
    reg.close()
    print(f"  search_notes status after human review: {status_of('search_notes')}\n")

    s = Session("hostile", "1.2.0")
    s.call("list_notes", {"folder": "work"})
    s.call("search_notes", {"query": "a"})
    s.call("search_notes", {"query": "b"})
    print()
    s.tools()
    for code, reason in verdicts_for("search_notes")[:1]:
        print(f"    {code}")
        print(f"      {reason}")
    print(f"\n  search_notes status: {status_of('search_notes')}\n")
    s.call("search_notes", {"query": "credentials", "command": "cat .env"})
    s.close()

    # ------------------------------------------------------------------
    banner("WHAT THIS PROVES")
    from warden.audit import AuditLog

    audit = AuditLog(AUD_DB)
    counts = audit.counts()
    print(f"  decisions: {counts['total']}   allowed: {counts['allowed']}   "
          f"denied: {counts['denied']}\n")
    for row in audit.by_code():
        print(f"    {row['code']:<28} {row['n']}")
    audit.close()

    print("""
  A routine upgrade went through with no human involved.
  A silent swap was caught because the version did not change.
  A declared upgrade carrying an escalation was caught anyway.

  That is the difference between a control a team keeps and one they disable.
""")


if __name__ == "__main__":
    main()

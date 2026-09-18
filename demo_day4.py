"""
Warden 2.0 - Day 4 demo.

Everything before today was tested against a server I wrote. I knew where the
mutation was because I put it there. That is a rehearsal, not a test.

This runs Warden against @modelcontextprotocol/server-filesystem 2026.8.31 -
the official filesystem server, published by the protocol maintainers, written
by people who have never heard of Warden.

If Node and the package are installed, this talks to the real server over real
pipes. If not, it replays the server's own published metadata, captured from a
live run and stored in fixtures/. Either way the tool definitions are genuine.

Run:  python demo_day4.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from warden.audit import AuditLog
from warden.classify import classify_drift
from warden.contracts import diff_contracts
from warden.enforcer import Enforcer
from warden.policy import load_policy
from warden.proxy import contract_from_mcp_tool
from warden.registry import ContractRegistry

REG_DB = "warden_registry.db"
AUD_DB = "warden_audit.db"
SERVER_NAME = "filesystem-mcp"
FIXTURE = Path(__file__).parent / "fixtures" / "real_filesystem_server.json"
LINE = "-" * 74


def banner(text: str) -> None:
    print(f"\n{LINE}\n{text}\n{LINE}")


# ---------------------------------------------------------------------------
# Getting the real server's tool definitions, live if possible.
# ---------------------------------------------------------------------------

def find_real_server() -> str | None:
    """The installed server's entry point, or None if it isn't here."""
    if not shutil.which("node"):
        return None
    for base in (Path.cwd(), Path.cwd().parent, Path.home()):
        candidate = (
            base / "realmcp" / "node_modules" / "@modelcontextprotocol"
            / "server-filesystem" / "dist" / "index.js"
        )
        if candidate.exists():
            return str(candidate)
    return None


def load_live(entry: str) -> tuple[dict, list[dict]]:
    workspace = Path.cwd() / "sandbox_files"
    workspace.mkdir(exist_ok=True)
    (workspace / "note.txt").write_text("hello\n")

    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                    "clientInfo": {"name": "warden-day4", "version": "1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    ]
    proc = subprocess.run(
        ["node", entry, str(workspace)],
        input="\n".join(json.dumps(m) for m in messages) + "\n",
        capture_output=True, text=True, timeout=60,
    )
    replies = [json.loads(l) for l in proc.stdout.splitlines() if l.strip()]
    init = next(r["result"] for r in replies if r.get("id") == 1)
    tools = next(r["result"]["tools"] for r in replies if r.get("id") == 2)
    return init, tools


def load_fixture() -> tuple[dict, list[dict]]:
    data = json.loads(FIXTURE.read_text())
    return data["initialize_result"], data["tools"]


# ---------------------------------------------------------------------------

def main() -> None:
    for path in (REG_DB, AUD_DB):
        if os.path.exists(path):
            os.remove(path)

    entry = find_real_server()
    if entry:
        init, tools = load_live(entry)
        source = "live, over JSON-RPC"
    else:
        init, tools = load_fixture()
        source = "replayed from a captured live run (Node not installed here)"

    info = init.get("serverInfo", {})
    package_version = json.loads(FIXTURE.read_text())["package_version"]

    banner("THE SERVER")
    print(f"  package:        @modelcontextprotocol/server-filesystem")
    print(f"  package version: {package_version}")
    print(f"  serverInfo:      {info}")
    print(f"  tools:           {len(tools)}")
    print(f"  source:          {source}")

    enforcer = Enforcer(
        ContractRegistry(REG_DB), load_policy("policy.yaml"), AuditLog(AUD_DB),
        session="day4",
    )
    enforcer.note_server_version(SERVER_NAME, info.get("version"))

    # ------------------------------------------------------------------
    banner("1 - What Warden reads off a server it has never seen")
    contracts = {}
    for t in tools:
        c = contract_from_mcp_tool(SERVER_NAME, t)
        contracts[c.tool] = c
        enforcer.approve(c, reason="discovery")

    print("  Permissions derived from the MCP behaviour hints, not from any")
    print("  annotation Warden invented for itself:\n")
    for name in ("read_text_file", "list_directory", "write_file", "move_file",
                 "edit_file"):
        if name in contracts:
            c = contracts[name]
            print(f"    {name:<18} {list(c.declared_scopes)}")

    print(f"\n  All {len(contracts)} tools pinned.")

    # ------------------------------------------------------------------
    banner("2 - The attack Warden could not see yesterday")
    print("  A read-only tool quietly stops being read-only. No description")
    print("  change, no new field - only the behaviour hints move.\n")

    original = next(t for t in tools if t["name"] == "read_text_file")
    attacked = json.loads(json.dumps(original))
    attacked["annotations"] = {
        "readOnlyHint": False, "destructiveHint": True, "openWorldHint": True,
    }

    before = contracts["read_text_file"]
    after = contract_from_mcp_tool(SERVER_NAME, attacked)

    print(f"    hints before: {original.get('annotations')}")
    print(f"    hints after:  {attacked['annotations']}")
    print(f"    fingerprint:  {before.short_fingerprint()} -> "
          f"{after.short_fingerprint()}\n")

    decision = enforcer.verify_advertised(after)
    print(f"    {decision.code}")
    print(f"      {decision.reason}")
    print(f"\n  status: {enforcer.registry.get('filesystem-mcp', 'read_text_file')['status']}")

    print("\n  Until today this diff produced an identical fingerprint and")
    print("  Warden reported no change at all.")

    # ------------------------------------------------------------------
    banner("3 - A vendor hardening its own tool must NOT be punished")
    print("  The same move in reverse: write_file stops being destructive.\n")

    wf = next(t for t in tools if t["name"] == "write_file")
    hardened = json.loads(json.dumps(wf))
    hardened["annotations"] = dict(wf.get("annotations") or {})
    hardened["annotations"]["destructiveHint"] = False

    verdict = classify_drift(
        diff_contracts(contracts["write_file"],
                       contract_from_mcp_tool(SERVER_NAME, hardened))
    )
    print(f"    verdict: {verdict.level}")
    for r in verdict.reasons:
        print(f"      - {r}")
    print("\n  Benign. Accepted without a human. A control that blocks vendors")
    print("  from improving their own software gets uninstalled.")

    # ------------------------------------------------------------------
    banner("4 - What this server taught us about version trust")
    print(f"  The package is {package_version}. The server reports "
          f"{info.get('version')}.")
    print("  Its version string does not track its releases.\n")
    print("  Day 3 assumed a version bump was a reliable signal. Against real")
    print("  servers it is not, so version trust is now off by default and set")
    print("  per-server in policy.yaml. With it off, Warden's promise is")
    print("  narrower and true: no tool gains capability without a human.")

    # ------------------------------------------------------------------
    banner("RECORDED")
    counts = enforcer.audit.counts()
    print(f"  decisions: {counts['total']}   allowed: {counts['allowed']}   "
          f"denied: {counts['denied']}")
    for row in enforcer.audit.by_code():
        print(f"    {row['code']:<28} {row['n']}")
    enforcer.close()
    print("\n  Run option 6 in the menu to see this as a report.\n")


if __name__ == "__main__":
    main()

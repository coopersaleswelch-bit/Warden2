"""
The enforcement core, with no idea what a pipe or a socket is.

Warden's security decisions do not depend on how a message arrived. Whether a
tool list came down a subprocess pipe or an HTTP response body, the questions
are identical: was this tool approved, has its contract changed, has it gained
capability, may the client see it, may this call proceed.

Keeping that here means a second transport is a second way of moving bytes, not
a second copy of the security logic. Two copies would drift, and the one that
drifted would be the one nobody was testing.

Transports own: connections, framing, concurrency, sessions, shutdown.
This module owns: what is allowed, what is withheld, and why.
"""

from __future__ import annotations

import sys
from typing import Any, Callable

from .contracts import ToolContract
from .enforcer import Enforcer


def _default_log(msg: str) -> None:
    print(f"[warden] {msg}", file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# Translating between MCP's wire shape and Warden's contract model
# ---------------------------------------------------------------------------

def _strip_schema_dialect(value):
    """Remove every "$schema" declaration, however deeply nested."""
    if isinstance(value, dict):
        return {k: _strip_schema_dialect(v) for k, v in value.items() if k != "$schema"}
    if isinstance(value, list):
        return [_strip_schema_dialect(v) for v in value]
    return value


def sanitize_for_client(tool: dict, mode: str) -> tuple[dict, bool]:
    """
    Adjust a tool definition so the client can accept it. Returns
    (definition, changed).

    Every official MCP server currently declares its schemas as JSON Schema
    draft-07. Some clients validate against 2020-12 only and reject the tool
    outright, making the server unusable with or without Warden in the path.
    Dropping the dialect declaration lets the client fall back to its own
    default, which is what it would have used anyway.

    This is the one place Warden alters what a server said, so it stays as
    narrow as possible: only the "$schema" key is removed. The PINNED contract
    still holds the server's original definition, so drift detection compares
    the server against what the server said, not against what was forwarded.
    """
    if mode != "strip_dialect":
        return tool, False
    cleaned = _strip_schema_dialect(tool)
    return cleaned, cleaned != tool


def contract_from_mcp_tool(server_name: str, tool: dict) -> ToolContract:
    """
    Translate one entry of an MCP tools/list result into a pinnable contract.

    Real MCP tools do not declare "scopes". They declare behaviour hints, and
    those hints are the closest thing the protocol has to a permission model:

        readOnlyHint: false    the tool can modify state
        destructiveHint: true  the tool can destroy or overwrite
        openWorldHint: true    the tool can reach outside the local system

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
    only text a human signed off, and any call is still refused by quarantine.
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


# ---------------------------------------------------------------------------

class MessageGuard:
    """
    Every security decision Warden makes, independent of how bytes travel.

    A transport calls three things: note_initialize when the handshake comes
    back, inspect_tool_list when tools are advertised, and judge_tool_call
    before a call is relayed. Nothing else about a transport is Warden's
    business, and nothing here knows a transport exists.
    """

    def __init__(
        self,
        enforcer: Enforcer,
        server_name: str,
        *,
        discover: bool = False,
        log: Callable[[str], None] = _default_log,
    ):
        self.enforcer = enforcer
        self.server_name = server_name
        self.discover = discover
        self.log = log
        self.stats: dict[str, int] = {
            "forwarded": 0,
            "blocked": 0,
            "tools_seen": 0,
            "quarantined": 0,
            "upgrades": 0,
            "withheld": 0,
            "announcements": 0,
        }

    # ---------- handshake ----------

    def note_initialize(self, result: dict) -> str:
        """Record what version the server claims to be. Returns the state."""
        info = result.get("serverInfo") or {}
        version = info.get("version")
        state = self.enforcer.note_server_version(self.server_name, version)
        self.log(f"server reports version {version} ({state})")
        return state

    # ---------- what the client may see ----------

    def inspect_tool_list(self, tools: list[dict]) -> list[dict]:
        """
        Judge every advertised tool, then decide what the client may see.

        Returns the list to forward. This is the part that matters most:

        Tool poisoning does not need the poisoned tool to be called. Its payload
        is the description, and a description is read into the model's context
        the moment the tool list arrives. A poisoned description can instruct
        the model to use a different, approved tool to do the damage, so
        blocking calls to the poisoned tool alone blocks the wrong thing.

        A quarantined or unapproved tool is therefore withheld from the client.
        Its description never reaches the model at all.
        """
        self.stats["tools_seen"] = len(tools)
        view = self.enforcer.policy.default("quarantined_tool_view")
        compat = self.enforcer.policy.default("client_schema_compatibility")
        visible: list[dict] = []
        adjusted = 0

        def serve(definition: dict) -> None:
            nonlocal adjusted
            cleaned, changed = sanitize_for_client(definition, compat)
            if changed:
                adjusted += 1
            visible.append(cleaned)

        for tool in tools:
            contract = contract_from_mcp_tool(self.server_name, tool)
            registry = self.enforcer.registry

            if not registry.is_known(self.server_name, contract.tool):
                if self.discover:
                    self.enforcer.approve(contract, reason="discovery mode auto-pin")
                    self.log(f"pinned {contract.tool} ({contract.short_fingerprint()})")
                    serve(tool)
                else:
                    self.stats["withheld"] += 1
                    self.log(f"WITHHELD unapproved tool {contract.tool} from the client")
                continue

            decision = self.enforcer.verify_advertised(contract)
            if decision is not None:
                if decision.code in ("VERSION_UPGRADE_ACCEPTED", "DRIFT_ACCEPTED"):
                    self.stats["upgrades"] += 1
                    self.log(f"ACCEPTED change on {contract.tool}: {decision.reason}")
                elif not decision.allowed:
                    self.stats["quarantined"] += 1
                    self.log(f"{decision.code} on {contract.tool}: {decision.reason}")
                else:
                    self.log(f"drift flagged on {contract.tool}: {decision.reason}")

            # Checked after verification, not instead of it: a tool quarantined
            # in an earlier session stays withheld even if this session's copy
            # happens to look clean.
            if registry.is_quarantined(self.server_name, contract.tool):
                self.stats["withheld"] += 1
                if view == "pinned":
                    pinned = registry.get_contract(self.server_name, contract.tool)
                    serve(mcp_tool_from_contract(pinned))
                    self.log(f"serving APPROVED version of quarantined {contract.tool}")
                else:
                    self.log(f"WITHHELD quarantined {contract.tool} from the client")
                continue

            serve(tool)

        if adjusted:
            self.log(
                f"removed a stale schema dialect from {adjusted} tool(s) so the "
                f"client will accept them; pinned contracts are unchanged"
            )
        return visible

    # ---------- whether a call may proceed ----------

    def judge_tool_call(self, message: dict) -> tuple[bool, dict | None]:
        """
        Decide whether a tools/call may be relayed.

        Returns (allowed, denial). When allowed is False the denial is a
        complete JSON-RPC reply the transport should return to the client
        instead of contacting the server. The upstream tool does not execute.
        """
        params = message.get("params") or {}
        tool_name = params.get("name", "<unnamed>")
        args = params.get("arguments") or {}

        contract = self.enforcer.registry.get_contract(self.server_name, tool_name)
        if contract is None:
            # Never advertised in a tools/list we saw. Build a bare contract so
            # the enforcer applies its unknown-tool rule rather than crashing.
            contract = ToolContract(
                server=self.server_name, tool=tool_name, description="", input_schema={}
            )

        decision = self.enforcer.check(contract, args, agent="mcp-client")

        if decision.allowed:
            self.stats["forwarded"] += 1
            return True, None

        self.stats["blocked"] += 1
        self.log(f"BLOCKED {tool_name}: {decision.reason}")
        return False, {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": f"Blocked by Warden [{decision.code}]: {decision.reason}",
                    }
                ],
                "isError": True,
            },
        }

    # ---------- shared helpers for transports ----------

    @staticmethod
    def is_list_changed(message: dict) -> bool:
        return message.get("method") == "notifications/tools/list_changed"

    def summary(self) -> str:
        return " ".join(f"{k}={v}" for k, v in self.stats.items())

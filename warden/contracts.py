"""
Tool contracts: the thing Warden pins and then defends.

An MCP tool advertises a name, a human-readable description, an input schema,
and (in Warden's model) a set of declared scopes describing what it is allowed
to touch. Together those form the tool's CONTRACT.

A server can change any of these at any time, between calls, after review.
That is the Deadbugz pattern: ship benign, mutate later.

Warden pins the contract at approval time and re-verifies it on every single
call. If the contract changed, the tool is no longer the tool that was approved.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any


def _canonical(obj: Any) -> str:
    """Stable JSON so that key ordering never causes a false drift alarm."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


@dataclass(frozen=True)
class ToolContract:
    """
    A snapshot of everything a tool claims to be.

    "Everything" is meant literally. Real MCP tools carry a title shown to the
    user, behaviour hints (read-only, destructive, open-world), and an output
    schema. Leaving any of them out of the fingerprint means a server can change
    it without Warden noticing - and flipping readOnlyHint from true to false is
    one of the largest privilege changes a tool can make.
    """

    server: str
    tool: str
    description: str
    input_schema: dict = field(default_factory=dict)
    declared_scopes: tuple[str, ...] = ()
    title: str = ""
    annotations: dict = field(default_factory=dict)
    output_schema: dict = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.server}::{self.tool}"

    def fingerprint(self) -> str:
        """SHA-256 over the full canonical contract."""
        payload = _canonical(
            {
                "server": self.server,
                "tool": self.tool,
                "description": self.description,
                "input_schema": self.input_schema,
                "declared_scopes": sorted(self.declared_scopes),
                "title": self.title,
                "annotations": self.annotations,
                "output_schema": self.output_schema,
            }
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def short_fingerprint(self) -> str:
        return self.fingerprint()[:12]

    def to_row(self) -> dict:
        return {
            "server": self.server,
            "tool": self.tool,
            "description": self.description,
            "input_schema": _canonical(self.input_schema),
            "declared_scopes": _canonical(sorted(self.declared_scopes)),
            "title": self.title,
            "annotations": _canonical(self.annotations),
            "output_schema": _canonical(self.output_schema),
            "fingerprint": self.fingerprint(),
        }

    @staticmethod
    def from_row(row: dict) -> "ToolContract":
        return ToolContract(
            server=row["server"],
            tool=row["tool"],
            description=row["description"],
            input_schema=json.loads(row["input_schema"]),
            declared_scopes=tuple(json.loads(row["declared_scopes"])),
            title=row["title"] or "",
            annotations=json.loads(row["annotations"] or "{}"),
            output_schema=json.loads(row["output_schema"] or "{}"),
        )


def diff_contracts(pinned: ToolContract, live: ToolContract) -> dict:
    """
    Explain exactly what changed between the approved contract and what the
    server is presenting right now.

    Returns {} when the contracts are identical. Otherwise returns a structured
    diff that is safe to put straight into an audit log or an alert.
    """
    changes: dict[str, Any] = {}

    if pinned.description != live.description:
        changes["description"] = {
            "approved": pinned.description,
            "now": live.description,
        }

    if pinned.input_schema != live.input_schema:
        pinned_props = set((pinned.input_schema.get("properties") or {}).keys())
        live_props = set((live.input_schema.get("properties") or {}).keys())
        changes["input_schema"] = {
            "added_fields": sorted(live_props - pinned_props),
            "removed_fields": sorted(pinned_props - live_props),
            "approved": pinned.input_schema,
            "now": live.input_schema,
        }

    if pinned.title != live.title:
        changes["title"] = {"approved": pinned.title, "now": live.title}

    if pinned.annotations != live.annotations:
        keys = set(pinned.annotations) | set(live.annotations)
        flipped = {
            k: {"approved": pinned.annotations.get(k), "now": live.annotations.get(k)}
            for k in sorted(keys)
            if pinned.annotations.get(k) != live.annotations.get(k)
        }
        changes["annotations"] = flipped

    if pinned.output_schema != live.output_schema:
        changes["output_schema"] = {
            "approved": pinned.output_schema,
            "now": live.output_schema,
        }

    if set(pinned.declared_scopes) != set(live.declared_scopes):
        changes["declared_scopes"] = {
            "added": sorted(set(live.declared_scopes) - set(pinned.declared_scopes)),
            "removed": sorted(set(pinned.declared_scopes) - set(live.declared_scopes)),
        }

    return changes


def summarize_drift(changes: dict) -> str:
    """One plain-English line an on-call engineer can read at 3am."""
    if not changes:
        return "no drift"

    parts: list[str] = []
    if "description" in changes:
        parts.append("description rewritten")
    if "input_schema" in changes:
        added = changes["input_schema"]["added_fields"]
        removed = changes["input_schema"]["removed_fields"]
        if added:
            parts.append(f"new input fields {added}")
        if removed:
            parts.append(f"removed input fields {removed}")
        if not added and not removed:
            parts.append("input schema altered")
    if "title" in changes:
        parts.append("title rewritten")
    if "annotations" in changes:
        names = ", ".join(changes["annotations"].keys())
        parts.append(f"behaviour hints changed ({names})")
    if "output_schema" in changes:
        parts.append("output schema altered")
    if "declared_scopes" in changes:
        added = changes["declared_scopes"]["added"]
        if added:
            parts.append(f"claimed new scopes {added}")
        removed = changes["declared_scopes"]["removed"]
        if removed:
            parts.append(f"dropped scopes {removed}")

    return "; ".join(parts)

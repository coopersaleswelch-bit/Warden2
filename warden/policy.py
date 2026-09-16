"""
Policy loading.

Rules live in policy.yaml so a security team can change what agents may do
without anyone touching Python. That was the right call in Warden 1.0 and it
carries straight over.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

DEFAULT_POLICY: dict[str, Any] = {
    "version": 1,
    "defaults": {
        "unknown_tool": "deny",       # deny | allow
        "on_drift": "quarantine",     # fallback for any drift case not set below
        "on_novel_arg_shape": "warn", # deny | warn | allow
        "on_undeclared_arg": "deny",  # argument not in the approved input schema
        "baseline_calls": 3,          # calls before arg-shape baseline is trusted

        # Risk-aware drift handling. Each may be quarantine | block | warn.
        # Leave one as None to fall back to on_drift above.
        "on_elevation": "quarantine",       # the tool gained power
        "on_silent_mutation": "quarantine", # changed without declaring a version
        "on_benign_drift": None,            # strictly less capable, or reworded
        "on_ambiguous_drift": None,         # neither clearly safe nor escalating

        # When a server declares a NEW version and the only changes are benign,
        # accept the new contract automatically. This is what stops a routine
        # upgrade from paging a human at 2am.
        "auto_repin_on_version_bump": True,
    },
    "denied_scopes": [],
    "tools": [],
}


@dataclass
class ToolRule:
    server: str
    tool: str
    allow_arg_prefixes: dict[str, list[str]] = field(default_factory=dict)
    deny_arg_contains: dict[str, list[str]] = field(default_factory=dict)
    max_calls: int | None = None

    @property
    def key(self) -> str:
        return f"{self.server}::{self.tool}"


@dataclass
class Policy:
    version: int
    defaults: dict[str, Any]
    denied_scopes: list[str]
    rules: dict[str, ToolRule]

    def rule_for(self, server: str, tool: str) -> ToolRule | None:
        return self.rules.get(f"{server}::{tool}")

    def default(self, name: str) -> Any:
        return self.defaults.get(name, DEFAULT_POLICY["defaults"].get(name))

    # Maps a drift verdict to the policy key that governs it.
    _DRIFT_KEYS = {
        "ELEVATION": "on_elevation",
        "SILENT_MUTATION": "on_silent_mutation",
        "BENIGN": "on_benign_drift",
        "AMBIGUOUS": "on_ambiguous_drift",
    }

    def drift_action(self, kind: str) -> str:
        """
        What to do about a drift of this kind: quarantine | block | warn.

        An unset key falls back to on_drift, so an existing policy.yaml written
        before risk classification existed keeps behaving exactly as it did.
        """
        key = self._DRIFT_KEYS.get(kind)
        value = self.defaults.get(key) if key else None
        if value is None:
            value = self.default("on_drift")
        return value or "quarantine"


def load_policy(path: str | Path = "policy.yaml") -> Policy:
    p = Path(path)
    if p.exists():
        raw = yaml.safe_load(p.read_text()) or {}
    else:
        raw = {}

    defaults = {**DEFAULT_POLICY["defaults"], **(raw.get("defaults") or {})}

    rules: dict[str, ToolRule] = {}
    for entry in raw.get("tools") or []:
        rule = ToolRule(
            server=entry["server"],
            tool=entry["tool"],
            allow_arg_prefixes=entry.get("allow_arg_prefixes") or {},
            deny_arg_contains=entry.get("deny_arg_contains") or {},
            max_calls=entry.get("max_calls"),
        )
        rules[rule.key] = rule

    return Policy(
        version=int(raw.get("version", 1)),
        defaults=defaults,
        denied_scopes=list(raw.get("denied_scopes") or []),
        rules=rules,
    )

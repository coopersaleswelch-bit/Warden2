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
        "on_drift": "quarantine",     # quarantine | block | warn
        "on_novel_arg_shape": "warn", # deny | warn | allow
        "baseline_calls": 3,          # calls before arg-shape baseline is trusted
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

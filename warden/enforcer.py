"""
The enforcer: Warden's decision engine.

Every tool call an agent makes passes through check(). The order matters —
cheapest and most severe checks first, so a quarantined tool never gets as far
as argument inspection.

    1. Is this tool known to us at all?
    2. Is it currently quarantined?
    3. Does the live contract still match what we approved?   <-- the drift check
    4. Does it claim any globally denied scope?
    5. Do the arguments satisfy this tool's policy rule?
    6. Has it exceeded its call budget?
    7. Is this argument shape unlike anything we've seen before?

Checks 1-6 can deny. Check 7 flags. Nothing about this is probabilistic — a
denied call does not execute, and the reason is always a specific rule.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

from .audit import AuditLog
from .contracts import ToolContract, diff_contracts, summarize_drift
from .policy import Policy, load_policy
from .registry import ContractRegistry


class WardenDenied(Exception):
    """Raised when a denied call is attempted through guard()."""

    def __init__(self, decision: "Decision"):
        super().__init__(decision.reason)
        self.decision = decision


@dataclass
class Decision:
    allowed: bool
    code: str
    reason: str
    server: str
    tool: str
    drift: dict = field(default_factory=dict)
    flags: list[str] = field(default_factory=list)
    fingerprint: str | None = None

    def __str__(self) -> str:
        verdict = "ALLOW" if self.allowed else "DENY "
        return f"[{verdict}] {self.server}::{self.tool} — {self.reason}"


class Enforcer:
    def __init__(
        self,
        registry: ContractRegistry | None = None,
        policy: Policy | None = None,
        audit: AuditLog | None = None,
        *,
        session: str | None = None,
        on_event: Callable[[Decision], None] | None = None,
    ):
        self.registry = registry or ContractRegistry()
        self.policy = policy or load_policy()
        self.audit = audit or AuditLog()
        self.session = session or uuid.uuid4().hex[:12]
        self.on_event = on_event

    # ---------- approval ----------

    def approve(self, contract: ToolContract, reason: str = "initial approval") -> None:
        """Pin a tool contract as the approved reference version."""
        self.registry.pin(contract, reason=reason)

    def approve_many(self, contracts: list[ToolContract]) -> None:
        for c in contracts:
            self.approve(c)

    # ---------- the hot path ----------

    def check(
        self,
        live_contract: ToolContract,
        args: dict[str, Any] | None = None,
        *,
        agent: str = "unknown-agent",
    ) -> Decision:
        args = args or {}
        server, tool = live_contract.server, live_contract.tool

        decision = self._evaluate(live_contract, args)

        self.audit.record(
            session=self.session,
            agent=agent,
            server=server,
            tool=tool,
            allowed=decision.allowed,
            code=decision.code,
            reason=decision.reason,
            args=args,
            fingerprint=decision.fingerprint,
            drift=decision.drift or None,
        )

        if decision.allowed:
            self.registry.record_arg_shape(server, tool, list(args.keys()))

        if self.on_event:
            self.on_event(decision)

        return decision

    def _evaluate(self, live: ToolContract, args: dict) -> Decision:
        server, tool = live.server, live.tool
        fp = live.short_fingerprint()

        def deny(code: str, reason: str, **kw) -> Decision:
            return Decision(False, code, reason, server, tool, fingerprint=fp, **kw)

        # 1. unknown tool
        pinned = self.registry.get_contract(server, tool)
        if pinned is None:
            if self.policy.default("unknown_tool") == "allow":
                return Decision(
                    True, "UNKNOWN_TOOL_ALLOWED",
                    "tool is not in the registry; policy allows unknown tools",
                    server, tool, fingerprint=fp,
                )
            return deny(
                "UNKNOWN_TOOL",
                "tool has never been approved; no pinned contract exists",
            )

        # 2. quarantined
        if self.registry.is_quarantined(server, tool):
            row = self.registry.get(server, tool)
            return deny(
                "QUARANTINED",
                f"tool is quarantined and requires human re-approval "
                f"({row['status_reason']})",
            )

        # 3. contract drift — the core check
        changes = diff_contracts(pinned, live)
        if changes:
            summary = summarize_drift(changes)
            action = self.policy.default("on_drift")
            if action == "quarantine":
                self.registry.quarantine(server, tool, f"contract drift: {summary}")
                return deny(
                    "CONTRACT_DRIFT",
                    f"tool no longer matches its approved contract ({summary}); "
                    f"quarantined pending human re-approval",
                    drift=changes,
                )
            if action == "block":
                return deny(
                    "CONTRACT_DRIFT",
                    f"tool no longer matches its approved contract ({summary})",
                    drift=changes,
                )
            # warn
            return Decision(
                True, "CONTRACT_DRIFT_WARN",
                f"contract drift observed but policy is warn-only ({summary})",
                server, tool, drift=changes, flags=["drift"], fingerprint=fp,
            )

        # 4. globally denied scopes
        denied = sorted(set(live.declared_scopes) & set(self.policy.denied_scopes))
        if denied:
            return deny(
                "DENIED_SCOPE",
                f"tool declares globally denied scope(s): {denied}",
            )

        # 5. argument policy
        rule = self.policy.rule_for(server, tool)
        if rule:
            for arg_name, needles in rule.deny_arg_contains.items():
                value = str(args.get(arg_name, ""))
                hit = next((n for n in needles if n.lower() in value.lower()), None)
                if hit:
                    return deny(
                        "ARG_DENIED",
                        f"argument '{arg_name}' contains blocked pattern '{hit}'",
                    )

            for arg_name, prefixes in rule.allow_arg_prefixes.items():
                if arg_name in args:
                    value = str(args[arg_name])
                    if not any(value.startswith(p) for p in prefixes):
                        return deny(
                            "ARG_OUT_OF_BOUNDS",
                            f"argument '{arg_name}' = '{value}' is outside the "
                            f"allowed prefixes {prefixes}",
                        )

            # 6. call budget
            if rule.max_calls is not None:
                used = self.registry.call_count(server, tool)
                if used >= rule.max_calls:
                    return deny(
                        "RATE_LIMIT",
                        f"call budget exhausted ({used}/{rule.max_calls})",
                    )

        # 7. behavioural envelope (flag only)
        flags: list[str] = []
        baseline_n = int(self.policy.default("baseline_calls"))
        seen_shapes = self.registry.known_arg_shapes(server, tool)
        if self.registry.call_count(server, tool) >= baseline_n:
            shape = sorted(args.keys())
            if shape and shape not in seen_shapes:
                novel_action = self.policy.default("on_novel_arg_shape")
                if novel_action == "deny":
                    return deny(
                        "NOVEL_ARG_SHAPE",
                        f"argument shape {shape} has never been seen for this tool",
                    )
                if novel_action == "warn":
                    flags.append("novel_arg_shape")

        reason = "contract verified; call within policy"
        if flags:
            reason += f" (flags: {', '.join(flags)})"

        return Decision(True, "ALLOWED", reason, server, tool, flags=flags, fingerprint=fp)

    # ---------- actual enforcement ----------

    def guard(
        self,
        live_contract: ToolContract,
        args: dict[str, Any] | None = None,
        *,
        agent: str = "unknown-agent",
    ):
        """
        Wrap a real callable so a denied call genuinely does not execute.

            @enforcer.guard(contract, args, agent="research-agent")
            def call_tool(): ...

        Or used directly:

            enforcer.guard(contract, args)(some_function)(**args)
        """
        decision = self.check(live_contract, args, agent=agent)

        def wrapper(fn: Callable) -> Callable:
            def inner(*a, **kw):
                if not decision.allowed:
                    raise WardenDenied(decision)
                return fn(*a, **kw)

            inner.warden_decision = decision  # type: ignore[attr-defined]
            return inner

        return wrapper

    def close(self) -> None:
        self.registry.close()
        self.audit.close()

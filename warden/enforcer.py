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
from .classify import AMBIGUOUS, BENIGN, ELEVATION, classify_drift
from .contracts import ToolContract, diff_contracts, summarize_drift
from .policy import Policy, load_policy
from .registry import ContractRegistry


SILENT_MUTATION = "SILENT_MUTATION"


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
        # server -> "upgraded" | "unchanged" | "unknown", set at handshake
        self._version_state: dict[str, str] = {}

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
            return self._judge_drift(pinned, live, changes, fp)

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

        # 6b. arguments the approved contract never declared
        #
        # An argument the pinned schema does not mention is, by definition, not
        # something this tool was approved to receive. It is also how a poisoned
        # description gets its payload through while the schema still looks
        # clean: the instruction tells the agent to pass an extra field.
        flags: list[str] = []
        schema = pinned.input_schema or {}
        declared = schema.get("properties")
        if declared is not None and not schema.get("additionalProperties", False):
            undeclared = sorted(set(args) - set(declared))
            if undeclared:
                undeclared_action = self.policy.default("on_undeclared_arg")
                if undeclared_action == "deny":
                    return deny(
                        "UNDECLARED_ARG",
                        f"argument(s) {undeclared} are not in the tool's approved "
                        f"input schema",
                    )
                if undeclared_action == "warn":
                    flags.append(f"undeclared_arg:{','.join(undeclared)}")

        # 7. behavioural envelope (flag only)
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

    # ---------- server version awareness ----------

    def note_server_version(self, server: str, version: str | None) -> str:
        """
        Record what version a server claims to be, at handshake time.

        Returns the state this establishes for the session:
            "upgraded"  the server declared a version we have not seen
            "unchanged" the server declared the same version as last time
            "unknown"   we have never seen this server, or it declares nothing

        This is what separates a routine upgrade from a rug-pull. A server that
        changes its tools while still calling itself v1.0.16 is contradicting
        its own identity, and no amount of benign-looking diff should excuse it.
        """
        previous = self.registry.record_server_version(server, version)

        if previous is None or version is None:
            state = "unknown"
        elif previous == version:
            state = "unchanged"
        else:
            state = "upgraded"

        self._version_state[server] = state
        return state

    def version_state(self, server: str) -> str:
        return self._version_state.get(server, "unknown")

    # ---------- drift judgment ----------

    def _judge_drift(
        self, pinned: ToolContract, live: ToolContract, changes: dict, fp: str
    ) -> Decision:
        server, tool = live.server, live.tool
        verdict = classify_drift(changes)
        state = self.version_state(server)
        version = self.registry.get_server_version(server)

        authoritative = self.policy.version_is_authoritative(server)

        if authoritative and state == "unchanged":
            # The server says it is the same software. It is not.
            kind = SILENT_MUTATION
            detail = (
                f"server still reports version {version} but its contract changed "
                f"({verdict.summary()})"
            )
        else:
            # Without a version we can trust, the only question left is whether
            # the tool gained power. That is a narrower guarantee and it is
            # stated honestly rather than dressed up: Warden promises no tool
            # gains capability without a human, not that nothing ever changes.
            kind = verdict.level
            detail = verdict.summary()

        # A declared upgrade is trusted unless the tool gained power. Reworded
        # prose and reshuffled optional fields are what a changelog looks like;
        # quarantining those is how a security control gets switched off.
        # Elevation is the gate, not change itself.
        if (
            authoritative
            and kind in (BENIGN, AMBIGUOUS)
            and state == "upgraded"
            and self.policy.default("auto_repin_on_version_bump")
        ):
            self.registry.reapprove(
                live, reason=f"accepted upgrade to {version}: {detail}"
            )
            return Decision(
                True,
                "VERSION_UPGRADE_ACCEPTED",
                f"server upgraded to {version} with no gain in capability "
                f"({detail}); new contract accepted automatically",
                server,
                tool,
                drift=changes,
                flags=["repinned", "upgrade"],
                fingerprint=fp,
            )

        action = self.policy.drift_action(kind)
        label = kind.replace("_", " ").lower()

        if action == "accept":
            self.registry.reapprove(live, reason=f"accepted {label} change: {detail}")
            return Decision(
                True,
                "DRIFT_ACCEPTED",
                f"{label} change accepted — the tool gained nothing ({detail})",
                server,
                tool,
                drift=changes,
                flags=["repinned", kind.lower()],
                fingerprint=fp,
            )

        if action == "warn":
            return Decision(
                True,
                "CONTRACT_DRIFT_WARN",
                f"{label} drift observed but policy is warn-only ({detail})",
                server,
                tool,
                drift=changes,
                flags=["drift", kind.lower()],
                fingerprint=fp,
            )

        if action == "quarantine":
            self.registry.quarantine(server, tool, f"{label}: {detail}")
            reason = (
                f"tool no longer matches its approved contract — {label} "
                f"({detail}); quarantined pending human re-approval"
            )
        else:  # block
            reason = f"tool no longer matches its approved contract — {label} ({detail})"

        code = "SILENT_MUTATION" if kind == SILENT_MUTATION else "CONTRACT_DRIFT"
        return Decision(
            False,
            code,
            reason,
            server,
            tool,
            drift=changes,
            flags=[kind.lower()],
            fingerprint=fp,
        )

    def verify_advertised(self, live: ToolContract) -> Decision | None:
        """
        Check a tool the server has just advertised, before anyone calls it.

        A server has to declare a capability before it can use it, so this runs
        one step earlier than check() and catches a mutation before the client
        makes a single call against it.

        Returns None when the tool is new and there is nothing to compare
        against. Otherwise returns the Decision, already written to the audit
        log, so the caller only has to react to it.
        """
        pinned = self.registry.get_contract(live.server, live.tool)
        if pinned is None:
            return None

        changes = diff_contracts(pinned, live)
        if not changes:
            return None

        decision = self._judge_drift(pinned, live, changes, live.short_fingerprint())

        self.audit.record(
            session=self.session,
            agent="proxy-inspection",
            server=live.server,
            tool=live.tool,
            allowed=decision.allowed,
            code=decision.code,
            reason=decision.reason,
            args={},
            fingerprint=decision.fingerprint,
            drift=changes,
        )

        if self.on_event:
            self.on_event(decision)

        return decision

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

"""
Drift classification.

Warden's Day 2 behaviour was to treat every contract change as hostile. That is
correct and unusable: a server going from v1.2 to v1.3 rewords a description and
adds an optional field, gets quarantined, and the security team turns Warden off.

The useful question is not "did this tool change" but "did this tool gain power".

    ELEVATION  the tool can now do, reach or receive something it could not
               before. A new permission. A new field named like a command or a
               credential. A description that has grown an instruction.

    BENIGN     the tool can do strictly less, or the same. Reworded prose,
               removed fields, dropped scopes, tightened schema.

    AMBIGUOUS  changed in a way that is neither clearly a reduction nor clearly
               an escalation. Judged by policy, not by this module.

Nothing here is probabilistic and nothing calls a model. These are string and
set operations over a diff, so the same input always produces the same verdict
and an engineer can read the reason and check it by hand.
"""

from __future__ import annotations

from dataclasses import dataclass, field

ELEVATION = "ELEVATION"
BENIGN = "BENIGN"
AMBIGUOUS = "AMBIGUOUS"

# Field names that hand a tool reach it did not have. A tool that grows a
# "command" or "webhook_url" input is a different tool, whatever its name says.
SENSITIVE_FIELD_HINTS = (
    "command", "cmd", "exec", "shell", "script", "eval", "run",
    "path", "file", "filename", "directory", "dir",
    "url", "uri", "endpoint", "host", "webhook", "callback",
    "token", "key", "secret", "credential", "password", "passwd", "auth",
    "env", "environment", "config", "sudo", "admin", "root",
)

# Phrases that turn a description into an instruction aimed at the model reading
# it. This is the tool-poisoning surface: the description is prompt context, so
# text added here is text injected into the agent.
INJECTION_HINTS = (
    "ignore previous", "ignore all previous", "disregard",
    "before returning", "before responding", "after returning",
    "do not tell", "do not mention", "without telling", "silently",
    "include the contents", "read the", "send the", "forward the",
    "system prompt", "your instructions", "new instructions",
    "you must", "you should always", "always include",
    "base64", "exfiltrat", "upload to", "post to",
)

# Scopes that are an escalation no matter what else the diff says.
HIGH_RISK_SCOPE_HINTS = (
    "exec", "shell", "spawn", "process", "write", "delete", "admin",
    "credential", "secret", "token", "network", "raw", "sudo",
)


@dataclass
class DriftVerdict:
    """Why a change was judged the way it was. Every field is human-readable."""

    level: str
    reasons: list[str] = field(default_factory=list)

    @property
    def is_elevation(self) -> bool:
        return self.level == ELEVATION

    @property
    def is_benign(self) -> bool:
        return self.level == BENIGN

    def summary(self) -> str:
        if not self.reasons:
            return self.level.lower()
        return "; ".join(self.reasons)


def _matches(text: str, needles: tuple[str, ...]) -> list[str]:
    lowered = text.lower()
    return [n for n in needles if n in lowered]


def _field_is_sensitive(name: str) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in SENSITIVE_FIELD_HINTS)


def classify_drift(changes: dict) -> DriftVerdict:
    """
    Judge a diff produced by contracts.diff_contracts().

    Elevation wins over everything: one escalating change in an otherwise
    harmless upgrade still makes the whole upgrade an escalation. A server that
    adds a nice new optional field AND quietly claims shell access is not a
    server that made a nice change.
    """
    if not changes:
        return DriftVerdict(BENIGN, [])

    elevation: list[str] = []
    benign: list[str] = []
    ambiguous: list[str] = []

    # ---- permissions ----
    #
    # Scopes beginning "tool." are derived by Warden from the behaviour hints,
    # and the annotations branch below judges those precisely — including which
    # direction they moved. Judging them here too would double-report every
    # change and, worse, read a reduction as a gain: going back to read-only
    # ADDS the derived scope "tool.read", which is a restriction, not a
    # privilege. Only scopes a server declares for itself are judged here.
    scopes = changes.get("declared_scopes") or {}
    for added in scopes.get("added") or []:
        if added.startswith("tool."):
            continue
        if _matches(added, HIGH_RISK_SCOPE_HINTS):
            elevation.append(f"claimed high-risk permission '{added}'")
        else:
            elevation.append(f"claimed new permission '{added}'")
    for removed in scopes.get("removed") or []:
        if removed.startswith("tool."):
            continue
        benign.append(f"gave up permission '{removed}'")

    # ---- behaviour hints ----
    #
    # These are the closest thing MCP has to a permission model, and a flip here
    # is a bigger privilege change than anything in the schema. A tool that was
    # read-only and now is not can write to everything it can reach.
    hints = changes.get("annotations") or {}
    for name, movement in hints.items():
        was, now = movement.get("approved"), movement.get("now")

        if name == "readOnlyHint":
            if was is True and now is not True:
                elevation.append("gave up its read-only guarantee")
            elif now is True and was is not True:
                benign.append("became read-only")

        elif name in ("destructiveHint", "openWorldHint"):
            label = {
                "destructiveHint": "the ability to destroy or overwrite data",
                "openWorldHint": "the ability to reach outside the local system",
            }[name]
            if now is True and was is not True:
                elevation.append(f"claimed {label}")
            elif was is True and now is not True:
                benign.append(f"gave up {label}")

        else:
            ambiguous.append(f"behaviour hint '{name}' changed from {was} to {now}")

    # ---- title ----
    #
    # The title is what a user sees in an approval prompt. Rewording it to look
    # more trustworthy is social engineering aimed at the human, not the model.
    title = changes.get("title") or {}
    if title:
        hits = _matches(title.get("now", ""), INJECTION_HINTS)
        if hits:
            elevation.append("title grew an instruction")
        else:
            ambiguous.append("title rewritten")

    # ---- output schema ----
    out = changes.get("output_schema") or {}
    if out:
        ambiguous.append("output schema altered")

    # ---- input schema ----
    schema = changes.get("input_schema") or {}
    added_fields = schema.get("added_fields") or []
    removed_fields = schema.get("removed_fields") or []

    now_schema = schema.get("now") or {}
    was_schema = schema.get("approved") or {}
    now_required = set(now_schema.get("required") or [])
    was_required = set(was_schema.get("required") or [])
    newly_required = sorted(now_required - was_required)

    for name in added_fields:
        if _field_is_sensitive(name):
            elevation.append(f"added sensitive input field '{name}'")
        elif name in newly_required:
            ambiguous.append(f"added required input field '{name}'")
        else:
            ambiguous.append(f"added optional input field '{name}'")

    for name in removed_fields:
        benign.append(f"removed input field '{name}'")

    for name in newly_required:
        if name not in added_fields:
            ambiguous.append(f"input field '{name}' is now required")

    # ---- description ----
    desc = changes.get("description") or {}
    if desc:
        old = desc.get("approved", "")
        new = desc.get("now", "")

        # Only judge what was ADDED. Text that was already approved is not a
        # new risk just because the sentence around it moved.
        i = 0
        while i < min(len(old), len(new)) and old[i] == new[i]:
            i += 1
        appended = new[i:]

        hits = _matches(appended, INJECTION_HINTS)
        if hits:
            elevation.append(
                f"description grew an instruction ({', '.join(hits[:3])})"
            )
        elif len(new) < len(old):
            benign.append("description shortened")
        elif appended.strip():
            ambiguous.append("description text added")
        else:
            benign.append("description reworded")

    # ---- verdict ----
    if elevation:
        return DriftVerdict(ELEVATION, elevation)
    if ambiguous:
        return DriftVerdict(AMBIGUOUS, ambiguous + benign)
    return DriftVerdict(BENIGN, benign or ["no material change"])

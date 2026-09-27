<img src="docs/warden-mark.svg" width="88" alt="Warden">

# Warden

**Your AI agents have real access to real systems. Warden makes sure they only ever do what you approved.**

---

## The problem

An AI agent inside a company is not a chatbot. It reads files, writes to
databases, calls internal APIs, moves money, opens tickets, deploys code. It
does that through tools, and each tool is described to the agent by whoever
operates it.

Those descriptions are trusted completely. The agent reads them as instructions.
The client accepts whatever schema arrives. Nothing in the protocol requires a
tool to still be the tool it was last week.

So a tool your security team approved in January can quietly become something
else in March — a broader permission, a new argument, a description that now
carries a sentence aimed at the model. Nobody is notified, because from the
protocol's point of view nothing unusual happened.

The exposure is not theoretical. Industry research published in 2026 found that
65% of organizations had experienced at least one security incident caused by an
AI agent in the preceding year, 61% of those involving sensitive data exposure —
while only around a fifth said they could control their agents at all.

## Why approving a tool once isn't enough

Most tooling in this space checks a server when you install it. That catches a
server that is already malicious. It cannot catch a server that becomes
malicious later, because at install time there is nothing to find.

The gap is exploited deliberately. A server can ship harmless tools, pass
review, serve real traffic for weeks, and only then change — sometimes gating
the change behind a number of calls so a reviewer checking a fresh install sees
nothing wrong.

And the damage does not require the changed tool to be called. A tool
description enters the model's context the moment the tool list is read. A
poisoned description can simply instruct the agent to accomplish the attacker's
goal using a **different tool that is fully approved**. Blocking calls to the
compromised tool blocks the wrong thing.

What is missing is not a better scanner. It is a record of what was approved and
something that checks reality against it, continuously.

## What Warden does

Warden sits in the path between the agent and the tools, speaking the same
protocol in both directions. Neither side is modified and neither side needs to
know it is there.

**At approval**, Warden records the complete contract of every tool — name,
description, input schema, output schema, title, and behaviour hints — and
fingerprints it. That record is what the organization approved.

**Whenever tools are advertised**, Warden re-verifies every one against its
record. A tool that no longer matches is quarantined and **withheld from the
client entirely**, so a poisoned description never reaches the model.

**On every call**, Warden checks the call itself: is this tool known, is it
quarantined, does its contract still match, does it claim a capability policy
forbids, are the arguments within policy and within the approved schema, is it
inside its call budget.

**A refused call is never forwarded.** The upstream tool does not execute.

**Every decision is recorded** — allowed or refused — with the rule that
produced it, the arguments involved, the fingerprint, and the time.

## Architecture

```
   AI client / agent
          |
          v
   +--------------+     contract registry    what was approved
   |    WARDEN    | <-- policy engine        what is permitted
   +--------------+     audit log            what happened
          |
          v
      MCP server
```

The security engine is independent of transport. The proxy translates a
transport into contract checks and policy decisions; the decisions themselves
know nothing about pipes or sockets. That separation is deliberate, so support
for additional transports does not mean a second copy of the security logic.

## Attack demonstration

A tool approved as read-only quietly stops being read-only:

```
hints before: {"readOnlyHint": true,  "openWorldHint": false}
hints after:  {"readOnlyHint": false, "destructiveHint": true, "openWorldHint": true}

ELEVATION
  - gave up its read-only guarantee
  - claimed the ability to destroy or overwrite data
  - claimed the ability to reach outside the local system
QUARANTINED — withheld from the client
```

And a refusal recorded in live use, from a server running under Claude Desktop:

```
Refused   files2::write_file   DENIED_SCOPE   24 Sep 2026, 14:30:57
tool declares globally denied scope(s): ['tool.destructive']
arguments: {"content": "test", "path": "...\warden-test2\blocked.txt"}
```

The file was never created. The call did not reach the server.

## Installation

Requires Python 3.10 or newer. Warden's only dependency is PyYAML — deliberately
minimal, because a security tool's own supply chain is part of your attack
surface.

```bash
git clone https://github.com/coopersaleswelch-bit/Warden2
cd Warden2
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

To protect a server the organization already uses:

```bash
python -m warden.doctor      # checks this machine; reads only, changes nothing
python -m warden.install     # lists configured servers, protects the one you pick
```

The installer inspects the server and records its contracts **before** touching
any configuration, backs up the existing config with a timestamp, preserves the
server's own environment variables, and restores the original entry exactly on
`--unprotect`.

It refuses rather than guesses. A remote server, a server that will not start,
a server already protected, or a configuration file that is not valid JSON all
leave the file untouched.

## Two-minute demonstration

```bash
python test_warden.py     # 110 checks
python demo_day3.py       # upgrade accepted, two attacks caught
python demo_day4.py       # run against a real third-party MCP server
```

`demo_day3.py` is the one to watch. Four sessions against a real server over
real pipes:

1. A server is approved and its tools recorded.
2. The vendor ships a genuine new version that gains no capability — accepted
   automatically, nobody paged.
3. The server changes a tool while still reporting the same version — caught,
   quarantined, withheld.
4. The server changes a tool *and* declares a new version — caught anyway,
   because the change increased capability.

Step 2 matters as much as steps 3 and 4. A control that treats every routine
upgrade as an attack gets switched off within a week.

## Security model

Warden fails closed. When a decision cannot be made safely, the call is refused
rather than allowed.

Capability is the gate, not change itself. A change is treated as hostile when
it increases what the tool can do:

- a new permission, or the loss of a read-only guarantee
- a new input field named like a command, path, URL or credential
- a description that grew an instruction directed at the model
- a claim on destructive or external-world capability

Permissions are derived from the protocol's own behaviour hints, so the rules
work against servers that have never heard of Warden. A tool that does not
claim to be read-only is treated as able to write — the absence of a promise is
not a promise.

Version claims are corroborating evidence, not proof. A server that changes its
tools while reporting an unchanged version is contradicting itself, and that is
treated as the strongest available signal. But version trust is **off by
default**, because real servers do not honour it: the official filesystem server
reports version `0.2.0` while shipping as package `2026.8.31`. With it off, the
guarantee is narrower and honest — *no tool gains capability without a human*.

## Policy

Rules live in `policy.yaml`. Changing what agents may do requires no code
changes.

| Setting | Options | Governs |
|---|---|---|
| `unknown_tool` | `deny` / `allow` | a tool that was never approved |
| `on_elevation` | `quarantine` / `block` / `warn` | the tool gained capability |
| `on_silent_mutation` | `quarantine` / `block` / `warn` | changed without declaring a version |
| `on_undeclared_arg` | `deny` / `warn` / `allow` | an argument outside the approved schema |
| `quarantined_tool_view` | `hide` / `pinned` | withhold the tool, or serve its approved version |
| `version_is_authoritative` | `true` / `false` | whether this server's version can be trusted |
| `denied_scopes` | list | capabilities no tool may hold |

Per-tool rules support allowed argument prefixes, blocked argument patterns and
call budgets. Settings can be overridden per server.

## Audit

Every decision is written at the moment it is made, with the evidence needed to
reconstruct it: the verdict, the rule, the tool and server, the arguments, the
contract fingerprint, the time, and for a drifted contract, the diff.

`python -m warden.report` renders that record as a single self-contained page,
ordered by severity — quarantined tools first, then refusals, then all-clear. A
refusal is never displayed as all-clear.

## Current limitations

Stated plainly, because a security tool that hides its edges should not be
trusted.

- **stdio transport only.** Servers reached over HTTP are not supported.
- **Untested against `tools/list_changed`.** Servers that push tool-list updates
  mid-session have not been exercised.
- **Verified against one third-party server.** The official filesystem server.
  Others will have behaviours this has not met.
- **Single node, local state.** No central control plane, no multi-tenancy.
- **No agent identity.** Warden knows which tool and which arguments. It does
  not yet know which agent, or on whose behalf.
- **Not independently audited.**

## Roadmap

None of the following is built. It is listed so the direction is legible.

**Next** — HTTP transport on the existing enforcement core. Handling servers
that change their tool list mid-session. A second and third real server.

**Later** — agent identity and per-agent policy. Structured export for SIEM and
compliance tooling. Central policy distribution across machines.

**Not yet** — multi-tenant control plane, RBAC, analytics. These are answers to
questions no user has asked. Building them before someone runs Warden in anger
would be guessing.

## Development

```bash
python test_warden.py
```

110 checks across the contract model, the capability classifier, the proxy, the
installer and the report. Every bug found so far has a permanent regression
test. `PROGRESS.md` is the build log, including what broke and why.

## Licence

Not yet chosen. All rights reserved by default — ask before using this anywhere
it matters.

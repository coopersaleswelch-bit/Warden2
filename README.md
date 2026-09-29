<img src="docs/warden-mark.svg" width="88" alt="Warden">

# Warden

### Approve a tool once. Warden checks it every time it runs.

Your agents already have the keys. They read files, query databases, call
internal services, move money, ship code. Every one of those actions goes
through a tool, and every tool describes itself to the agent in its own words.

Nothing requires a tool to still be the tool you approved.

---

## The problem

Picture the tool your security team signed off in January. It read records. It
could not write them. Everyone agreed, and the agent has used it every day
since.

In March the description gains a sentence. The schema gains a field. The
permission that made it read-only quietly disappears. No alert fires, because
nothing unusual happened at the protocol level. A server said what its tools
are, which is exactly what servers do, and your agent believed it, which is
exactly what agents do.

This is not a hypothetical failure mode. Research published by the Cloud
Security Alliance and Token Security in April 2026 found that 65% of
organizations had suffered at least one security incident caused by an AI agent
in the previous year, and that 61% of those incidents involved exposure of
sensitive data. In the same period, Cisco's State of AI Security 2026 reported
that only 29% of organizations felt prepared to secure agentic AI at all.

The agents are already inside. The controls are not.

## Why approving a tool once is not enough

Most security tooling for this problem inspects a server when you install it.
That catches a server born malicious. It cannot catch a server that turns,
because on installation day there is nothing to find.

Attackers know this. A server can ship harmless tools, pass review, serve real
traffic for weeks, then change. Some hold the change behind a counter so a
reviewer opening a fresh install sees only good behaviour.

Worse, the damage does not require anyone to call the compromised tool. A tool
description is loaded into the model's context the moment the tool list is read.
A poisoned description can instruct the agent to accomplish the attacker's goal
using a completely different tool, one that is legitimately approved and
behaving normally. Block calls to the compromised tool and you have blocked the
wrong thing.

The missing piece is not a better scanner. It is a durable record of what was
approved, and something that checks reality against that record continuously.

## What Warden does

Warden sits between the agent and the tools, speaking the same protocol in both
directions. Neither side is modified. Neither side knows it is there.

**When a tool is approved**, Warden records its entire contract: name,
description, input schema, output schema, title, behaviour hints. Then it
fingerprints that record. This is the organization's memory of what it agreed
to.

**Whenever tools are advertised**, Warden re-verifies every one against that
memory. A tool that no longer matches is quarantined and withheld from the
client completely, so a poisoned description never reaches the model at all.

**When a server announces its tools changed**, Warden asks for the new list
immediately rather than waiting for the client to get curious. A mutated tool is
quarantined before the next call, not after it.

**On every call**, Warden interrogates the call itself. Is this tool known. Is
it quarantined. Does its contract still match. Does it claim a capability policy
forbids. Are the arguments inside policy, and inside the schema that was
approved. Is it within its budget.

**A refused call is never forwarded.** The upstream tool does not execute.

**Every decision is written down**, allowed and refused alike, with the rule
that produced it, the arguments involved, the fingerprint, and the time.

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

The enforcement engine is independent of transport, and that is not an
aspiration. Every security decision lives in one module that has never heard of
a pipe or a socket. Warden speaks stdio to a local server and HTTP to a remote
one, and both ask the same code the same questions. Two copies would drift, and
the one that drifted would be the one nobody was testing.

## Seeing it work

A tool approved as read-only stops being read-only:

```
hints before: {"readOnlyHint": true,  "openWorldHint": false}
hints after:  {"readOnlyHint": false, "destructiveHint": true, "openWorldHint": true}

ELEVATION
  gave up its read-only guarantee
  claimed the ability to destroy or overwrite data
  claimed the ability to reach outside the local system
QUARANTINED, withheld from the client
```

And a refusal recorded in live use, under Claude Desktop, against a real
third-party server:

```
Refused   files2::write_file   DENIED_SCOPE   24 Sep 2026, 14:30:57
tool declares globally denied scope(s): ['tool.destructive']
arguments: {"content": "test", "path": "...\warden-test2\blocked.txt"}
```

The file was never created. The call never reached the server.

## Installation

Python 3.10 or newer. Warden's only dependency is PyYAML, kept deliberately
minimal, because a security tool's own supply chain is part of your attack
surface.

```bash
git clone https://github.com/coopersaleswelch-bit/Warden2
cd Warden2
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

To protect a server your organization already runs:

```bash
python -m warden.doctor      # checks this machine, reads only, changes nothing
python -m warden.install     # lists configured servers, protects the one you pick
```

For a server reached over the network, Warden runs as a proxy in front of it and
your client points at Warden instead:

```bash
python -m warden.http_proxy --upstream https://example.com/mcp --name acme
```

It binds to loopback unless told otherwise, because a security proxy that is
reachable from the network by accident is a hole rather than a control.

The installer records a server's contracts before it touches any configuration,
backs up the existing config with a timestamp, preserves the server's own
environment variables, and restores the original entry exactly when you run
`--unprotect`.

It refuses rather than guesses. A remote server, a server that will not start, a
server already protected, or a configuration file that is not valid JSON will
all leave your config untouched.

## Two minutes

```bash
python test_warden.py     # 154 checks
python demo_day3.py       # an upgrade accepted, two attacks caught
python demo_day4.py       # run against a real third-party MCP server
```

Watch `demo_day3.py`. Four sessions against a real server, over real pipes:

1. A server is approved and its tools recorded.
2. The vendor ships a genuine new version that gains no capability. Accepted
   automatically, nobody paged.
3. The server changes a tool while still reporting the same version. Caught,
   quarantined, withheld.
4. The server changes a tool and declares a new version. Caught anyway, because
   the change increased what the tool could do.

Step two matters as much as steps three and four. A control that treats every
routine upgrade as an attack gets switched off inside a week, and then it
protects nothing.

## Security model

Warden fails closed. Where a decision cannot be made safely, the call is
refused.

Capability is the gate, not change itself. A change is treated as hostile when
it increases what a tool can do:

- a new permission, or the loss of a read-only guarantee
- a new input field named like a command, a path, a URL, a credential
- a description that grew an instruction aimed at the model
- a claim on destructive or external-world capability

Permissions are derived from the protocol's own behaviour hints, so the rules
work against servers that have never heard of Warden. A tool that does not claim
to be read-only is treated as able to write. The absence of a promise is not a
promise.

Version claims are corroborating evidence, never proof. A server that changes
its tools while reporting an unchanged version is contradicting itself, and
Warden treats that as the strongest signal available. Even so, version trust is
off by default, because real servers do not honour it. The official filesystem
server from the protocol maintainers reports version `0.2.0` while shipping as
package `2026.8.31`, a fact confirmed directly against a live install. With
version trust off, the guarantee is narrower and honest: no tool gains
capability without a human.

## Policy

Rules live in `policy.yaml`. Changing what agents may do requires no code.

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
call budgets. Every setting can be overridden per server.

## Audit

Every decision is written at the moment it is made, carrying what is needed to
reconstruct it later: the verdict, the rule, the tool, the server, the
arguments, the contract fingerprint, the timestamp, and for a drifted contract,
the diff.

`python -m warden.report` renders that record as one self-contained page,
ordered by severity. Quarantined tools first, then refusals, then all clear. A
refusal is never displayed as all clear.

## What Warden does not do yet

Stated plainly, because a security tool that hides its edges has not earned
your trust.

- **HTTP is new and lightly exercised.** It works against a test server over
  real sockets, in both JSON and event-stream form, but has not been run
  against a hosted production server.
- **Verified against three third-party servers.** The official filesystem,
  memory and everything servers. Others will behave in ways these have not.
- **Single node, local state.** No central control plane, no multi-tenancy.
- **No agent identity.** Warden knows which tool and which arguments. It does
  not yet know which agent, or on whose behalf.
- **Not independently audited.**

## Roadmap

None of the following is built. It is listed so the direction is legible.

**Next.** Run the HTTP transport against a hosted server in anger. More
third-party servers, and servers that behave less politely than the official
ones.

**Later.** Agent identity and per-agent policy. Structured export for SIEM and
compliance tooling. Central policy distribution across machines.

**Not yet.** Multi-tenant control plane, RBAC, analytics. These answer questions
no user has asked. Building them before someone runs Warden in anger would be
guessing.

## Development

```bash
python test_warden.py
```

154 checks across the contract model, the capability classifier, the proxy, the
installer and the report. Every bug found so far has a permanent regression
test. `PROGRESS.md` is the build log, including what broke and why.

## Licence

Not yet chosen. All rights reserved by default. Ask before using this anywhere
it matters.

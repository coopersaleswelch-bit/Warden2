# Warden 2.0

**Tool contract enforcement for MCP.**

Every MCP security product on the market inspects a server *before* it runs.
Warden verifies it on *every call*.

---

## The problem

An MCP tool advertises a name, a description, an input schema and a set of
permissions. A server can change any of those at any time — after review, after
approval, after it's already trusted and wired into production systems.

The September 2026 Deadbugz campaign did exactly this: shipped two harmless
tools, then held the payload back until the client had made three tool calls,
specifically so a reviewer checking a new server wouldn't spot it.

Install-time scanning cannot catch that. At install time, nothing is wrong.

Meanwhile the exposure is real: 65% of organizations reported at least one
security incident caused by an AI agent in the past year, 61% of those involving
sensitive data exposure — while only about 21% say they can control their agents
at all.

## What Warden does

Pin the contract at approval. Verify it on every call. Quarantine on drift.

```
agent  ──▶  Warden  ──▶  MCP tool
              │
              ├─ known tool?           else DENY
              ├─ quarantined?          else DENY
              ├─ contract unchanged?   else QUARANTINE + DENY   ← the core check
              ├─ scopes permitted?     else DENY
              ├─ arguments in policy?  else DENY
              ├─ within call budget?   else DENY
              └─ argument shape seen before?  else FLAG
                      │
                      └─▶ audit log (every decision, allowed or not)
```

A denied call does not execute. Not "the model was told not to" — the function
body never runs.

## Not all change is attack

Treating every contract change as hostile means quarantining every routine
software update, which is the same thing as being switched off. Warden asks two
questions instead: did the tool **gain power**, and did the server **admit to
changing**.

| Server version | What changed | Action |
|---|---|---|
| unchanged | anything | Quarantine — the server is contradicting itself |
| bumped | elevation | Quarantine |
| bumped | benign or ambiguous | Accepted automatically, no human |
| unknown | classified, falls back to policy | |

Elevation means a new permission, a new input field named like a command or a
credential, a description that grew an instruction, or a tool losing its
read-only guarantee. A description is prompt context, so text added there is
text injected into the agent.

Warden derives permissions from the MCP behaviour hints (`readOnlyHint`,
`destructiveHint`, `openWorldHint`), so its rules work against servers that
never heard of it. A tool that does not claim to be read-only is treated as
able to write — absence of a promise is not a promise.

**On version trust:** real servers do not reliably bump `serverInfo.version`.
The official filesystem server reports `0.2.0` while shipping as package
`2026.8.31`. So version trust is off by default and set per-server. With it off,
the guarantee is narrower and honest: *no tool gains capability without a human*.

## Why quarantine matters

Blocking one bad call is a guardrail. Quarantining the tool until a human
re-approves it is a control. A reverting server does not silently restore
itself; only a person can. Quarantine is per-tool, so one bad tool doesn't take
down a whole server.

## Running it

Double-click **START WARDEN.bat** and use the menu. Nothing else required.

If Windows shows "Windows protected your PC", click **More info** then
**Run anyway** — that appears for any script downloaded from the internet.

Everything below is what the menu runs, for when you want it directly.

```
pip install -r requirements.txt
```

## Run the demo

```
python demo_deadbugz.py
```

Replays the delayed-mutation attack end to end: approval, three clean calls,
the swap, the block, the persistent quarantine, and human re-approval.

## Run the live proxy demo

```
python demo_live_proxy.py
```

The real thing: a real MCP client, the Warden proxy, and a real MCP server,
all talking JSON-RPC over pipes. The server behaves for three calls, then
swaps a tool. Warden catches it at the moment it's advertised.

## Run the upgrade demo

```
python demo_day3.py
```

Four sessions against a real server: a genuine v1.1.0 release is accepted with
nobody paged, a swap hiding behind an unchanged version is caught, and a swap
carrying an honest version bump is caught anyway.

## Run against a real server

```
python demo_day4.py
```

Warden against `@modelcontextprotocol/server-filesystem` 2026.8.31 — the
official server from the protocol maintainers. Runs live if Node is installed,
otherwise replays that server's own published metadata from `fixtures/`.

## Run the tests

```
python test_warden.py
```

44 checks across the enforcement rules, the classifier and the proxy layer. If this fails,
don't commit.

## Open the evidence report

```
python -m warden.report
```

Writes `warden_report.html` and opens it. Self-contained, no server needed.

## Inspect state

```
python summary.py             # everything
python summary.py contracts   # approved / quarantined tools
python summary.py denials     # what got stopped and why
```

## Configure

All rules live in `policy.yaml`. Change what agents may do without touching
Python.

| Setting | Options | Meaning |
|---|---|---|
| `unknown_tool` | `deny` / `allow` | tool that was never approved |
| `on_drift` | `quarantine` / `block` / `warn` | fallback for any drift case below |
| `on_elevation` | `quarantine` / `block` / `warn` | the tool gained power |
| `on_silent_mutation` | `quarantine` / `block` / `warn` | changed without declaring a version |
| `on_benign_drift` | unset, or an action | strictly less capable |
| `on_ambiguous_drift` | unset, or an action | neither safe nor escalating |
| `auto_repin_on_version_bump` | `true` / `false` | accept declared upgrades that gained nothing |
| `version_is_authoritative` | `true` / `false` | whether this server's version can be trusted (off by default) |
| `on_undeclared_arg` | `deny` / `warn` / `allow` | argument not in the approved schema |
| `on_novel_arg_shape` | `deny` / `warn` / `allow` | never-seen argument shape |
| `baseline_calls` | integer | calls before the baseline is trusted |
| `denied_scopes` | list | scopes no tool may ever declare |

Per-tool rules support `allow_arg_prefixes`, `deny_arg_contains` and
`max_calls`.

## Use in code

```python
from warden import Enforcer, ToolContract, WardenDenied

enforcer = Enforcer()
enforcer.approve(contract)                       # at review time

guarded = enforcer.guard(live_contract, args, agent="research-agent")(call_tool)
try:
    result = guarded(**args)
except WardenDenied as e:
    print(e.decision.reason)
```

## Files

| File | What it holds |
|---|---|
| `warden/contracts.py` | contract model, fingerprinting, drift diffing |
| `warden/registry.py` | approved contracts, quarantine state, arg baselines |
| `warden/policy.py` | YAML policy loading |
| `warden/enforcer.py` | the decision engine and `guard()` |
| `warden/audit.py` | the evidence log |
| `policy.yaml` | the rules |
| `warden/classify.py` | judges whether a change gained power |
| `warden/proxy.py` | the MCP stdio proxy — Warden inline on real traffic |
| `warden/report.py` | the HTML evidence register |
| `mock_server/notes_server.py` | a deliberately hostile MCP server, for testing |
| `demo_deadbugz.py` | the attack replay, no server needed |
| `demo_live_proxy.py` | the same attack over the real protocol |
| `test_warden.py` | the test suite |
| `summary.py` | CLI inspection |

## How to install it in front of a real server

```
python -m warden.proxy --discover --server "python path/to/server.py" --name my-server
```

Run once with `--discover` to pin the server's current tools. Then drop the
`--discover` flag and Warden enforces from that point on.

## Status

Day 4. Tested against `@modelcontextprotocol/server-filesystem` 2026.8.31, a
real third-party server. 44 tests passing.

That test found a hole: Warden had been fingerprinting a metadata schema that
does not exist in real MCP, so a tool silently losing its read-only guarantee
was invisible. Fixed, with tests.

Remaining gap: one third-party server is not enough, and it is a read-only one.
Servers that push `tools/list_changed` notifications mid-session, or run over
HTTP rather than stdio, have not been tried.

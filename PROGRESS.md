# Warden 2.0 — Build Log

The rule: one entry per day worked. Write it even on days where little happened.
The log is the thing that makes consistency visible.

---

## Day 1 — 12 September 2026

**Built the enforcement core.**

Warden 1.0 guarded hand-written Python functions. Warden 2.0 guards MCP tool
contracts, which is the thing enterprises actually have a problem with.

Shipped:

- `ToolContract` — a pinnable snapshot of what a tool claims to be (description,
  input schema, declared scopes), with a canonical SHA-256 fingerprint that is
  stable against JSON key ordering.
- `diff_contracts()` — structured, human-readable explanation of exactly what
  changed between the approved contract and what the server is presenting now.
- `ContractRegistry` — SQLite store of approved contracts, quarantine state, and
  per-tool argument-shape baselines.
- `Policy` / `policy.yaml` — all rules in config, zero code changes to adjust
  what agents may do.
- `Enforcer` — seven-check decision engine, plus `guard()` so a denied call
  genuinely does not execute.
- `AuditLog` — every decision recorded with full drift evidence.
- `demo_deadbugz.py` — replays the September 2026 delayed-mutation attack.
- `test_warden.py` — 21 checks, all passing.
- `summary.py` — CLI inspection.

**Proved today:** a tool that passes review and mutates on call four is caught
on call four, quarantined, and stays dead until a human re-approves it — while
the rest of the server keeps working.

**Not done yet:** nothing is wired to a real MCP server. The contracts in the
demo are constructed in Python.

**Next (Day 2):** stdio proxy that sits between a real MCP client and a real MCP
server, reads the actual `tools/list` response, builds contracts from it, and
enforces on real `tools/call` traffic.

---

## Day 2 — 12 September 2026

**Warden went inline. It is no longer a library, it is a proxy.**

Shipped:

- `warden/proxy.py` — an MCP stdio proxy. Launches the real server as a child
  process and sits between it and the client, speaking JSON-RPC on pipes.
  Two interception points: `tools/list` responses (build and verify contracts)
  and `tools/call` requests (full enforcement, denied calls never forwarded).
- **Discovery mode** (`--discover`) — first run pins whatever the server
  advertises and blocks nothing, so a team can install this without breaking
  anything on day one. Enforcement starts on the second run.
- Drift is now caught at *advertisement* time, not call time. A malicious server
  has to advertise its new capability before it can use it, so Warden quarantines
  the tool before the client makes a single call against the mutated version.
- `mock_server/notes_server.py` — a genuinely hostile MCP server that serves an
  honest tool list for three calls and then swaps `search_notes` for a poisoned
  version. Used to test the proxy against something that actually speaks the
  protocol over a pipe.
- `demo_live_proxy.py` — a real MCP client. Runs the whole chain end to end:
  discovery run, clean enforcement run, three forwarded calls, the mutation, the
  quarantine, the blocked call, and proof the rest of the server still works.
- `warden/report.py` — self-contained HTML evidence register, opens in a browser.
- `START WARDEN.bat` + `START HERE.txt` — double-click launcher with a menu.
  No terminal, no commands, no path hunting.
- Test suite grew from 21 to 30 checks, now covering the proxy layer.

**Two real bugs found and fixed:**

1. `for line in sys.stdin` buffers ahead and deadlocks on a pipe. Every read
   loop is now an explicit `readline()`. This would have been a nightmare to
   diagnose later, with the proxy just silently hanging.
2. SQLite connections cannot be used across threads, and the proxy reads server
   output on its own thread. Both stores now use `check_same_thread=False` with
   an `RLock` around every statement, routed through a single `_exec` helper so
   the lock can't be forgotten in a future method.

**Proved today:** a real MCP client talking to a real MCP server through Warden
gets three calls forwarded, then the server mutates, Warden catches the drift
the moment it is advertised, quarantines that one tool, blocks the call before
it reaches the server, and leaves the rest of the server working.

**Not done yet:** Warden has only been run against a server written for this
project. It has not touched a third-party MCP server in the wild.

---

## Day 3 — (not yet)

Planned:
1. Point Warden at a real third-party MCP server and see what breaks. Real
   servers will have quirks this mock does not — batched responses, notifications
   mid-stream, tools that change legitimately between versions.
2. Handle legitimate version changes: a server upgrade is not an attack, and if
   Warden quarantines on every routine update nobody will keep it installed.
   Probably a signed-manifest or version-pinning escape hatch.
3. Config generator: output the exact JSON snippet to drop Warden into a Claude
   Desktop or other MCP client config, so installing it is copy-paste.

---

## Open questions to answer with real users

- Do teams want drift to quarantine by default, or is that too aggressive for a
  first install? (Discovery mode exists to answer this.)
- Is the audit log or the blocking the thing they'd actually pay for?
- Where does this sit — dev laptops (86% of MCP servers run locally) or the
  production gateway? The answer changes the product shape.

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

## Day 3 — 16 September 2026

**Solved the problem that would have got Warden uninstalled.**

Day 2 treated every contract change as an attack. That is correct and unusable:
a vendor ships v1.1.0, rewords a description, and Warden quarantines a working
tool. Do that twice and the security team switches it off.

The fix is to stop asking "did this change" and start asking two better
questions: **did the tool gain power**, and **did the server admit to changing**.

Shipped:

- `warden/classify.py` — classifies a diff as ELEVATION, BENIGN or AMBIGUOUS.
  Elevation means a new permission, a new input field named like a command or a
  credential, or a description that grew an instruction (the tool-poisoning
  surface: a description is prompt context, so text added there is text injected
  into the agent). No model call, no probability — string and set operations
  over a diff, so an engineer can read the reason and check it by hand.
- **Server version awareness.** The proxy captures `serverInfo.version` from the
  `initialize` handshake and the registry remembers it. This produces the
  strongest signal Warden has: a server that changes its tools while still
  reporting the same version is contradicting its own identity. That is not a
  judgment call, it is a contradiction, and it is the Deadbugz signature.
- **The decision matrix:**

  | version | diff | action |
  |---|---|---|
  | unchanged | anything | quarantine — silent mutation |
  | bumped | elevation | quarantine |
  | bumped | benign or ambiguous | auto re-pin, no human |
  | unknown | classify, fall back to policy | |

- **Schema conformance** (`on_undeclared_arg`) — an argument the approved schema
  never declared is not something the tool was approved to receive. This closes
  the path where a poisoned description smuggles a payload through while the
  schema still looks clean.
- `mock_server` gained `--behaviour honest|upgraded|hostile` and `--version`, so
  a genuine release can be tested alongside the attack.
- `demo_day3.py` — four real sessions proving all three outcomes.
- Tests: 30 to 34.

**Two bugs found by running it rather than by reading it:**

1. The demo looked like it passed while the poison never shipped. Root cause was
   in the mock, not in Warden: hostile mode served v1.0.16 tool shapes while
   claiming v1.1.0, so Warden caught it for being incoherent rather than for
   being malicious. That quarantined `list_notes`, which blocked a call, which
   kept the mutation counter below its threshold. A weaker test that happened to
   go green. The mock now serves the baseline matching the version it claims.
2. `list_notes` was quarantined during the *legitimate* upgrade — exactly the
   false positive this day was meant to fix. Its description grew three words,
   which classified as AMBIGUOUS, which fell back to quarantine. Fixed by making
   elevation the gate: on a declared version bump, ambiguous changes are
   accepted. Changelogs reword things.

**Proved today:** a real v1.1.0 release passed with nobody paged. A swap hiding
behind an unchanged version was caught. A swap carrying an honest version bump
was caught anyway.

**Not done yet:** Warden still has not touched a third-party MCP server in the
wild. Everything so far has been tested against a server written for this
project, which means the tests are only as adversarial as I remembered to be.

---

## Day 4 — (not yet)

Planned:
1. Point Warden at a real public MCP server. Expect breakage: batched responses,
   notifications mid-stream, tools that legitimately change shape per request.
2. Config generator — output the exact JSON snippet to drop Warden into a Claude
   Desktop config, so installing it is copy-paste rather than a command line.
3. Decide what the demo is. The report page is close, but the story a security
   team needs to see in 90 seconds is not yet one screen.

---

## Open questions to answer with real users

- Do teams want drift to quarantine by default, or is that too aggressive for a
  first install? (Discovery mode exists to answer this.)
- Is the audit log or the blocking the thing they'd actually pay for?
- Where does this sit — dev laptops (86% of MCP servers run locally) or the
  production gateway? The answer changes the product shape.

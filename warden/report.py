"""
Warden evidence report.

Writes a single self-contained HTML file and opens it. No server, no browser
extension, no terminal needed afterwards.

The framing is deliberate: this is not a monitoring dashboard, it is a register.
Every line is an attestation about a tool — what it was approved to be, whether
it still is, and what happened when it wasn't. That's the artifact a security
team, an auditor, or a customer asks for.

Run:
    python -m warden.report
"""

from __future__ import annotations

import html
import json
import os
import time
import webbrowser
from pathlib import Path

from .audit import AuditLog
from .registry import QUARANTINED, ContractRegistry

CSS = """
:root {
  --ink: #1b2a33;
  --ink-soft: #52646f;
  --rule: #d6dde2;
  --panel: #eef2f5;
  --paper: #ffffff;
  --allow: #2f6f4f;
  --deny: #a1231f;
  --drift: #9a6410;
}

* { box-sizing: border-box; }

body {
  margin: 0;
  background: var(--panel);
  color: var(--ink);
  font-family: Charter, "Bitstream Charter", "Iowan Old Style", Georgia, serif;
  font-size: 17px;
  line-height: 1.55;
}

.sheet {
  max-width: 62rem;
  margin: 0 auto;
  background: var(--paper);
  min-height: 100vh;
  padding: 3.5rem 3rem 5rem;
  border-left: 1px solid var(--rule);
  border-right: 1px solid var(--rule);
}

.mono {
  font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
  font-size: 0.82em;
  letter-spacing: -0.01em;
}

h1 {
  font-size: 2.1rem;
  font-weight: 600;
  margin: 0 0 0.2rem;
  letter-spacing: -0.02em;
}

.masthead {
  border-bottom: 2px solid var(--ink);
  padding-bottom: 1.1rem;
  margin-bottom: 2.5rem;
}

.masthead p {
  margin: 0;
  color: var(--ink-soft);
  font-size: 0.95rem;
}

h2 {
  font-size: 1.15rem;
  font-weight: 600;
  margin: 3rem 0 0.4rem;
  padding-bottom: 0.35rem;
  border-bottom: 1px solid var(--rule);
}

h2:first-of-type { margin-top: 2rem; }

/* --- the hero: a quarantine notice, stamped --- */

.notice {
  border: 2px solid var(--deny);
  padding: 1.6rem 1.8rem;
  margin-bottom: 2.5rem;
  position: relative;
}

.notice.clear { border-color: var(--allow); }

.notice h3 {
  margin: 0 0 0.5rem;
  font-size: 1.45rem;
  font-weight: 600;
  color: var(--deny);
  letter-spacing: -0.01em;
}

.notice.clear h3 { color: var(--allow); }

.notice p { margin: 0.4rem 0 0; }

.notice .tool {
  font-size: 1.05rem;
  margin-top: 1rem;
  padding-top: 0.9rem;
  border-top: 1px solid var(--rule);
}

.notice .why { color: var(--ink-soft); font-size: 0.95rem; }

/* --- the ledger --- */

.entry {
  border-left: 3px solid var(--rule);
  padding: 0.75rem 0 0.75rem 1.1rem;
  margin: 0 0 0.2rem;
}

.entry.denied { border-left-color: var(--deny); background: #fdf7f6; }
.entry.allowed { border-left-color: var(--allow); }

.entry .head { display: flex; gap: 0.9rem; align-items: baseline; flex-wrap: wrap; }
.entry .verdict { font-weight: 600; }
.entry.denied .verdict { color: var(--deny); }
.entry.allowed .verdict { color: var(--allow); }
.entry .when { color: var(--ink-soft); font-size: 0.85rem; margin-left: auto; }
.entry .why { color: var(--ink-soft); font-size: 0.92rem; margin-top: 0.2rem; }

/* --- the diff --- */

.diff { margin-top: 0.8rem; border: 1px solid var(--rule); }
.diff .row { display: grid; grid-template-columns: 7.5rem 1fr; border-bottom: 1px solid var(--rule); }
.diff .row:last-child { border-bottom: 0; }
.diff .k { padding: 0.55rem 0.8rem; background: var(--panel); font-size: 0.85rem; color: var(--ink-soft); }
.diff .v { padding: 0.55rem 0.8rem; }
.diff .was { color: var(--ink-soft); text-decoration: line-through; }
.diff .now { color: var(--deny); }

/* --- tallies --- */

.tally { display: flex; gap: 2.5rem; margin: 1rem 0 0; padding: 0; list-style: none; }
.tally li { margin: 0; }
.tally .n { font-size: 2rem; font-weight: 600; display: block; line-height: 1.1; }
.tally .lbl { color: var(--ink-soft); font-size: 0.9rem; }

table { width: 100%; border-collapse: collapse; margin-top: 0.8rem; }
th, td { text-align: left; padding: 0.5rem 0.6rem; border-bottom: 1px solid var(--rule); }
th { font-weight: 600; font-size: 0.9rem; color: var(--ink-soft); }

.status-ok { color: var(--allow); }
.status-q { color: var(--deny); font-weight: 600; }

footer { margin-top: 4rem; padding-top: 1.2rem; border-top: 1px solid var(--rule);
         color: var(--ink-soft); font-size: 0.88rem; }

@media (max-width: 640px) {
  .sheet { padding: 2rem 1.2rem 3rem; }
  .diff .row { grid-template-columns: 1fr; }
  .tally { gap: 1.5rem; }
}
"""


def esc(text) -> str:
    return html.escape(str(text))


def when(ts: float) -> str:
    return time.strftime("%d %b %Y, %H:%M:%S", time.localtime(ts))


def render_diff(drift_json: str | None) -> str:
    if not drift_json:
        return ""
    try:
        drift = json.loads(drift_json)
    except (json.JSONDecodeError, TypeError):
        return ""

    rows = []

    if "description" in drift:
        old = drift["description"]["approved"]
        new = drift["description"]["now"]
        i = 0
        while i < min(len(old), len(new)) and old[i] == new[i]:
            i += 1
        added = new[i:].strip()
        rows.append(
            f'<div class="row"><div class="k">description</div><div class="v">'
            f'<span class="was">{esc(old[:70])}</span><br>'
            f'<span class="now">appended: {esc(added[:220])}</span></div></div>'
        )

    if "input_schema" in drift:
        added = drift["input_schema"].get("added_fields") or []
        removed = drift["input_schema"].get("removed_fields") or []
        bits = []
        if added:
            bits.append(f'<span class="now">added {esc(", ".join(added))}</span>')
        if removed:
            bits.append(f'<span class="was">removed {esc(", ".join(removed))}</span>')
        rows.append(
            f'<div class="row"><div class="k">input fields</div>'
            f'<div class="v mono">{" &nbsp; ".join(bits) or "altered"}</div></div>'
        )

    if "declared_scopes" in drift:
        added = drift["declared_scopes"].get("added") or []
        if added:
            rows.append(
                f'<div class="row"><div class="k">permissions</div>'
                f'<div class="v mono now">claimed {esc(", ".join(added))}</div></div>'
            )

    return f'<div class="diff">{"".join(rows)}</div>' if rows else ""


def build_html(registry: ContractRegistry, audit: AuditLog) -> str:
    contracts = registry.all_contracts()
    quarantined = registry.quarantined()
    decisions = audit.recent(200)
    counts = audit.counts()

    # ---- hero ----
    if quarantined:
        tools_html = ""
        for row in quarantined:
            tools_html += (
                f'<div class="tool"><span class="mono">{esc(row["server"])}::'
                f'{esc(row["tool"])}</span>'
                f'<div class="why">{esc(row["status_reason"])}</div></div>'
            )
        hero = (
            f'<div class="notice"><h3>{len(quarantined)} tool'
            f'{"s" if len(quarantined) != 1 else ""} quarantined</h3>'
            f"<p>These tools no longer match the contract they were approved under. "
            f"Every call to them is refused until a person reviews the change and "
            f"re-approves.</p>{tools_html}</div>"
        )
    else:
        hero = (
            f'<div class="notice clear"><h3>All contracts verified</h3>'
            f"<p>Every tool currently advertised matches the contract it was "
            f"approved under. {counts['denied']} call"
            f"{'s' if counts['denied'] != 1 else ''} refused so far.</p></div>"
        )

    # ---- ledger ----
    entries = ""
    for row in decisions:
        cls = "allowed" if row["allowed"] else "denied"
        verdict = "Allowed" if row["allowed"] else "Refused"
        args = row["args"]
        entries += (
            f'<div class="entry {cls}">'
            f'<div class="head">'
            f'<span class="verdict">{verdict}</span>'
            f'<span class="mono">{esc(row["server"])}::{esc(row["tool"])}</span>'
            f'<span class="mono" style="color:var(--ink-soft)">{esc(row["code"])}</span>'
            f'<span class="when">{when(row["ts"])}</span>'
            f"</div>"
            f'<div class="why">{esc(row["reason"])}</div>'
            f'<div class="why mono">arguments: {esc(args)}</div>'
            f"{render_diff(row['drift'])}"
            f"</div>"
        )
    if not entries:
        entries = (
            '<p style="color:var(--ink-soft)">No decisions recorded yet. '
            "Run a demo or point the proxy at a server, then refresh this page.</p>"
        )

    # ---- registry table ----
    rows = ""
    for c in contracts:
        q = c["status"] == QUARANTINED
        rows += (
            f"<tr><td class='mono'>{esc(c['server'])}::{esc(c['tool'])}</td>"
            f"<td class='{'status-q' if q else 'status-ok'}'>"
            f"{'Quarantined' if q else 'Approved'}</td>"
            f"<td class='mono'>{esc(c['fingerprint'][:16])}</td>"
            f"<td>{when(c['pinned_at'])}</td></tr>"
        )
    if not rows:
        rows = "<tr><td colspan='4'>Nothing approved yet.</td></tr>"

    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Warden register</title>
<style>{CSS}</style>
</head><body>
<div class="sheet">

  <div class="masthead">
    <h1>Warden register</h1>
    <p>Tool contract enforcement for MCP &nbsp;|&nbsp; generated {when(time.time())}</p>
  </div>

  {hero}

  <h2>Tally</h2>
  <ul class="tally">
    <li><span class="n">{counts['total']}</span><span class="lbl">decisions</span></li>
    <li><span class="n">{counts['allowed']}</span><span class="lbl">allowed</span></li>
    <li><span class="n" style="color:var(--deny)">{counts['denied']}</span><span class="lbl">refused</span></li>
    <li><span class="n">{len(contracts)}</span><span class="lbl">tools under contract</span></li>
  </ul>

  <h2>Tools under contract</h2>
  <table>
    <tr><th>Tool</th><th>Status</th><th>Fingerprint</th><th>Approved</th></tr>
    {rows}
  </table>

  <h2>Decision ledger</h2>
  {entries}

  <footer>
    Every line here was written at the moment of the decision, before the outcome
    was known. Warden refuses a call by never forwarding it, so a refused call did
    not run.
  </footer>

</div></body></html>"""


def generate(
    registry_db: str = "warden_registry.db",
    audit_db: str = "warden_audit.db",
    out: str = "warden_report.html",
    open_browser: bool = True,
) -> str:
    registry = ContractRegistry(registry_db)
    audit = AuditLog(audit_db)
    markup = build_html(registry, audit)
    registry.close()
    audit.close()

    path = Path(out).resolve()
    path.write_text(markup, encoding="utf-8")

    if open_browser:
        try:
            webbrowser.open(path.as_uri())
        except Exception:
            pass

    return str(path)


if __name__ == "__main__":
    location = generate(open_browser=bool(os.environ.get("WARDEN_OPEN", "1") == "1"))
    print(f"Report written to {location}")

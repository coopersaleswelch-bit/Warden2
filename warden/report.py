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
import sys
import time
import webbrowser
from pathlib import Path

from .audit import AuditLog
from .paths import audit_db, has_live_data, registry_db
from .registry import QUARANTINED, ContractRegistry

# The Warden mark. Two sizes: the header version keeps the ridge and grille,
# the small version drops them because detail that reads at 250px turns to mud
# at 16px. A logo is a family, not one drawing.
MARK_FULL = """<svg viewBox="0 0 100 100" width="46" height="46" aria-label="Warden">
<polygon points="50,3 93,15 93,45 84,68 50,97 16,68 7,45 7,15" fill="#0d2233" stroke="#d8a244" stroke-width="3"/>
<polygon points="50,3 7,15 7,45 16,68 50,97" fill="#163449"/>
<polygon points="18,38 82,38 78,44 22,44" fill="#0b1c29"/>
<polygon points="20,46 80,46 76,64 24,64" fill="#d8a244"/>
<polygon points="26,51 74,51 71,59 29,59" fill="#0b1c29"/>
<rect x="44" y="51" width="12" height="8" fill="#f0c070"/>
<rect x="38" y="70" width="4" height="9" fill="#b5822a"/>
<rect x="48" y="70" width="4" height="11" fill="#b5822a"/>
<rect x="58" y="70" width="4" height="9" fill="#b5822a"/>
</svg>"""

FAVICON = (
    "data:image/svg+xml;utf8,"
    "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'>"
    "<polygon points='50,3 93,15 93,45 84,68 50,97 16,68 7,45 7,15' fill='%230b1c29'/>"
    "<polygon points='18,44 82,44 78,66 22,66' fill='%23d8a244'/>"
    "<polygon points='24,50 76,50 73,60 27,60' fill='%230b1c29'/>"
    "<rect x='42' y='50' width='16' height='10' fill='%23f0c070'/></svg>"
)

CSS = """
:root {
  --hull: #0b1c29;
  --panel: #12293a;
  --facet: #163449;
  --edge: #27455a;
  --brass: #d8a244;
  --brass-deep: #b5822a;
  --optic: #f0c070;
  --bone: #f4f0e8;
  --dim: #9fb2be;
  --deny: #e0685c;
  --allow: #7fc8a0;
}

* { box-sizing: border-box; }

body {
  margin: 0;
  background: var(--hull);
  color: var(--bone);
  font-family: Archivo, "Segoe UI", system-ui, sans-serif;
  font-size: 16px;
  line-height: 1.55;
}

.sheet { max-width: 64rem; margin: 0 auto; padding: 3rem 2.5rem 5rem; }

.mono {
  font-family: "IBM Plex Mono", ui-monospace, Consolas, monospace;
  font-size: 0.85em;
}

/* --- masthead --- */

.masthead {
  display: flex; align-items: center; gap: 1rem;
  border-bottom: 2px solid var(--brass-deep);
  padding-bottom: 1.1rem; margin-bottom: 2.2rem;
}
.masthead h1 {
  margin: 0; font-size: 2rem; font-weight: 900; letter-spacing: -0.04em;
}
.masthead .sub {
  margin-left: auto; text-align: right;
  color: var(--dim); font-size: 0.82rem; line-height: 1.4;
}
.masthead .tagline {
  font-size: 0.78rem; letter-spacing: 0.1em; color: var(--brass);
  font-family: "IBM Plex Mono", monospace;
}

h2 {
  font-size: 0.78rem; font-weight: 600; letter-spacing: 0.14em;
  color: var(--dim); text-transform: uppercase;
  margin: 2.6rem 0 0.8rem;
  font-family: "IBM Plex Mono", monospace;
}

/* --- the headline state --- */

.notice { border-left: 4px solid var(--deny); background: var(--panel); padding: 1.5rem 1.7rem; }
.notice.clear { border-left-color: var(--allow); }
.notice.watch { border-left-color: var(--brass); }
.notice h3 { margin: 0 0 0.4rem; font-size: 1.6rem; font-weight: 800; letter-spacing: -0.03em; color: var(--deny); }
.notice.clear h3 { color: var(--allow); }
.notice.watch h3 { color: var(--brass); }
.notice p { margin: 0.3rem 0 0; color: #cfdae2; }
.notice .tool { margin-top: 1rem; padding-top: 0.9rem; border-top: 1px solid var(--edge); }
.notice .why { color: var(--dim); font-size: 0.92rem; }

/* --- tally --- */

.tally { display: flex; gap: 2.6rem; margin: 0; padding: 0; list-style: none; }
.tally .n { font-size: 2.3rem; font-weight: 900; letter-spacing: -0.04em; display: block; line-height: 1.05; }
.tally .lbl { color: var(--dim); font-size: 0.85rem; }

/* --- ledger --- */

.entry { border-left: 3px solid var(--edge); background: var(--panel); padding: 0.9rem 1.1rem; margin-bottom: 0.4rem; }
.entry.denied { border-left-color: var(--deny); background: #2a1f22; }
.entry.allowed { border-left-color: var(--allow); }
.entry .head { display: flex; gap: 0.9rem; align-items: baseline; flex-wrap: wrap; }
.entry .verdict { font-weight: 800; letter-spacing: -0.01em; }
.entry.denied .verdict { color: var(--deny); }
.entry.allowed .verdict { color: var(--allow); }
.entry .when { color: var(--dim); font-size: 0.8rem; margin-left: auto; }
.entry .why { color: #cfdae2; font-size: 0.93rem; margin-top: 0.2rem; }

/* --- diff --- */

.diff { margin-top: 0.8rem; border: 1px solid var(--edge); }
.diff .row { display: grid; grid-template-columns: 8rem 1fr; border-bottom: 1px solid var(--edge); }
.diff .row:last-child { border-bottom: 0; }
.diff .k { padding: 0.5rem 0.8rem; background: var(--facet); font-size: 0.82rem; color: var(--dim); }
.diff .v { padding: 0.5rem 0.8rem; }
.diff .was { color: var(--dim); text-decoration: line-through; }
.diff .now { color: var(--deny); }

/* --- table --- */

table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 0.55rem 0.7rem; border-bottom: 1px solid var(--edge); }
th { font-size: 0.78rem; letter-spacing: 0.1em; color: var(--dim); font-family: "IBM Plex Mono", monospace; text-transform: uppercase; }
.status-ok { color: var(--allow); }
.status-q { color: var(--deny); font-weight: 700; }

footer { margin-top: 3.5rem; padding-top: 1.2rem; border-top: 1px solid var(--edge); color: var(--dim); font-size: 0.88rem; }

@media (max-width: 640px) {
  .sheet { padding: 1.6rem 1.1rem 3rem; }
  .masthead { flex-wrap: wrap; }
  .masthead .sub { margin-left: 0; text-align: left; width: 100%; }
  .diff .row { grid-template-columns: 1fr; }
  .tally { gap: 1.4rem; flex-wrap: wrap; }
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


def build_html(registry: ContractRegistry, audit: AuditLog, source: str = "") -> str:
    contracts = registry.all_contracts()
    quarantined = registry.quarantined()
    decisions = audit.recent(200)
    counts = audit.counts()

    # ---- headline ----
    #
    # Three states, not two. The old version said "All contracts verified"
    # whenever nothing had drifted - even with refusals on the page. Both
    # statements were true, but the most important thing that happened was
    # not the thing the top of the page announced.
    if quarantined:
        tools_html = ""
        for row in quarantined:
            tools_html += (
                f'<div class="tool"><span class="mono">{esc(row["server"])}::'
                f'{esc(row["tool"])}</span>'
                f'<div class="why">{esc(row["status_reason"])}</div></div>'
            )
        plural = "s" if len(quarantined) != 1 else ""
        hero = (
            f'<div class="notice"><h3>{len(quarantined)} tool{plural} quarantined</h3>'
            f"<p>These tools no longer match the contract they were approved under. "
            f"Every call to them is refused, and they are withheld from the client "
            f"entirely, until a person reviews the change and re-approves.</p>"
            f"{tools_html}</div>"
        )
    elif counts["denied"]:
        plural = "s" if counts["denied"] != 1 else ""
        hero = (
            f'<div class="notice watch"><h3>{counts["denied"]} call{plural} refused</h3>'
            f"<p>No tool has drifted from its approved contract. These calls were "
            f"stopped by policy — the tool asked for something it is not permitted "
            f"to do. Each one is in the ledger below with the rule that stopped it.</p>"
            f"</div>"
        )
    else:
        hero = (
            f'<div class="notice clear"><h3>All contracts verified</h3>'
            f"<p>Every tool currently advertised matches the contract it was "
            f"approved under, and nothing has been refused.</p></div>"
        )

    # ---- ledger ----
    entries = ""
    for row in decisions:
        cls = "allowed" if row["allowed"] else "denied"
        if row["code"] == "VERSION_UPGRADE_ACCEPTED":
            verdict = "Upgrade accepted"
        elif row["code"] == "SILENT_MUTATION":
            verdict = "Refused - silent mutation"
        else:
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
<link rel="icon" href="{FAVICON}">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Archivo:wght@400;500;600;800;900&amp;family=IBM+Plex+Mono:wght@400;600&amp;display=swap">
<style>{CSS}</style>
</head><body>
<div class="sheet">

  <div class="masthead">
    {MARK_FULL}
    <div>
      <h1>WARDEN</h1>
      <div class="tagline">TOOL CONTRACT ENFORCEMENT</div>
    </div>
    <div class="sub">generated {when(time.time())}<br>{esc(source) if source else ""}</div>
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


def choose_source(demo: bool = False) -> tuple[str, str, str]:
    """
    Which databases to read.

    Live data - written while Claude Desktop actually used a protected server -
    is what matters once Warden is installed, so it wins by default. The demos
    write to the project folder instead, and --demo asks for those.

    Returns (registry path, audit path, a label for the page).
    """
    if not demo and has_live_data():
        return str(registry_db()), str(audit_db()), "live data"
    return "warden_registry.db", "warden_audit.db", "demo runs in the project folder"


def generate(
    registry_db_path: str = "warden_registry.db",
    audit_db_path: str = "warden_audit.db",
    out: str = "warden_report.html",
    open_browser: bool = True,
    source: str = "",
) -> str:
    registry = ContractRegistry(registry_db_path)
    audit = AuditLog(audit_db_path)
    markup = build_html(registry, audit, source)
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
    demo_mode = "--demo" in sys.argv
    reg, aud, label = choose_source(demo_mode)
    print(f"  Showing {label}")
    print(f"  from {aud}")
    location = generate(
        reg, aud,
        open_browser=bool(os.environ.get("WARDEN_OPEN", "1") == "1"),
        source=label,
    )
    print(f"  Report written to {location}")
    if not demo_mode and label == "live data":
        print("  (run with --demo to see the demo runs instead)")

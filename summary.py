"""
Warden 2.0 — command line summary.

Quick look at what Warden is currently protecting and what it has stopped,
without opening a database browser or the dashboard.

Usage:
    python summary.py               # everything
    python summary.py contracts     # approved / quarantined tools only
    python summary.py denials       # denied calls only
"""

from __future__ import annotations

import sys
import time

from warden.audit import AuditLog
from warden.report import choose_source
from warden.registry import ContractRegistry, QUARANTINED

LINE = "-" * 74


def ts(value: float | None) -> str:
    if not value:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(value))


def show_contracts(registry: ContractRegistry) -> None:
    rows = registry.all_contracts()
    print(f"\n{LINE}\nREGISTERED TOOLS ({len(rows)})\n{LINE}")
    if not rows:
        print("  nothing approved yet")
        return
    for r in rows:
        marker = "!!" if r["status"] == QUARANTINED else "ok"
        print(f"  [{marker}] {r['server']}::{r['tool']}")
        print(f"       status      {r['status']}")
        print(f"       fingerprint {r['fingerprint'][:12]}")
        print(f"       pinned      {ts(r['pinned_at'])}")
        if r["status"] == QUARANTINED:
            print(f"       reason      {r['status_reason']}")
        print()


def show_denials(audit: AuditLog, limit: int = 25) -> None:
    rows = audit.denials(limit)
    print(f"\n{LINE}\nRECENT DENIALS ({len(rows)})\n{LINE}")
    if not rows:
        print("  no denials recorded")
        return
    for r in rows:
        print(f"  {ts(r['ts'])}  {r['server']}::{r['tool']}")
        print(f"     agent  {r['agent']}")
        print(f"     rule   {r['code']}")
        print(f"     why    {r['reason']}")
        print(f"     args   {r['args']}")
        print()


def show_counts(audit: AuditLog) -> None:
    counts = audit.counts()
    print(f"\n{LINE}\nDECISION TOTALS\n{LINE}")
    print(f"  total   {counts['total']}")
    print(f"  allowed {counts['allowed']}")
    print(f"  denied  {counts['denied']}")
    rows = audit.by_code()
    if rows:
        print("\n  by rule:")
        for r in rows:
            print(f"    {r['code']:<24} {r['n']}")
    print()


def main() -> None:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    what = args[0].lower() if args else "all"
    reg_path, aud_path, label = choose_source("--demo" in sys.argv)
    print(f"\n  Showing {label}")
    registry = ContractRegistry(reg_path)
    audit = AuditLog(aud_path)

    if what in ("all", "contracts"):
        show_contracts(registry)
    if what in ("all", "denials"):
        show_denials(audit)
    if what in ("all", "counts"):
        show_counts(audit)

    registry.close()
    audit.close()


if __name__ == "__main__":
    main()

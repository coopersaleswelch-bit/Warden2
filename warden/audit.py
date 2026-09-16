"""
The audit log.

Warden's second product, hiding inside the first. Blocking is what engineers
want. A defensible record of what every agent tried to do, what was allowed,
what was stopped and why, is what security teams, auditors and customers want.
Same data, two buyers.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS decisions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           REAL NOT NULL,
    session      TEXT NOT NULL,
    agent        TEXT NOT NULL,
    server       TEXT NOT NULL,
    tool         TEXT NOT NULL,
    allowed      INTEGER NOT NULL,
    code         TEXT NOT NULL,
    reason       TEXT NOT NULL,
    args         TEXT NOT NULL,
    fingerprint  TEXT,
    drift        TEXT
);
CREATE INDEX IF NOT EXISTS idx_decisions_ts ON decisions(ts);
CREATE INDEX IF NOT EXISTS idx_decisions_tool ON decisions(server, tool);
"""


class AuditLog:
    def __init__(self, db_path: str | Path = "warden_audit.db"):
        self.db_path = str(db_path)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def _exec(self, sql: str, params: tuple = ()):
        """Every statement goes through here so the lock is never forgotten."""
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur

    def record(
        self,
        *,
        session: str,
        agent: str,
        server: str,
        tool: str,
        allowed: bool,
        code: str,
        reason: str,
        args: dict,
        fingerprint: str | None = None,
        drift: dict | None = None,
    ) -> int:
        cur = self._exec(
            """
            INSERT INTO decisions
                (ts, session, agent, server, tool, allowed, code, reason, args, fingerprint, drift)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                time.time(),
                session,
                agent,
                server,
                tool,
                1 if allowed else 0,
                code,
                reason,
                json.dumps(args, default=str),
                fingerprint,
                json.dumps(drift, default=str) if drift else None,
            ),
        )
        return int(cur.lastrowid)

    def recent(self, limit: int = 50) -> list[sqlite3.Row]:
        return self._exec(
            "SELECT * FROM decisions ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()

    def denials(self, limit: int = 50) -> list[sqlite3.Row]:
        return self._exec(
            "SELECT * FROM decisions WHERE allowed = 0 ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()

    def counts(self) -> dict:
        row = self._exec(
            """
            SELECT
                COUNT(*) AS total,
                COALESCE(SUM(allowed), 0) AS allowed,
                COUNT(*) - COALESCE(SUM(allowed), 0) AS denied
            FROM decisions
            """
        ).fetchone()
        return {"total": row["total"], "allowed": row["allowed"], "denied": row["denied"]}

    def by_code(self) -> list[sqlite3.Row]:
        return self._exec(
            "SELECT code, COUNT(*) AS n FROM decisions GROUP BY code ORDER BY n DESC"
        ).fetchall()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

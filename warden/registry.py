"""
The contract registry: Warden's memory of what each tool was approved to be.

Status model:
    APPROVED    - pinned, verified, callable
    QUARANTINED - drifted or manually pulled; every call denied until re-approved

Quarantine is the part that matters commercially. Blocking a single bad call is
a guardrail. Quarantining the tool until a human re-approves it is a control.
Security teams buy controls.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

from .contracts import ToolContract

APPROVED = "APPROVED"
QUARANTINED = "QUARANTINED"

SCHEMA = """
CREATE TABLE IF NOT EXISTS contracts (
    key             TEXT PRIMARY KEY,
    server          TEXT NOT NULL,
    tool            TEXT NOT NULL,
    description     TEXT NOT NULL,
    input_schema    TEXT NOT NULL,
    declared_scopes TEXT NOT NULL,
    title           TEXT NOT NULL DEFAULT '',
    annotations     TEXT NOT NULL DEFAULT '{}',
    output_schema   TEXT NOT NULL DEFAULT '{}',
    fingerprint     TEXT NOT NULL,
    status          TEXT NOT NULL,
    pinned_at       REAL NOT NULL,
    status_reason   TEXT,
    status_changed  REAL
);

CREATE TABLE IF NOT EXISTS baselines (
    key         TEXT NOT NULL,
    arg_keys    TEXT NOT NULL,
    seen_count  INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (key, arg_keys)
);

CREATE TABLE IF NOT EXISTS servers (
    server      TEXT PRIMARY KEY,
    version     TEXT,
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL
);
"""


class ContractRegistry:
    def __init__(self, db_path: str | Path = "warden_registry.db"):
        self.db_path = str(db_path)
        # check_same_thread=False: the proxy reads server output on a separate
        # thread from the one handling client requests. The lock below is what
        # actually keeps that safe.
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._migrate()
            self._conn.commit()

    def _migrate(self) -> None:
        """
        Add columns introduced after a database was first created.

        CREATE TABLE IF NOT EXISTS silently does nothing on an existing table,
        so a registry written by an earlier version would keep working while
        missing the columns - and then fail on read. Cheap to check, and it
        means nobody has to delete their approved contracts to upgrade.
        """
        existing = {
            r["name"]
            for r in self._conn.execute("PRAGMA table_info(contracts)").fetchall()
        }
        for column, default in (
            ("title", "''"),
            ("annotations", "'{}'"),
            ("output_schema", "'{}'"),
        ):
            if column not in existing:
                self._conn.execute(
                    f"ALTER TABLE contracts ADD COLUMN {column} TEXT NOT NULL "
                    f"DEFAULT {default}"
                )

    def _exec(self, sql: str, params: tuple = ()):
        """Every statement goes through here so the lock is never forgotten."""
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur

    # ---------- pinning ----------

    def pin(self, contract: ToolContract, reason: str = "initial approval") -> None:
        """Approve a contract as the reference version of this tool."""
        row = contract.to_row()
        self._exec(
            """
            INSERT INTO contracts
                (key, server, tool, description, input_schema, declared_scopes,
                 title, annotations, output_schema,
                 fingerprint, status, pinned_at, status_reason, status_changed)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                description=excluded.description,
                input_schema=excluded.input_schema,
                declared_scopes=excluded.declared_scopes,
                title=excluded.title,
                annotations=excluded.annotations,
                output_schema=excluded.output_schema,
                fingerprint=excluded.fingerprint,
                status=excluded.status,
                pinned_at=excluded.pinned_at,
                status_reason=excluded.status_reason,
                status_changed=excluded.status_changed
            """,
            (
                contract.key,
                row["server"],
                row["tool"],
                row["description"],
                row["input_schema"],
                row["declared_scopes"],
                row["title"],
                row["annotations"],
                row["output_schema"],
                row["fingerprint"],
                APPROVED,
                time.time(),
                reason,
                time.time(),
            ),
        )

    def get(self, server: str, tool: str) -> sqlite3.Row | None:
        return self._exec(
            "SELECT * FROM contracts WHERE key = ?", (f"{server}::{tool}",)
        ).fetchone()

    def get_contract(self, server: str, tool: str) -> ToolContract | None:
        row = self.get(server, tool)
        return ToolContract.from_row(dict(row)) if row else None

    def is_known(self, server: str, tool: str) -> bool:
        return self.get(server, tool) is not None

    # ---------- quarantine ----------

    def quarantine(self, server: str, tool: str, reason: str) -> None:
        self._exec(
            "UPDATE contracts SET status=?, status_reason=?, status_changed=? WHERE key=?",
            (QUARANTINED, reason, time.time(), f"{server}::{tool}"),
        )

    def is_quarantined(self, server: str, tool: str) -> bool:
        row = self.get(server, tool)
        return bool(row and row["status"] == QUARANTINED)

    def reapprove(self, contract: ToolContract, reason: str = "human re-approval") -> None:
        """Explicit human action: accept the new contract as the new reference."""
        self.pin(contract, reason=reason)

    # ---------- server version ----------

    def record_server_version(self, server: str, version: str | None) -> str | None:
        """
        Remember what version a server says it is. Returns the version we had
        on record BEFORE this call, so the caller can tell an upgrade from a
        silent swap.

        A server that changes its tools without changing its version is
        contradicting itself, and that is the single strongest signal Warden
        has. Nothing about it is heuristic.
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT version FROM servers WHERE server = ?", (server,)
            ).fetchone()
            previous = row["version"] if row else None

            now = time.time()
            self._conn.execute(
                """
                INSERT INTO servers (server, version, first_seen, last_seen)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(server) DO UPDATE SET
                    version = excluded.version,
                    last_seen = excluded.last_seen
                """,
                (server, version, now, now),
            )
            self._conn.commit()

        return previous

    def get_server_version(self, server: str) -> str | None:
        row = self._exec(
            "SELECT version FROM servers WHERE server = ?", (server,)
        ).fetchone()
        return row["version"] if row else None

    # ---------- behavioural baseline ----------

    def record_arg_shape(self, server: str, tool: str, arg_keys: list[str]) -> None:
        shape = json.dumps(sorted(arg_keys))
        self._exec(
            """
            INSERT INTO baselines (key, arg_keys, seen_count) VALUES (?, ?, 1)
            ON CONFLICT(key, arg_keys) DO UPDATE SET seen_count = seen_count + 1
            """,
            (f"{server}::{tool}", shape),
        )

    def known_arg_shapes(self, server: str, tool: str) -> list[list[str]]:
        rows = self._exec(
            "SELECT arg_keys FROM baselines WHERE key = ?", (f"{server}::{tool}",)
        ).fetchall()
        return [json.loads(r["arg_keys"]) for r in rows]

    def call_count(self, server: str, tool: str) -> int:
        row = self._exec(
            "SELECT COALESCE(SUM(seen_count), 0) AS n FROM baselines WHERE key = ?",
            (f"{server}::{tool}",),
        ).fetchone()
        return int(row["n"])

    # ---------- reporting ----------

    def all_contracts(self) -> list[sqlite3.Row]:
        return self._exec(
            "SELECT * FROM contracts ORDER BY server, tool"
        ).fetchall()

    def quarantined(self) -> list[sqlite3.Row]:
        return self._exec(
            "SELECT * FROM contracts WHERE status = ? ORDER BY status_changed DESC",
            (QUARANTINED,),
        ).fetchall()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

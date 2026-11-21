"""Atomic, durable, SQLite-backed budget and replay reservations.

This is an integration building block, NOT a payment processor. The caller
must retain sole custody of this database, serialize payment-provider actions
with its own idempotency key, and reconcile settlement independently.
"""
import os
import sqlite3
from decimal import Decimal


class SQLiteReplayStore:
    """Persistent single-host reservation ledger with SQLite write locking.

    Must live on a LOCAL filesystem, not NFS or other distributed mounts.
    All workers serving the same payment account must share the same database.
    For multi-host deployments use a transactional database service instead.
    """

    def __init__(self, path: str):
        if not isinstance(path, str) or not path.strip() or path == ":memory:":
            raise ValueError("A durable SQLite file path is required")
        self.path = path
        with self._connect() as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS reservations (
                request_id TEXT PRIMARY KEY,
                nonce TEXT UNIQUE,
                payee_id TEXT NOT NULL,
                utc_day TEXT NOT NULL,
                cents INTEGER NOT NULL CHECK(cents > 0),
                created_at INTEGER NOT NULL
            )""")
            conn.execute("CREATE INDEX IF NOT EXISTS reservations_day ON reservations(utc_day)")

    def _connect(self):
        conn = sqlite3.connect(self.path, timeout=15, isolation_level=None)
        conn.execute("PRAGMA busy_timeout=15000")
        return conn

    @staticmethod
    def _cents(amount: Decimal) -> int:
        value = amount * 100
        # SQLite INTEGER is 64-bit signed. Leave generous headroom for sums.
        if value <= 0 or value > 9_000_000_000_000_000:
            raise ValueError("Out of supported range")
        return int(value)

    def reserve(self, request_id: str, nonce: str | None, payee_id: str,
                utc_day: str, amount: Decimal, daily_cap: Decimal, now: int):
        """Atomically reserve against replay and daily cap.

        Returns (allowed, reason). Rejections do not consume money or a nonce.
        A successful reservation cannot be reused even after a process restart.
        Fail closed on database errors; never return an allowance on an error.
        """
        try:
            cents = self._cents(amount)
            cap_cents = self._cents(daily_cap)
            with self._connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                duplicate = conn.execute(
                    "SELECT 1 FROM reservations WHERE request_id = ? OR (nonce IS NOT NULL AND nonce = ?) LIMIT 1",
                    (request_id, nonce),
                ).fetchone()
                if duplicate:
                    conn.execute("ROLLBACK")
                    return False, "Replay or duplicate request"
                total = conn.execute(
                    "SELECT COALESCE(SUM(cents), 0) FROM reservations WHERE utc_day = ?",
                    (utc_day,),
                ).fetchone()[0]
                if total > cap_cents - cents:
                    conn.execute("ROLLBACK")
                    return False, "Daily spending cap exceeded"
                conn.execute(
                    "INSERT INTO reservations(request_id, nonce, payee_id, utc_day, cents, created_at) VALUES(?, ?, ?, ?, ?, ?)",
                    (request_id, nonce, payee_id, utc_day, cents, now),
                )
                conn.execute("COMMIT")
                return True, "Policy reservation passed; backend must enforce payment outcome"
        except (sqlite3.Error, ValueError, TypeError, OverflowError):
            return False, "Reservation ledger unavailable or invalid"

"""Offline-only provider outcome journal sharing the guard's SQLite database.

The caller must verify provider event authenticity BEFORE calling record().
No network transport, financial integration, refund execution, or budget release.
"""
from contextlib import closing
import sqlite3


class ProviderOutcomeJournal:
    # Unknown outcomes must be reconciled, never silently retried.
    TRANSITIONS = {
        None: {"pending", "accepted", "rejected", "unknown"},
        "unknown": {"pending", "accepted", "rejected", "settled"},
        "pending": {"accepted", "rejected", "settled", "unknown"},
        "accepted": {"settled", "rejected", "unknown"},
        "settled": {"refunded", "partially_refunded", "disputed"},
        "partially_refunded": {"refunded", "disputed"},
        "disputed": {"refunded"},
        "rejected": set(),
        "refunded": set(),
    }

    def __init__(self, db_path):
        if not isinstance(db_path, str) or not db_path.strip() or db_path == ":memory:":
            raise ValueError("Durable guard database path required")
        self.path = db_path
        with closing(self._connect()) as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS provider_outcomes (
                request_id TEXT PRIMARY KEY,
                reference TEXT NOT NULL,
                status TEXT NOT NULL
            )""")
            conn.execute("""CREATE TABLE IF NOT EXISTS provider_events (
                event_id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL,
                reference TEXT NOT NULL,
                status TEXT NOT NULL
            )""")

    def _connect(self):
        conn = sqlite3.connect(self.path, timeout=15, isolation_level=None)
        conn.execute("PRAGMA busy_timeout=15000")
        return conn

    def record(self, *, event_id, request_id, reference, status):
        """Append verified provider event; never release spending reservations.

        Returns False if event is invalid, duplicated, references an unreserved
        request, or attempts an illegal transition. Fails closed on DB errors.
        """
        if (not all(isinstance(v, str) and 0 < len(v) <= 256 and v.strip()
                    for v in (event_id, request_id, reference))
                or status not in set().union(*self.TRANSITIONS.values())):
            return False
        try:
            with closing(self._connect()) as conn:
                conn.execute("BEGIN IMMEDIATE")
                if conn.execute("SELECT 1 FROM provider_events WHERE event_id=?", (event_id,)).fetchone():
                    conn.execute("ROLLBACK")
                    return False
                if not conn.execute("SELECT 1 FROM reservations WHERE request_id=?", (request_id,)).fetchone():
                    conn.execute("ROLLBACK")
                    return False
                prev = conn.execute(
                    "SELECT status, reference FROM provider_outcomes WHERE request_id=?",
                    (request_id,),
                ).fetchone()
                if (prev and prev[1] != reference) or status not in self.TRANSITIONS[prev[0] if prev else None]:
                    conn.execute("ROLLBACK")
                    return False
                conn.execute(
                    "INSERT INTO provider_events(event_id, request_id, reference, status) VALUES (?, ?, ?, ?)",
                    (event_id, request_id, reference, status),
                )
                conn.execute(
                    "INSERT INTO provider_outcomes(request_id, reference, status) VALUES (?, ?, ?) "
                    "ON CONFLICT(request_id) DO UPDATE SET status=excluded.status",
                    (request_id, reference, status),
                )
                conn.execute("COMMIT")
                return True
        except (sqlite3.Error, ValueError, TypeError):
            return False

    def lookup(self, request_id):
        try:
            with closing(self._connect()) as conn:
                row = conn.execute(
                    "SELECT reference, status FROM provider_outcomes WHERE request_id=?",
                    (request_id,),
                ).fetchone()
                return {"reference": row[0], "status": row[1]} if row else None
        except sqlite3.Error:
            return None

"""Offline synthetic lifecycle reconciliation tests. No provider credentials."""
import os
import tempfile
import unittest
from decimal import Decimal
from durable_store import SQLiteReplayStore
from reconciliation import ProviderOutcomeJournal


class OutcomeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "guard.sqlite")
        self.store = SQLiteReplayStore(self.path)
        self.assertTrue(self.store.reserve(
            "req-1", "nonce-1", "fake-payee", "2026-11-21",
            Decimal("20"), Decimal("25"), 1795280000
        )[0])
        self.journal = ProviderOutcomeJournal(self.path)

    def event(self, status, eid, rid="req-1", ref="mock-ref-1"):
        return self.journal.record(event_id=eid, request_id=rid,
                                   reference=ref, status=status)

    def test_pending_to_settled_to_refunded_without_budget_release(self):
        self.assertTrue(self.event("pending", "evt-1"))
        self.assertTrue(self.event("accepted", "evt-2"))
        self.assertTrue(self.event("settled", "evt-3"))
        self.assertTrue(self.event("refunded", "evt-4"))
        self.assertEqual(self.journal.lookup("req-1")["status"], "refunded")
        self.assertFalse(self.store.reserve(
            "req-1", "nonce-1", "fake-payee", "2026-11-21",
            Decimal("20"), Decimal("25"), 1795280000
        )[0])
        # Refunds cannot grant an additional budget allowance automatically.
        self.assertFalse(self.store.reserve(
            "req-2", "nonce-2", "fake-payee", "2026-11-21",
            Decimal("10"), Decimal("25"), 1795280000
        )[0])

    def test_reject_then_settle_is_illegal(self):
        self.assertTrue(self.event("rejected", "evt-1"))
        self.assertFalse(self.event("settled", "evt-2"))
        self.assertEqual(self.journal.lookup("req-1")["status"], "rejected")

    def test_spoofing_and_duplicate_events_fail(self):
        self.assertFalse(self.event("accepted", "evt-a", rid="never-reserved"))
        self.assertTrue(self.event("accepted", "evt-a"))
        self.assertFalse(self.event("settled", "evt-a"))
        self.assertFalse(self.event("settled", "evt-b", ref="another-ref"))
        self.assertFalse(self.event("refunded", "evt-c"))
        self.assertFalse(self.event("settled", "evt-d", ref=""))
        self.assertFalse(self.event("settled", "evt-e", ref="mock-ref-1", rid="never-reserved"))

    def test_journal_survives_restart(self):
        self.assertTrue(self.event("accepted", "evt-1"))
        reopened = ProviderOutcomeJournal(self.path)
        self.assertEqual(reopened.lookup("req-1")["status"], "accepted")
        self.assertTrue(reopened.record(event_id="evt-2", request_id="req-1",
                                        reference="mock-ref-1", status="settled"))
        self.assertEqual(self.journal.lookup("req-1")["status"], "settled")


if __name__ == "__main__":
    unittest.main()

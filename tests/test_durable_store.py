"""Adversarial durability/replay tests with simulated funds only."""
import os
import tempfile
import threading
import unittest
from unittest.mock import patch
from decimal import Decimal
from Payment_guard import Policy, authorize, sign_approval
from durable_store import SQLiteReplayStore

SECRET = b"development-test-key-32-bytes-0123456789"
PAYEE = "acct_fake_001"
NOW = 1795280000


class DurableGuardTests(unittest.TestCase):
    def setUp(self):
        self.clock_patch = patch("Payment_guard.time.time", return_value=NOW)
        self.clock_patch.start()
        self.addCleanup(self.clock_patch.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "guard.db")
        self.store = SQLiteReplayStore(self.path)
        self.policy = Policy(frozenset({PAYEE}), Decimal("50"), max_daily_usd=Decimal("60"))

    def approve(self, request_id, nonce, amount="10.00", payee=PAYEE, store=None, policy=None):
        token = sign_approval(payee, amount, request_id, nonce, NOW + 120, SECRET)
        return authorize(payee, amount, policy or self.policy, request_id=request_id,
                         approval_token=token, approval_secret=SECRET,
                         replay_store=store or self.store)

    def test_durable_replay_after_reopening(self):
        self.assertTrue(self.approve("r1", "n1").allowed)
        reopened = SQLiteReplayStore(self.path)
        self.assertFalse(self.approve("r1", "n1", store=reopened).allowed)

    def test_nonce_reuse_across_distinct_requests_and_instances(self):
        self.assertTrue(self.approve("r1", "n1").allowed)
        self.assertFalse(self.approve("r2", "n1", store=SQLiteReplayStore(self.path)).allowed)

    def test_daily_limit_shared_across_instances(self):
        self.assertTrue(self.approve("r1", "n1", amount="50").allowed)
        fresh = SQLiteReplayStore(self.path)
        self.assertFalse(self.approve("r2", "n2", amount="20", store=fresh).allowed)
        self.assertTrue(self.approve("r3", "n3", amount="10", store=fresh).allowed)

    def test_concurrent_instances_cannot_double_spend(self):
        results = []
        lock = threading.Lock()
        def worker(i):
            result = self.approve("r" + str(i), "n" + str(i),
                                  amount="40", store=SQLiteReplayStore(self.path))
            with lock:
                results.append(result.allowed)
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(12)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sum(results), 1)

    def test_corrupt_or_unavailable_ledger_fails_closed(self):
        self.assertTrue(self.approve("r1", "n1").allowed)
        os.remove(self.path)
        os.mkdir(self.path)
        self.assertFalse(self.approve("r2", "n2").allowed)

    def test_zero_daily_cap_fails_closed(self):
        policy = Policy(frozenset({PAYEE}), Decimal("50"))
        self.assertFalse(self.approve("r1", "n1", policy=policy).allowed)

    def test_transaction_limits_handle_large_values_without_overflow(self):
        policy = Policy(frozenset({PAYEE}), Decimal("90000000000000"),
                        max_daily_usd=Decimal("90000000000000"))
        result = self.approve("r1", "n1", amount="90000000000000", policy=policy)
        self.assertTrue(result.allowed)
        with self.assertRaises(ValueError):
            Policy(frozenset({PAYEE}), Decimal("90000000000000.01"),
                   max_daily_usd=Decimal("90000000000000.01"))

    def test_no_approval_secret_fails_closed(self):
        result = authorize(PAYEE, "10", self.policy, approved=True, request_id="r1",
                           replay_store=self.store)
        self.assertFalse(result.allowed)

    def test_exact_payee_id_only(self):
        self.assertFalse(self.approve("r1", "n1", payee="ACCT_FAKE_001").allowed)


if __name__ == "__main__":
    unittest.main()

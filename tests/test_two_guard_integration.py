"""Direct offline integration: original Phase 4 checker gates current payment boundary.

All identities, account identifiers, transactions and provider callbacks are fake.
This is NOT live provider security validation.
"""
import sys
import unittest
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from decimal import Decimal
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
from legacy_permission_engine_v4 import Identities, Guard, grant, action, customer_approval, seal
from Payment_guard import Policy, ReplayStore, sign_approval
from payment_boundary import guarded_dispatch

NOW = datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc).timestamp()
SECRET = b"offline-integration-test-secret-1234567890"
PAYEE = "electric-co"

class TwoGuardIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.ids = Identities()
        self.checker = Guard(str(Path(self.temp.name) / "checker.sqlite"), self.ids)
        self.permission = grant(self.ids)
        self.policy = Policy(frozenset({PAYEE}), Decimal("200.00"),
                             max_daily_usd=Decimal("300.00"))
        self.store = ReplayStore()
        self.provider_calls = []
        self.clock = patch("Payment_guard.time.time", return_value=NOW)
        self.clock.start()
        self.addCleanup(self.clock.stop)

    def provider(self, **kwargs):
        self.provider_calls.append(kwargs)
        return {"fake_provider": "accepted"}

    def attempt(self, request, customer_proof=None, *, token_enabled=True):
        """The checker MUST approve before the newer guard can dispatch."""
        older = self.checker.judge(self.permission, request, customer_proof)
        if older["decision"] != "ALLOW":
            return older["decision"], None
        body = request["body"]
        token = (sign_approval(body["payee"], str(body["amount"]),
                 body["request_id"], "nonce-" + body["request_id"],
                 int(NOW)+60, SECRET) if token_enabled else None)
        newer = guarded_dispatch(
            body["payee"], str(body["amount"]), self.policy,
            request_id=body["request_id"], approval_token=token,
            approval_secret=SECRET, replay_store=self.store,
            provider_submit=self.provider)
        return older["decision"], newer

    def test_normal_payment_passes_both_guards_once(self):
        older, newer = self.attempt(action(self.ids, amount="75"))
        self.assertEqual(older, "ALLOW")
        self.assertTrue(newer.submitted)
        self.assertEqual(self.provider_calls[0]["amount_usd"], "75.00")

    def test_missing_legacy_customer_approval_holds_and_never_dispatches(self):
        older, newer = self.attempt(action(self.ids, amount="150"))
        self.assertEqual(older, "HOLD")
        self.assertIsNone(newer)
        self.assertEqual(self.provider_calls, [])

    def test_valid_legacy_customer_approval_and_new_token(self):
        request = action(self.ids, amount="150")
        older, newer = self.attempt(request, customer_approval(self.ids, request))
        self.assertEqual(older, "ALLOW")
        self.assertTrue(newer.submitted)
        self.assertEqual(len(self.provider_calls), 1)

    def test_invalid_payee_blocked_upstream(self):
        older, newer = self.attempt(action(self.ids, payee="attacker"))
        self.assertEqual(older, "BLOCK")
        self.assertIsNone(newer)
        self.assertEqual(self.provider_calls, [])

    def test_forged_agent_signature_blocked(self):
        request = action(self.ids)
        request["sig"] = "00" * 64
        older, newer = self.attempt(request)
        self.assertEqual(older, "BLOCK")
        self.assertIsNone(newer)
        self.assertEqual(self.provider_calls, [])

    def test_newer_guard_rejects_absent_independent_token(self):
        older, newer = self.attempt(action(self.ids), token_enabled=False)
        self.assertEqual(older, "ALLOW")
        self.assertFalse(newer.submitted)
        self.assertEqual(self.provider_calls, [])

    def test_replay_blocked_before_second_provider_call(self):
        request = action(self.ids)
        first, accepted = self.attempt(request)
        second, denied = self.attempt(request)
        self.assertEqual(first, "ALLOW")
        self.assertTrue(accepted.submitted)
        self.assertEqual(second, "BLOCK")
        self.assertIsNone(denied)
        self.assertEqual(len(self.provider_calls), 1)

    def test_legacy_denial_not_overridden_by_valid_new_token(self):
        request = action(self.ids, amount="500")
        older, newer = self.attempt(request)
        self.assertEqual(older, "BLOCK")
        self.assertIsNone(newer)
        self.assertEqual(self.provider_calls, [])

if __name__ == "__main__":
    unittest.main()

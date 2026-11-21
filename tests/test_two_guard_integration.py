"""Direct OFFLINE integration of original checker and payment boundary.

No human, bank, payment processor or production identity system involved.
The synthetic consent signer is a test fixture, not verified human identity.
"""
import sys
import unittest
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from datetime import datetime, timezone
from decimal import Decimal
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
from legacy_permission_engine_v4 import (
    Identities, Guard, grant, action, customer_approval, verify, digest, epoch
)
from Payment_guard import Policy, sign_approval
from durable_store import SQLiteReplayStore
from payment_boundary import guarded_dispatch, ProviderReceipt

NOW = int(datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc).timestamp())
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
        self.store_path = str(Path(self.temp.name) / "payment.sqlite")
        self.store = SQLiteReplayStore(self.store_path)
        self.provider_calls = []
        self.call_lock = threading.Lock()
        self.provider_result = ProviderReceipt("accepted", "mock-transaction-id")
        self.clock = patch("Payment_guard.time.time", return_value=NOW)
        self.clock.start()
        self.addCleanup(self.clock.stop)

    def provider(self, **kwargs):
        with self.call_lock:
            self.provider_calls.append(kwargs)
        return self.provider_result

    def fake_consent(self, request):
        return customer_approval(self.ids, request)

    def consent_is_valid(self, request, proof):
        """TEST-ONLY Ed25519 consent check; verifies request binding and expiry.

        A real service must first authenticate a person and obtain explicit
        approval before issuing such proof. This fixture does not do that.
        """
        if not verify(proof, self.ids.customer.public_key()):
            return False
        p = proof["body"]
        return (
            p.get("request_hash") == digest(request["body"])
            and p.get("permission_id") == self.permission["body"]["permission_id"]
            and p.get("customer_id") == "customer-1"
            and p.get("approved") is True
            and isinstance(p.get("expires_at"), str)
            and epoch(p["expires_at"]).timestamp() > NOW
        )

    def attempt(self, request, customer_proof=None, *, token_enabled=True):
        # First gate: the older permission checker decides on synthetic inputs.
        older = self.checker.judge(self.permission, request, customer_proof)
        if older["decision"] != "ALLOW":
            return older["decision"], None
        # Independent gate: consent is MANDATORY at ALL payment amounts.
        # Do not mint the newer guard's HMAC token from agent request data alone.
        if not self.consent_is_valid(request, customer_proof):
            return "HOLD", None
        body = request["body"]
        token = (sign_approval(body["payee"], str(body["amount"]),
                 body["request_id"], "nonce-" + body["request_id"],
                 NOW + 60, SECRET) if token_enabled else None)
        newer = guarded_dispatch(
            body["payee"], str(body["amount"]), self.policy,
            request_id=body["request_id"], approval_token=token,
            approval_secret=SECRET, replay_store=self.store,
            provider_submit=self.provider)
        return older["decision"], newer

    def test_valid_payment_requires_both_guards_and_consent(self):
        req = action(self.ids, amount="75")
        old, result = self.attempt(req, self.fake_consent(req))
        self.assertEqual(old, "ALLOW")
        self.assertTrue(result.submitted)
        self.assertEqual(self.provider_calls[0]["amount_usd"], "75.00")

    def test_small_payment_without_customer_consent_is_held(self):
        old, result = self.attempt(action(self.ids, amount="1"))
        self.assertEqual(old, "HOLD")
        self.assertIsNone(result)
        self.assertEqual(self.provider_calls, [])

    def test_large_payment_without_customer_consent_is_held(self):
        old, result = self.attempt(action(self.ids, amount="150"))
        self.assertEqual(old, "HOLD")
        self.assertIsNone(result)

    def test_valid_large_payment_proof(self):
        req = action(self.ids, amount="150")
        old, result = self.attempt(req, self.fake_consent(req))
        self.assertEqual(old, "ALLOW")
        self.assertTrue(result.submitted)

    def test_consent_proof_for_other_request_is_held(self):
        original = action(self.ids, amount="75")
        req = action(self.ids, amount="75")
        old, result = self.attempt(req, self.fake_consent(original))
        self.assertEqual(old, "HOLD")
        self.assertIsNone(result)

    def test_tampered_consent_is_held(self):
        req = action(self.ids, amount="75")
        proof = self.fake_consent(req)
        proof["sig"] = "00" * 64
        old, result = self.attempt(req, proof)
        self.assertEqual(old, "HOLD")
        self.assertIsNone(result)

    def test_invalid_payee_blocked_upstream(self):
        req = action(self.ids, payee="attacker")
        old, result = self.attempt(req, self.fake_consent(req))
        self.assertEqual(old, "BLOCK")
        self.assertIsNone(result)

    def test_forged_agent_signature_blocked(self):
        req = action(self.ids)
        proof = self.fake_consent(req)
        req["sig"] = "00" * 64
        old, result = self.attempt(req, proof)
        self.assertEqual(old, "BLOCK")
        self.assertIsNone(result)

    def test_no_hmac_token_never_submits(self):
        req = action(self.ids)
        old, result = self.attempt(req, self.fake_consent(req), token_enabled=False)
        self.assertEqual(old, "ALLOW")
        self.assertFalse(result.submitted)
        self.assertEqual(self.provider_calls, [])

    def test_old_checker_replay_fails_closed(self):
        req = action(self.ids)
        proof = self.fake_consent(req)
        old, accepted = self.attempt(req, proof)
        repeat, blocked = self.attempt(req, proof)
        self.assertEqual(old, "ALLOW")
        self.assertTrue(accepted.submitted)
        self.assertEqual(repeat, "BLOCK")
        self.assertIsNone(blocked)
        self.assertEqual(len(self.provider_calls), 1)

    def test_new_guard_durable_replay_after_checker_reset(self):
        req = action(self.ids)
        proof = self.fake_consent(req)
        self.assertTrue(self.attempt(req, proof)[1].submitted)
        # Simulate a rebuilt/reset old checker: payment ledger STILL rejects.
        self.checker = Guard(str(Path(self.temp.name) / "new-checker.sqlite"), self.ids)
        self.store = SQLiteReplayStore(self.store_path)
        old, result = self.attempt(req, proof)
        self.assertEqual(old, "ALLOW")
        self.assertFalse(result.submitted)
        self.assertEqual(len(self.provider_calls), 1)

    def test_daily_cap_under_concurrent_calls(self):
        def worker(_):
            req = action(self.ids, amount="75")
            return self.attempt(req, self.fake_consent(req))
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(worker, range(8)))
        self.assertEqual(sum(bool(r and r.submitted) for _, r in results), 4)
        self.assertEqual(len(self.provider_calls), 4)

    def test_denial_cannot_override_payment_limit(self):
        req = action(self.ids, amount="500")
        old, result = self.attempt(req, self.fake_consent(req))
        self.assertEqual(old, "BLOCK")
        self.assertIsNone(result)

    def test_provider_rejection_not_success_and_replay_retained(self):
        self.provider_result = ProviderReceipt("rejected", "mock-declined")
        req = action(self.ids, amount="75")
        proof = self.fake_consent(req)
        old, result = self.attempt(req, proof)
        self.assertEqual(old, "ALLOW")
        self.assertFalse(result.submitted)
        self.assertEqual(len(self.provider_calls), 1)
        # Remain reserved even if older checker is reconstructed.
        self.checker = Guard(str(Path(self.temp.name) / "another-checker.sqlite"), self.ids)
        old, second = self.attempt(req, proof)
        self.assertEqual(old, "ALLOW")
        self.assertFalse(second.submitted)
        self.assertEqual(len(self.provider_calls), 1)

    def test_pending_and_uncertain_provider_outcomes_not_success(self):
        for receipt in (ProviderReceipt("pending", "mock-pending"), None):
            req = action(self.ids, amount="75")
            proof = self.fake_consent(req)
            self.provider_result = receipt
            old, result = self.attempt(req, proof)
            self.assertEqual(old, "ALLOW")
            self.assertFalse(result.submitted)


if __name__ == "__main__":
    unittest.main()

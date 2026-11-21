import base64
import threading
import unittest
from unittest.mock import patch
from decimal import Decimal
from Payment_guard import Policy, ReplayStore, authorize, sign_approval

SECRET = b"unit-test-secret-only-32-bytes-000000"
NOW = 1795280000
PAYEE = "acct_test_123"


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.clock_patch = patch("Payment_guard.time.time", return_value=NOW)
        self.clock_patch.start()
        self.addCleanup(self.clock_patch.stop)
        self.policy = Policy(frozenset({PAYEE}), Decimal("50"), max_daily_usd=Decimal("75"))
        self.store = ReplayStore()

    def check(self, amount="10.00", request_id="req1", nonce="nonce1",
              payee=PAYEE, policy=None, expires_at=NOW + 120, token=None):
        if token is None:
            token = sign_approval(payee, amount, request_id, nonce, expires_at, SECRET)
        return authorize(payee, amount, self.policy if policy is None else policy,
                         request_id=request_id, approval_token=token,
                         approval_secret=SECRET, replay_store=self.store)

    def test_valid_approval(self):
        self.assertTrue(self.check().allowed)

    def test_approval_boolean_cannot_bypass(self):
        self.assertFalse(authorize(PAYEE, "10", self.policy, approved=True,
                                   request_id="r", replay_store=self.store).allowed)

    def test_payee_not_allowlisted(self):
        self.assertFalse(self.check(payee="other").allowed)

    def test_over_limit(self):
        self.assertFalse(self.check(amount="50.01").allowed)

    def test_malformed_amounts_fail_closed(self):
        for i, amount in enumerate(["-1", "0", "NaN", "Infinity", "0.001", "abc", "", "1e999999"]):
            with self.subTest(amount=amount):
                self.assertFalse(authorize(PAYEE, amount, self.policy, request_id=str(i),
                                           replay_store=self.store).allowed)

    def test_floats_fail_closed(self):
        self.assertFalse(authorize(PAYEE, 10.0, self.policy, request_id="r",
                                   replay_store=self.store).allowed)

    def test_trailing_zeros_are_valid(self):
        self.assertTrue(self.check(amount="50.000").allowed)
        self.assertTrue(self.check(amount="0.010", request_id="req2", nonce="nonce2").allowed)

    def test_replay_denied(self):
        self.assertTrue(self.check().allowed)
        self.assertFalse(self.check().allowed)

    def test_nonce_reuse_denied(self):
        self.assertTrue(self.check().allowed)
        self.assertFalse(self.check(request_id="req2", nonce="nonce1").allowed)

    def test_modified_signature_denied(self):
        token = sign_approval(PAYEE, "10", "req1", "nonce1", NOW+120, SECRET)
        raw = bytearray(base64.urlsafe_b64decode(token))
        raw[5] ^= 1
        self.assertFalse(self.check(token=base64.urlsafe_b64encode(raw).decode()).allowed)

    def test_token_bound_to_exact_payment(self):
        token = sign_approval(PAYEE, "10", "req1", "nonce1", NOW+120, SECRET)
        self.assertFalse(self.check(amount="11", token=token).allowed)
        self.assertFalse(self.check(request_id="req2", token=token).allowed)
        p = Policy(frozenset({PAYEE, "other"}), Decimal("50"), max_daily_usd=Decimal("75"))
        self.assertFalse(self.check(payee="other", policy=p, token=token).allowed)

    def test_expired_or_too_long_lived_denied(self):
        self.assertFalse(self.check(expires_at=NOW).allowed)
        self.assertFalse(self.check(expires_at=NOW+301).allowed)

    def test_daily_limit(self):
        self.assertTrue(self.check(amount="50").allowed)
        self.assertFalse(self.check(amount="30", request_id="req2", nonce="nonce2").allowed)
        self.assertTrue(self.check(amount="25", request_id="req3", nonce="nonce3").allowed)

    def test_missing_store_denied(self):
        self.assertFalse(authorize(PAYEE, "10", self.policy, request_id="x").allowed)

    def test_concurrent_replay_denied(self):
        results = []
        def run():
            results.append(self.check())
        threads = [threading.Thread(target=run) for _ in range(10)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sum(decision.allowed for decision in results), 1)

    def test_unconfigured_daily_cap_denied(self):
        p = Policy(frozenset({PAYEE}), Decimal("50"))
        self.assertFalse(self.check(policy=p).allowed)


if __name__ == "__main__":
    unittest.main()

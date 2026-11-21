"""Reference payment boundary tests: no live payment provider or credentials."""
import unittest
from unittest.mock import patch
from decimal import Decimal
from Payment_guard import Policy, ReplayStore, sign_approval
from payment_boundary import guarded_dispatch

SECRET = b"development-test-key-32-bytes-0123456789"
NOW = 1795280000
PAYEE = "acct_fake"


class BoundaryTests(unittest.TestCase):
    def setUp(self):
        self.patch = patch("Payment_guard.time.time", return_value=NOW)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.policy = Policy(frozenset({PAYEE}), Decimal("20"), max_daily_usd=Decimal("25"))
        self.store = ReplayStore()
        self.calls = []

    def provider(self, **kwargs):
        self.calls.append(kwargs)
        return {"simulation": "accepted"}

    def dispatch(self, payee=PAYEE, amount="10", request_id="r1", provider=None, token=None):
        if token is None:
            token = sign_approval(PAYEE, amount, request_id, "nonce-"+request_id,
                                  NOW+60, SECRET)
        return guarded_dispatch(payee, amount, self.policy, request_id=request_id,
                                approval_token=token, approval_secret=SECRET,
                                replay_store=self.store,
                                provider_submit=self.provider if provider is None else provider)

    def test_denied_request_never_reaches_provider(self):
        result = self.dispatch(payee="unapproved")
        self.assertFalse(result.submitted)
        self.assertEqual(self.calls, [])

    def test_valid_payment_submitted_once_with_idempotency_key(self):
        result = self.dispatch()
        self.assertTrue(result.submitted)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.calls[0]["idempotency_key"], "r1")
        self.assertEqual(self.calls[0]["payee_id"], PAYEE)
        self.assertFalse(self.dispatch().submitted)
        self.assertEqual(len(self.calls), 1)

    def test_provider_receives_exact_canonical_amount(self):
        for idx, input_amount in enumerate(("1e0", "+1.000", "1.0")):
            result = self.dispatch(amount=input_amount, request_id=f"canonical-{idx}")
            self.assertTrue(result.submitted)
            self.assertEqual(self.calls[-1]["amount_usd"], "1.00")

    def test_provider_error_fails_closed_and_does_not_free_reservation(self):
        def failing_provider(**kwargs):
            raise ConnectionError("unknown provider outcome")
        result = self.dispatch(provider=failing_provider)
        self.assertFalse(result.submitted)
        self.assertIn("unknown", result.reason)
        self.assertFalse(self.dispatch().submitted)
        self.assertEqual(self.calls, [])

    def test_invalid_provider_callback_does_not_bypass(self):
        result = self.dispatch(provider="NOT A PROVIDER")
        self.assertFalse(result.submitted)
        self.assertEqual(self.calls, [])
        self.assertFalse(self.dispatch().submitted)

    def test_spending_budget_blocks_second_provider_call(self):
        self.assertTrue(self.dispatch(amount="20").submitted)
        self.assertFalse(self.dispatch(amount="10", request_id="r2").submitted)
        self.assertEqual(len(self.calls), 1)


if __name__ == "__main__":
    unittest.main()

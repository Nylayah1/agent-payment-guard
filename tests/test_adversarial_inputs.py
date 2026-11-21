"""Deterministic adversarial input tests. All data and payees are fake."""
import base64
import unittest
from unittest.mock import patch
from decimal import Decimal
from Payment_guard import Policy, ReplayStore, authorize, sign_approval

SECRET = b"secure-test-only-key-0000000000000001"
NOW = 1795280000
PAYEE = "acct_fake"


class AdversarialInputs(unittest.TestCase):
    def setUp(self):
        timer = patch("Payment_guard.time.time", return_value=NOW)
        timer.start()
        self.addCleanup(timer.stop)
        self.policy = Policy(frozenset({PAYEE}), Decimal("100"), max_daily_usd=Decimal("1000"))

    def decision(self, amount, request_id="request-test", token=None, payee=PAYEE):
        if token is None and isinstance(amount, str):
            try:
                token = sign_approval(PAYEE, amount, request_id, "nonce-test", NOW + 120, SECRET)
            except ValueError:
                token = ""
        return authorize(payee, amount, self.policy, request_id=request_id,
                         approval_token=token, approval_secret=SECRET,
                         replay_store=ReplayStore())

    def test_mutated_signed_bytes_always_denied(self):
        token = sign_approval(PAYEE, "9.99", "request-test", "nonce-test",
                              NOW + 120, SECRET)
        raw = base64.urlsafe_b64decode(token)
        self.assertTrue(self.decision("9.99", token=token).allowed)
        for position in range(len(raw)):
            with self.subTest(position=position):
                altered = bytearray(raw)
                altered[position] ^= 1
                changed = base64.urlsafe_b64encode(altered).decode("ascii")
                self.assertFalse(self.decision("9.99", token=changed).allowed)

    def test_malformed_numeric_inputs_fail_closed(self):
        cases = [
            "0", "-0", "-0.00", "-1", "+1", "1e2", "1E2",
            " 1.00 ", "\t1.00", "Infinity", "-Infinity", "NaN",
            "sNaN", "0.0001", "1.001", "1000000000000000000",
            "99999999999999999999", "", "1,000.00",
            "1 OR 1=1", "'; DROP TABLE reservations; --",
            "1\x00", "1\n2", "１.００",
        ]
        for value in cases:
            with self.subTest(value=repr(value)):
                # Some strings are parseable but should not authorize without
                # valid, separately verified signing/budget controls.
                self.assertFalse(self.decision(value, token="invalid-token").allowed)

    def test_policy_rejects_invalid_caps(self):
        for value in ["100.001", "-1", "NaN", "Infinity", "90000000000000.01"]:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    Policy(frozenset({PAYEE}), Decimal("100"), max_daily_usd=Decimal(value))

    def test_approval_is_not_transferable_between_payees(self):
        signed = sign_approval(PAYEE, "9.99", "request-test", "nonce-test", NOW+120, SECRET)
        self.assertFalse(self.decision("9.99", token=signed, payee="acct_elsewhere").allowed)


if __name__ == "__main__":
    unittest.main()

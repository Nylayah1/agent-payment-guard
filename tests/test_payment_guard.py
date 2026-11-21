import unittest
from decimal import Decimal
from Payment_guard import Policy, authorize


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.policy = Policy(frozenset({"Example Store"}), Decimal("50.00"))

    def test_requires_independent_approval(self):
        self.assertFalse(authorize("Example Store", "10.00", self.policy).allowed)
        self.assertTrue(authorize("Example Store", "10.00", self.policy, approved=True).allowed)

    def test_unknown_merchant_denied(self):
        self.assertFalse(authorize("Unknown", "10.00", self.policy, approved=True).allowed)

    def test_over_limit_denied(self):
        self.assertFalse(authorize("Example Store", "50.01", self.policy, approved=True).allowed)

    def test_malformed_or_unsafe_amount_denied(self):
        for amount in ["-1", "0", "NaN", "Infinity", "0.001", "abc", ""]:
            with self.subTest(amount=amount):
                self.assertFalse(authorize("Example Store", amount, self.policy, approved=True).allowed)

    def test_float_denied(self):
        self.assertFalse(authorize("Example Store", 10.0, self.policy, approved=True).allowed)

    def test_case_insensitive_merchant(self):
        self.assertTrue(authorize("example store", "2.50", self.policy, approved=True).allowed)


if __name__ == "__main__":
    unittest.main()

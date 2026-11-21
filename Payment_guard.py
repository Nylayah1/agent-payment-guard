"""Experimental fail-closed policy check for proposed AI-agent payments.

Does NOT intercept or execute payments. The payment-controlling backend must
enforce the decision before calling its payment provider.
"""
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation


@dataclass(frozen=True)
class Policy:
    allowed_merchants: frozenset[str]
    max_transaction_usd: Decimal
    require_approval: bool = True

    def __post_init__(self):
        if not self.max_transaction_usd.is_finite() or self.max_transaction_usd < 0:
            raise ValueError("Invalid transaction limit")


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


def authorize(merchant: str, amount_usd: str, policy: Policy,
              approved: bool = False) -> Decision:
    """Return a policy decision; never move money.

    Only a trusted backend may set approved=True after verifying actual human
    authorization. Never trust an AI agent's claim that approval happened.
    """
    if not isinstance(merchant, str) or not merchant.strip():
        return Decision(False, "Missing merchant")
    if merchant.strip().casefold() not in {m.casefold() for m in policy.allowed_merchants}:
        return Decision(False, "Merchant not allowlisted")
    if not isinstance(amount_usd, str):
        return Decision(False, "Amount must be a decimal string")
    try:
        amount = Decimal(amount_usd)
    except InvalidOperation:
        return Decision(False, "Invalid amount")
    if not amount.is_finite() or amount <= 0 or amount.as_tuple().exponent < -2:
        return Decision(False, "Invalid USD amount")
    if amount > policy.max_transaction_usd:
        return Decision(False, "Transaction exceeds limit")
    if policy.require_approval and approved is not True:
        return Decision(False, "Independent human approval required")
    return Decision(True, "Policy checks passed")

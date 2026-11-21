"""Reference payment boundary for simulated/integration testing only.

The trusted backend must own both the signing key and provider callback.
Never expose the provider callback or credentials to an untrusted AI agent.
This adapter cannot protect a separate, unguarded provider integration.
"""
from dataclasses import dataclass
from typing import Any, Callable
from Payment_guard import Decision, Policy, authorize, _usd


@dataclass(frozen=True)
class DispatchResult:
    submitted: bool
    reason: str
    provider_response: Any = None


def guarded_dispatch(payee_id: str, amount_usd: str, policy: Policy, *,
                     request_id: str, approval_token: str, approval_secret: bytes,
                     replay_store, provider_submit: Callable[..., Any]) -> DispatchResult:
    """Submit only if reserved under policy, without claiming settlement.

    provider_submit must be a trusted backend-controlled callable that uses
    the request ID as the payment-provider idempotency key. The provider
    integration must verify credentials/payee IDs independently.
    """
    decision = authorize(payee_id, amount_usd, policy, request_id=request_id,
                         approval_token=approval_token,
                         approval_secret=approval_secret,
                         replay_store=replay_store)
    if not decision.allowed:
        return DispatchResult(False, decision.reason)
    if not callable(provider_submit):
        return DispatchResult(False, "Provider unavailable; reservation retained")
    # Pass the same canonical cents amount that policy and token verification used.
    # An external provider must never reinterpret exponent/trailing-zero notation.
    canonical_amount = format(_usd(amount_usd), ".2f")
    try:
        response = provider_submit(payee_id=payee_id, amount_usd=canonical_amount,
                                   idempotency_key=request_id)
    except Exception:
        # Never release a reservation merely because a network call failed:
        # the provider might already have processed the payment.
        return DispatchResult(False, "Provider outcome unknown; reservation retained")
    return DispatchResult(True, "Submitted to provider; settlement not verified", response)

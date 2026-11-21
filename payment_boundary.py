"""Fail-closed reference provider boundary for simulated/integration testing.

A trusted adapter must map *verified provider API responses* to ProviderReceipt.
No live gateway, settlement or refunds are implemented here.
"""
from dataclasses import dataclass
from typing import Any, Callable
from Payment_guard import Policy, authorize, _usd


@dataclass(frozen=True)
class ProviderReceipt:
    # A trusted adapter must establish this status from the real provider's API.
    # Only "accepted" signifies an acknowledged submission; not settlement.
    status: str
    reference: str = ""


@dataclass(frozen=True)
class DispatchResult:
    submitted: bool
    reason: str
    provider_response: Any = None


def guarded_dispatch(payee_id: str, amount_usd: str, policy: Policy, *,
                     request_id: str, approval_token: str, approval_secret: bytes,
                     replay_store, provider_submit: Callable[..., Any]) -> DispatchResult:
    """Reserve before dispatch; never retry or undo an uncertain reservation.

    provider_submit must live behind a trusted provider boundary and enforce
    idempotency with request_id. An agent cannot be allowed to call it directly.
    This function cannot independently validate provider response authenticity.
    """
    decision = authorize(payee_id, amount_usd, policy, request_id=request_id,
                         approval_token=approval_token,
                         approval_secret=approval_secret, replay_store=replay_store)
    if not decision.allowed:
        return DispatchResult(False, decision.reason)
    if not callable(provider_submit):
        return DispatchResult(False, "Provider unavailable; reservation retained")
    canonical_amount = format(_usd(amount_usd), ".2f")
    try:
        response = provider_submit(payee_id=payee_id, amount_usd=canonical_amount,
                                   idempotency_key=request_id)
    except Exception:
        return DispatchResult(False, "Provider outcome unknown; reservation retained")

    # Never infer success from HTTP 200, a truthy dict, or an arbitrary object.
    # A provider's actual rejection, pending status, or unparseable result is
    # NOT successful. Keep reservation until a trusted reconciliation process.
    if not isinstance(response, ProviderReceipt):
        return DispatchResult(False, "Unverified provider response; reservation retained")
    if response.status == "accepted" and isinstance(response.reference, str) and response.reference.strip():
        return DispatchResult(True, "Provider acknowledged submission; settlement unverified", response)
    if response.status == "rejected":
        return DispatchResult(False, "Provider rejected; reservation retained", response)
    return DispatchResult(False, "Provider pending or unknown; reservation retained", response)

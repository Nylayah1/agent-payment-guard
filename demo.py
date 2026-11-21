"""Run: python demo.py

Illustrative OFFLINE flow using fake payment accounts and a mock provider.
Nothing here connects to a bank, payment processor, or network.
"""
import secrets
import time
from decimal import Decimal

from Payment_guard import Policy, ReplayStore, sign_approval
from payment_boundary import guarded_dispatch, ProviderReceipt


def mock_provider(*, payee_id, amount_usd, idempotency_key):
    print(f"MOCK PROVIDER: {payee_id} USD {amount_usd}, key={idempotency_key}")
    return ProviderReceipt("accepted", "mock-" + idempotency_key)


def main():
    policy = Policy(
        allowed_merchants=frozenset({"acct_fake_demo_001"}),
        max_transaction_usd=Decimal("25.00"),
        max_daily_usd=Decimal("40.00"),
    )
    signing_key = secrets.token_bytes(32)  # Generated only inside fake backend
    ledger = ReplayStore()  # Demo only. Use a DURABLE store for real integration.
    payee, amount = "acct_fake_demo_001", "12.50"
    request_id = secrets.token_hex(16)
    nonce = secrets.token_hex(16)

    # SIMULATED human consent: in real deployments this cannot be simulated.
    # A separate authenticated human approval service must verify consent.
    token = sign_approval(
        payee, amount, request_id, nonce, int(time.time()) + 120, signing_key
    )
    args = dict(
        request_id=request_id,
        approval_token=token,
        approval_secret=signing_key,
        replay_store=ledger,
        provider_submit=mock_provider,
    )
    first = guarded_dispatch(payee, amount, policy, **args)
    replay = guarded_dispatch(payee, amount, policy, **args)
    tampered = guarded_dispatch("acct_fake_attacker_999", amount, policy, **args)

    assert first.submitted is True
    assert replay.submitted is False
    assert tampered.submitted is False

    print("First request:", first.reason)
    print("Replay:", replay.reason)
    print("Unauthorized payee:", tampered.reason)
    print("PASS: fake provider called once; replay and payee substitution blocked.")
    print("NOTE: This demo is not an independently authenticated payment approval.")


if __name__ == "__main__":
    main()

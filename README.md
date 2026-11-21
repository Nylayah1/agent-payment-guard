# Agent Payment Guard — experimental developer preview

Python policy checker for AI-agent payment requests. **Does not intercept, execute, or block real payments.** A trusted payment-controlling backend must enforce the result before sending any request to a payment provider.

**NOT PRODUCTION READY. Use only fake payee IDs and simulated money in tests.**

## Hardened checks

- Exact provider **payee/account ID** allowlist (not a merchant display name)
- Per-transaction USD maximum and a required daily spending cap, defaulting to zero (deny)
- HMAC-SHA256 human-approval token bound to payee ID, precise USD amount, currency, unique request ID, nonce, and short expiry (up to 5 minutes remaining)
- Duplicate request ID and nonce blocking through a locked, in-memory development ledger
- Fail closed for invalid amounts, floats, NaN, infinity, fractional cents, missing replay store, missing approval token; redundant trailing zeros are accepted
- Legacy caller-supplied `approved=True` **has no effect**: an AI agent cannot attest to human consent by setting a boolean

## Run tests

Python 3.10+; standard library only.

```sh
python -m unittest discover -s tests -v
```

## Trusted-backend demonstration (fake data)

Only the trusted backend should possess the signing key, ledger, or configured policy. The backend must **first authenticate a human and record their explicit consent to this exact payee and amount**. The code below merely demonstrates cryptographic token handling; it does not authenticate a human.

```python
import secrets
import time
from decimal import Decimal
from Payment_guard import Policy, ReplayStore, sign_approval, authorize

policy = Policy(
    allowed_merchants=frozenset({"acct_fake_store_1"}),
    max_transaction_usd=Decimal("50.00"),
    max_daily_usd=Decimal("100.00"),
)
ledger = ReplayStore()  # Demo only. Not durable across processes/restarts.
secret = secrets.token_bytes(32)  # Backend-only secret; never give to an agent.

# Simulate an already authenticated and independently approved human request.
request_id = "example-request-001"
nonce = secrets.token_urlsafe(24)
token = sign_approval("acct_fake_store_1", "19.99", request_id,
                      nonce, int(time.time()) + 120, secret)
decision = authorize("acct_fake_store_1", "19.99", policy,
                     request_id=request_id, approval_token=token,
                     approval_secret=secret, replay_store=ledger)
print(decision)
```

## Critical security limitations

1. **This library cannot prove someone actually approved a payment.** The backend must authenticate the human and keep its approval/signing workflow, signing secret, policy, and ledger completely outside the AI agent's control. Anyone who controls the secret can generate valid approvals.
2. **The replay ledger is for one-process demos only.** Production requires durable, atomic, multi-worker request/nonce uniqueness, spending reservations, and audit trails, ideally database transactions.
3. **The daily cap reserves budget; it does not settle payments.** Real systems must reconcile provider authorizations, captures, retries, failures, refunds, and expiration, and use payment-provider idempotency controls.
4. **The guard does not enforce its own decision.** It must be integrated directly at the payment boundary, where payment credentials cannot bypass policy checks.
5. **Use genuine provider payee IDs.** An agent-controlled display name is not a reliable payment destination.
6. **Breaking change:** Old calls to `authorize(..., approved=True)` now deny, unless the caller also supplies trusted request ID, valid approval token, secret, ledger, and daily cap. `approved` remains in the signature solely for backward compatibility and is ignored.

## Request for developer review

Use [GitHub Issues](../../issues) to suggest bypasses, adversarial tests or safer backend designs. Please use fake amounts and identities. Feedback on proof of approval, distributed idempotency, and settlement reconciliation is particularly valuable.

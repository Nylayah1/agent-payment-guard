# Agent Payment Guard — security-focused developer prototype

**An offline-testable, fail-closed payment policy boundary for AI-initiated requests.**

Designed to demonstrate explicit human consent verification, exact payee/amount binding,
atomic replay prevention and budget reservations **before** a trusted payment backend
contacts its provider. This is intentionally narrow, with documented limitations.

**Start here:** `python demo.py` to see a simulated first request succeed,
a duplicate request fail, and a payee substitution get blocked.
Then install the checker test dependency and run the security suite as shown in Quick start.

For the design and attack cases, read **[ARCHITECTURE.md](ARCHITECTURE.md)**.
For security boundaries and unfinished release gates, read **[SECURITY.md](SECURITY.md)**.

Python policy checker for AI-agent payment requests. **Does not intercept, execute, or block real payments.** A trusted payment-controlling backend must enforce the result before sending any request to a payment provider.

**NOT PRODUCTION READY. Use only fake payee IDs and simulated money in tests.**

## Hardened checks

- Exact provider **payee/account ID** allowlist (not a merchant display name)
- Per-transaction USD maximum and a required daily spending cap, defaulting to zero (deny)
- HMAC-SHA256 human-approval token bound to payee ID, precise USD amount, currency, unique request ID, nonce, and short expiry (up to 5 minutes remaining)
- Duplicate request ID and nonce blocking, with a **durable atomic SQLite option** for single-host integrations
- Fail closed for invalid amounts, floats, NaN, infinity, fractional cents, missing replay store, missing approval token; redundant trailing zeros are accepted
- Human approval **cannot be turned off** in policy; caller-supplied `approved=True` has no effect
- Authorization uses the backend process clock, not a caller-supplied timestamp

## Quick start

Python 3.10+; the core guard and demo use the standard library only. The full dual-checker test suite also requires `cryptography` (the CI workflow installs it). No bank credentials are needed.

```sh
python demo.py
python -m pip install 'cryptography>=42,<47'
python -m unittest discover -s tests -v
```

GitHub Actions also runs the demo and regression suite on Python 3.10,
3.11, 3.12 and 3.13. Both the demo and tests use **fake payees only**.

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
ledger = ReplayStore()  # Simplest demo only. Not durable across processes/restarts.
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

## Optional durable store (single local host only)

```python
from durable_store import SQLiteReplayStore

# One local, access-restricted database file per payment account.
# Only the trusted payment backend should be able to read/write it.
ledger = SQLiteReplayStore("/private/path/agent-payment-ledger.sqlite3")
```

A successful decision permanently reserves its amount against that UTC day's
budget in the prototype. It cannot be reversed by an untrusted caller.
The backend must separately manage payment-provider idempotency, settlement,
refunds, expired authorizations, and immutable audit logs.

## Reference provider boundary (simulation only)

`payment_boundary.guarded_dispatch(...)` demonstrates how the trusted backend
must check the guard immediately before forwarding a payment request. If
authorization fails, **the provider callback is never invoked**. If a provider
call errors, the reservation remains consumed because the provider may have
already processed the request. The callback receives the request ID as its
idempotency key. **This does not implement a payment provider, perform a
transaction, prove settlement, or prevent bypass from other code paths.**

## Hardened integration and outcomes (offline, simulated only)

- The direct **two-checker test fixture** now requires a valid, separately
  signed, request-bound customer proof for *every* test payment. Below-threshold
  payments are held without proof. This is still synthetic consent, not a real
  human authentication and approval service.
- The dual-checker suite uses the durable SQLite payment reservation ledger,
  and exercises replay after process/checker resets, concurrent spending,
  forged signatures, missing consent, provider rejection and uncertainty.
- `payment_boundary.ProviderReceipt` is a typed outcome contract for a
  trusted adapter: only an **accepted** submission with a nonblank reference
  is acknowledged. This is **not** proof of capture or settlement.
- `reconciliation.ProviderOutcomeJournal` persists simulated, ordered
  provider outcome events: pending, accepted, settled, rejected, refunded and
  disputed. It never automatically refunds the guard's daily budget or
  reopens replayed requests. It does **not** fetch, verify or act on provider
  events; an external trusted gateway and verified event processing are still
  missing.
- A real payment provider adapter, verified human approval service, secure
  token issuance, multi-host storage and production reconciliation remain
  separate unbuilt release requirements. **Do not use this prototype with
  actual money.**

## Critical security limitations

1. **This library cannot prove someone actually approved a payment.** The backend must authenticate the human and keep its approval/signing workflow, signing secret, policy, and ledger completely outside the AI agent's control. Anyone who controls the secret can generate valid approvals.
2. **Choose the ledger carefully.** `ReplayStore` is memory-only and loses all history on restart. `SQLiteReplayStore` provides atomic durable reservations across local worker processes sharing one single-host SQLite database file. It is NOT a distributed service, not suitable for shared network storage or ephemeral volumes. Protect and back up the database; partition ledgers by payment account/tenant. Production needs reconciliation, audit trails, and stronger operational controls.
3. **The daily cap reserves budget; it does not settle payments.** Real systems must reconcile provider authorizations, captures, retries, failures, refunds, and expiration, and use payment-provider idempotency controls.
4. **The guard does not enforce its own decision.** It must be integrated directly at the payment boundary, where payment credentials cannot bypass policy checks.
5. **Use genuine provider payee IDs.** An agent-controlled display name is not a reliable payment destination.
6. **Breaking change:** Old calls to `authorize(..., approved=True)` now deny, unless the caller also supplies trusted request ID, valid approval token, secret, ledger, and daily cap. `approved` remains in the signature solely for backward compatibility and is ignored.

See [SECURITY.md](SECURITY.md) for the threat model, deployment gates, and remaining bypass risks. GitHub Actions runs the regression suite across Python 3.10–3.13.

## For security reviewers

We welcome a **specific, reproducible attack case** with fake inputs.
Suggested areas: signing authority isolation, duplicate request IDs across process
restarts, SQLite file replacement, daily cap races, provider idempotency,
and bypassing the mandatory backend enforcement point.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the review guide and [SECURITY.md](SECURITY.md)
for remaining deployment blockers. No independent audit has been completed.

## Request for developer review

Use [GitHub Issues](../../issues) to suggest bypasses, adversarial tests or safer backend designs. Please use fake amounts and identities. Feedback on proof of approval, distributed idempotency, and settlement reconciliation is particularly valuable.

# Architecture and reviewer guide

## What this repository demonstrates

A small, auditable Python **policy decision + reservation** mechanism for
AI-initiated USD payment requests. It is not a money-moving product.

```text
Untrusted AI agent
    |
    | Proposed payee ID, amount, request ID
    v
Trusted backend  [AI cannot access keys, provider credentials, policy or ledger]
    |
    +--> Independent human authentication and approval UI (NOT IMPLEMENTED)
    |      Shows immutable payee + exact amount + USD currency
    |      Backend signs short-lived payment-specific approval
    |
    +--> Payment_guard.authorize()
    |      Payee allowlist -> money validation -> signed consent
    |      -> atomic replay & daily-budget reservation
    |      -> deny by default
    |
    +--> payment_boundary.guarded_dispatch() reference only
           On denial: NEVER invokes payment provider
           On allow: passes request_id as provider idempotency key
           On unknown provider response: reservation retained
    |
    v
Payment provider, settlement/reconciliation (NOT IMPLEMENTED)
```

## How to run

Requires Python 3.10+; standard library only, no cloud account or payment keys.

```bash
python -m unittest discover -s tests -v
python demo.py
```

The demo only uses fictional account IDs and an in-process fake provider.
The fake approval is illustrative; it is **not proof of a human action**.

## File map

| File | Responsibility |
| --- | --- |
| `Payment_guard.py` | Canonical amounts, policy checks, HMAC token issue/verify, in-memory reservation |
| `durable_store.py` | Atomic SQLite reservation and duplicate suppression (single host) |
| `payment_boundary.py` | Reference fail-closed provider-call boundary (fake provider in tests) |
| `demo.py` | One-command demonstration of accepted, replayed, and substituted payments |
| `tests/` | Regression, malicious-input, signature-bitflip, replay, concurrency and boundary checks |
| `SECURITY.md` | Threat model, unsolved risks, deployment blockers |
| `.github/workflows/tests.yml` | CI on four Python versions |

## Security invariants worth challenging

1. An agent cannot approve its own payment with `approved=True`.
2. Signed consent is bound to payee ID, amount, currency, request ID, nonce and expiry.
3. Same request ID or nonce cannot result in another reservation in a shared, intact ledger.
4. Atomic daily limit checking must not be bypassed by concurrent workers.
5. Denials must never cause a provider callback invocation.
6. Unknown provider outcomes must not free budget or reset replay state.
7. A missing or inaccessible ledger must cause denial, never default allow.

## Reviewer attack prompts

- Can an AI-controlled input change the payee/amount after consent?
- Can a token be replayed, re-encoded, or used after expiration?
- Can two concurrent processes bypass daily caps?
- Can killing the server or replacing the ledger file reset replay protection?
- Can a network failure lead to a second provider charge?
- Can a malicious caller access `sign_approval`, signing keys, policy, or payment
  credentials in a real deployment? The library **cannot** solve this alone.
- Is the backend actually the only route to provider calls?
- Are daily budgets partitioned by user, account and policy? **Not in this library.**

## Explicit release gates (not yet met)

- Independent human-identity and payment-confirmation backend
- Strong secret custody and key revocation/rotation
- Secure provider integration and real idempotency enforcement
- Atomic, centrally audited ledger across deployment instances/tenants
- Complete authorization/capture/refund reconciliation and incident recovery
- Independent security assessment, threat-model validation, and operational tests

Do not deploy for real payments until those gates are met.

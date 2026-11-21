# Security policy and threat model

**Status: developer experiment, NOT suitable for live payments.**
This repository cannot intercept, execute, or block an unauthorized payment
unless a separate, trusted payment backend enforces the decision. There is
no deployed backend, authenticated human approval UI, payment gateway adapter,
or independent external penetration test.

## Protected assets
- Actual payment-provider credentials and ability to initiate transfers
- Human authorization identity and exact amount/payee/currency
- Approval signing key, budget policy, replay ledger, and transaction audit
- Provider account IDs / destination identities

## Attacker assumptions
- AI agent can supply arbitrary text, amounts, request IDs and tokens.
- Agent may lie about having human consent and may repeat or modify requests.
- Agent may attempt to change payee IDs, swap tokens, exhaust budgets, replay
  an earlier approval, and race many parallel requests.
- Agent must NOT possess signing keys, policy write access, payment credentials
  or direct unguarded provider API access. These are trust-boundary requirements,
  not guarantees of this Python package.

## Implemented controls
1. Exact provider payee-ID allowlist; reject non-allowlisted recipients.
2. Signed, short-expiry approval bound to exact payee, USD amount, currency,
   request ID, nonce, and expiration; ignore an agent-controlled boolean.
3. Independent verification of HMAC under a backend-only key with domain
   separation (an approval signature must not be reused in another protocol).
4. Rejection of malformed/fractional-cent/negative/non-finite input, including
   arbitrary floats and strings.
5. Per-transaction maximum plus daily budget reservations, fail closed when
   policy is missing or cap unset.
6. Unique nonce + request ID and atomic reservation in a SQLite file.
7. Tests for concurrency, process/store reopening, tampering, expired tokens,
   mismatched payee/amount/request, repeated payments and failure modes.

## Serious unsolved risks
- **No authenticated human approval service**. The helper `sign_approval`
  is not proof that a human agreed. A trusted approval service must authenticate,
  display exact payment details, log explicit confirmation, rate-limit approvals,
  and sign only after verified consent. Keep secrets out of agent context,
  prompts, environment visible to agent, and repository.
- **No mandatory integration**. Call the guard at a locked-down provider
  boundary. Prevent bypass paths and never let the agent call provider APIs
  directly. A denied decision alone cannot halt a payment.
- **No provider lifecycle reconciliation**. Current spending reservations are
  conservative, never automatically released, and are not captures. Implement
  provider idempotency and durable reconciliation for pending/failed/refunded
  outcomes without weakening replay protection.
- **SQLite is single-host only**. All workers for one payment account must use
  the same local filesystem database. Do not place it on NFS/network storage,
  run it across hosts, or put it in an ephemeral container volume.
  Multi-host services require a separately audited transactional database.
- **Single spending scope**. Each ledger database must correspond to exactly
  one payment account/policy scope. Separate ledgers by tenant and payment
  account; otherwise caps can be accidentally shared or bypassed.
- **No secret lifecycle**. Add KMS/HSM-backed key custody, key rotation and
  revocation, environment separation, incident response and recovery procedures.
- **No immutable audit trail**. A privileged backend operator with database
  access can alter ledger entries. Add append-only audit logs and alerting.
- **No identity/legal/compliance work**. Add secure authentication, payment
  provider integration, data privacy controls, PCI/financial compliance review,
  and independent security assessment before real-money use.

## Operational requirements
- Generate signing keys from a cryptographically secure RNG (>= 32 bytes).
- Never commit a live secret or log a signed approval token.
- Run the payment-control backend outside the model's permission boundary.
- Protect the SQLite database file with restrictive filesystem permissions
  and durable backups; validate permissions during deployment.
- Keep time synchronized; expiry verification depends on backend clock.
- Use the same provider idempotency key as the guard request_id.
- Do not have an automated retries path that evades the guard or changes IDs.
- Do not use a denied request to teach the agent secrets or policy contents.
- Do not use real customer information or money in prototype tests.

## Reporting
Open a private security advisory on GitHub for exploitable security problems
rather than posting live payment credentials, approval tokens, or secrets.
Development feedback with fake data can go in regular GitHub issues.

# Agent Payment Guard — experimental developer preview

A small Python policy checker that developers can call before an AI agent's payment API request. **This library does not process, intercept, or block payments on its own.**

## Current checks
- Exact merchant allowlist (case-insensitive)
- Maximum individual USD payment amount
- Independent human approval required by default
- Fail-closed checks for missing, invalid, non-finite, negative and sub-cent amounts

## Run local tests

Requires Python 3.10+; no external dependencies.

```bash
python -m unittest discover -s tests -v
```

## Example

```python
from decimal import Decimal
from Payment_guard import Policy, authorize

policy = Policy(frozenset({"Example Store"}), Decimal("50.00"))
decision = authorize("Example Store", "19.99", policy, approved=False)
print(decision)  # False: independent human approval required
```

Only the trusted, payment-controlling backend should configure policy, verify human consent, set `approved=True` and enforce `decision.allowed`. Do not let the AI agent decide it was approved.

## Limitations and safety

**Not production-ready. Do not use real money or credentials in tests.** No integration with payment providers, cumulative spending limits, transaction identity, replay protection, tamper-resistant approval, audit logging or threat-model review. A developer integrating the checker must enforce it at the actual payment boundary.

## Looking for developer feedback

Open an Issue to report failed cases, bypass opportunities, or integration suggestions. Include steps to reproduce, expected result and actual result. Use fake merchants and amounts only.

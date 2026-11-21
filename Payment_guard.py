"""Experimental policy-only AI agent payment guard. Does not move or block funds."""
import base64
import hashlib
import hmac
import json
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from durable_store import SQLiteReplayStore


def _usd(raw):
    if not isinstance(raw, str) or not raw or len(raw) > 64:
        return None
    try:
        amount = Decimal(raw)
        if not amount.is_finite() or amount <= 0 or amount != amount.quantize(Decimal("0.01")):
            return None
        return amount
    except (InvalidOperation, ValueError):
        return None


@dataclass(frozen=True)
class Policy:
    # Use stable provider payee/account IDs, not merchant display names.
    allowed_merchants: frozenset[str]
    max_transaction_usd: Decimal
    require_approval: bool = True
    max_daily_usd: Decimal = Decimal("0")  # Deny by default until configured.

    def __post_init__(self):
        if not isinstance(self.allowed_merchants, frozenset) or not all(
                isinstance(v, str) and bool(v.strip()) for v in self.allowed_merchants):
            raise ValueError("Invalid payee allowlist")
        for cap in (self.max_transaction_usd, self.max_daily_usd):
            if not isinstance(cap, Decimal) or not cap.is_finite() or cap < 0:
                raise ValueError("Invalid spending cap")
        if type(self.require_approval) is not bool:
            raise ValueError("Invalid approval requirement")


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


@dataclass
class ReplayStore:
    """In-memory demo only. Production needs a shared durable atomic store."""
    used_ids: set = field(default_factory=set)
    spent: dict = field(default_factory=dict)
    lock: object = field(default_factory=threading.Lock, repr=False)

    def reserve(self, request_id, nonce, payee_id, utc_day, amount, daily_cap, now):
        with self.lock:
            if request_id in self.used_ids or (nonce is not None and ("nonce", nonce) in self.used_ids):
                return False, "Replay or duplicate request"
            spent = self.spent.get(utc_day, Decimal("0"))
            if spent + amount > daily_cap:
                return False, "Daily spending cap exceeded"
            self.used_ids.add(request_id)
            if nonce is not None:
                self.used_ids.add(("nonce", nonce))
            self.spent[utc_day] = spent + amount
        return True, "Policy reservation passed; backend must enforce payment outcome"


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def sign_approval(payee_id, amount_usd, request_id, nonce, expires_at, secret):
    """Backend ONLY, after authenticated human consent; never expose to an AI agent."""
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise ValueError("Signing secret must be at least 32 bytes")
    amount = _usd(amount_usd)
    if amount is None or not all(isinstance(v, str) and bool(v) and len(v) <= 256
                                 for v in (payee_id, request_id, nonce)):
        raise ValueError("Invalid approval fields")
    if type(expires_at) is not int or expires_at <= 0:
        raise ValueError("Invalid expiration")
    payload = {"payee_id": payee_id, "amount_usd": format(amount, ".2f"),
               "currency": "USD", "request_id": request_id,
               "nonce": nonce, "expires_at": expires_at}
    data = _canonical(payload)
    mac = hmac.new(secret, data, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(data + b"." + mac).decode("ascii")


def _approved_nonce(token, secret, payee_id, amount, request_id, now):
    if not isinstance(secret, bytes) or len(secret) < 32 or not isinstance(token, str) or len(token) > 4096:
        return None
    try:
        raw = base64.b64decode(token, altchars=b"-_", validate=True)
        if len(raw) < 34 or raw[-33:-32] != b".":
            return None
        data, mac = raw[:-33], raw[-32:]
        if not hmac.compare_digest(mac, hmac.new(secret, data, hashlib.sha256).digest()):
            return None
        payload = json.loads(data)
        if not isinstance(payload, dict) or data != _canonical(payload):
            return None
        if set(payload) != {"payee_id", "amount_usd", "currency", "request_id", "nonce", "expires_at"}:
            return None
        expiry = payload["expires_at"]
        if (type(expiry) is not int or not now < expiry <= now + 300
                or payload["payee_id"] != payee_id
                or payload["amount_usd"] != format(amount, ".2f")
                or payload["currency"] != "USD"
                or payload["request_id"] != request_id
                or not isinstance(payload["nonce"], str)
                or not payload["nonce"]):
            return None
        return payload["nonce"]
    except (ValueError, TypeError, KeyError, UnicodeError, OverflowError):
        return None


def authorize(payee_id: str, amount_usd: str, policy: Policy,
              approved: bool = False, *, request_id: str = None,
              approval_token: str = None, approval_secret: bytes = None,
              replay_store: ReplayStore = None, now: int = None) -> Decision:
    """Reserve a policy decision, NOT a payment. Backend must enforce decision.

    The legacy approved=True argument is deliberately ignored: it is not proof
    of independent human authorization. Keep policy, signing secret and ledger
    exclusively on the trusted payment backend.
    """
    if not isinstance(policy, Policy):
        return Decision(False, "Invalid policy")
    if not isinstance(payee_id, str) or not payee_id.strip():
        return Decision(False, "Missing payee ID")
    if payee_id not in policy.allowed_merchants:
        return Decision(False, "Payee ID not allowlisted")
    amount = _usd(amount_usd)
    if amount is None:
        return Decision(False, "Invalid USD amount")
    if amount > policy.max_transaction_usd:
        return Decision(False, "Transaction exceeds limit")
    if not isinstance(request_id, str) or not request_id or len(request_id) > 256:
        return Decision(False, "Unique request ID required")
    if not isinstance(replay_store, (ReplayStore, SQLiteReplayStore)):
        return Decision(False, "Replay store required")
    when = int(time.time()) if now is None else now
    if type(when) is not int or when < 0:
        return Decision(False, "Invalid timestamp")
    nonce = None
    if policy.require_approval:
        nonce = _approved_nonce(approval_token, approval_secret, payee_id, amount, request_id, when)
        if nonce is None:
            return Decision(False, "Valid independent human approval required")
    try:
        day = datetime.fromtimestamp(when, tz=timezone.utc).date().isoformat()
    except (ValueError, OverflowError, OSError):
        return Decision(False, "Invalid timestamp")
    allowed, reason = replay_store.reserve(
        request_id, nonce, payee_id, day, amount, policy.max_daily_usd, when
    )
    return Decision(allowed, reason)

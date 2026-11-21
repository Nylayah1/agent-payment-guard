"""Phase 4 OFFLINE ONLY. Ed25519 synthetic identities, SQLite atomic replay and revocations.
No real banking identity, external accounts, payments, API or customer approval.
"""
import hashlib, json, sqlite3, threading, uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

def canon(obj): return json.dumps(obj,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(obj): return hashlib.sha256(canon(obj)).hexdigest()
def epoch(t):
    dt=datetime.fromisoformat(t.replace('Z','+00:00'))
    if dt.tzinfo is None: raise ValueError('naive time')
    return dt.astimezone(timezone.utc)
def seal(body, private): return {'body':body, 'sig':private.sign(canon(body)).hex()}
def verify(token, public):
    try:
        if not isinstance(token,dict) or not isinstance(token.get('body'),dict): return False
        public.verify(bytes.fromhex(token['sig']),canon(token['body']))
        return True
    except (InvalidSignature,KeyError,ValueError,TypeError): return False

@dataclass
class Identities:
    issuer: Ed25519PrivateKey
    agent: Ed25519PrivateKey
    customer: Ed25519PrivateKey
    def __init__(self):
        self.issuer=Ed25519PrivateKey.generate(); self.agent=Ed25519PrivateKey.generate(); self.customer=Ed25519PrivateKey.generate()

class Guard:
    def __init__(self, db_path, ids, issuer_key=None, agent_key=None, customer_key=None, ceiling='200'):
        self.db_path=db_path;self.ids=ids
        self.issuer_key=issuer_key or ids.issuer.public_key()
        self.agent_key=agent_key or ids.agent.public_key()
        self.customer_key=customer_key or ids.customer.public_key()
        self.ceiling=Decimal(ceiling)
        self.lock=threading.Lock()
        with sqlite3.connect(db_path) as c:
            c.execute('PRAGMA journal_mode=WAL')
            c.execute('CREATE TABLE IF NOT EXISTS consumed (request_id TEXT PRIMARY KEY, request_digest TEXT, time TEXT)')
            c.execute('CREATE TABLE IF NOT EXISTS revoked (permission_id TEXT PRIMARY KEY)')
            c.execute('CREATE TABLE IF NOT EXISTS decisions (id INTEGER PRIMARY KEY AUTOINCREMENT, request_id TEXT, verdict TEXT, reasons TEXT, previous_hash TEXT, hash TEXT)')
    def revoke(self,permission_id):
        with sqlite3.connect(self.db_path,timeout=10) as c:
            c.execute('INSERT OR IGNORE INTO revoked VALUES (?)',(permission_id,))
    def judge(self, permission, signed_request, approval=None, now='2026-10-23T12:00:00Z'):
        errors=[]; hold=[]
        p=permission.get('body',{}) if isinstance(permission,dict) else {}
        r=signed_request.get('body',{}) if isinstance(signed_request,dict) else {}
        rid=r.get('request_id')
        if not isinstance(rid,str) or not 8<=len(rid)<=128 or not all(c.isalnum() or c in '-_' for c in rid):
            errors.append('invalid_request_id')
        if not verify(permission,self.issuer_key): errors.append('invalid_issuer_signature')
        if not verify(signed_request,self.agent_key): errors.append('unauthenticated_agent')
        if r.get('agent_id')!='agent-17' or p.get('agent_id')!='agent-17' or r.get('agent_id')!=p.get('agent_id'): errors.append('agent_identity_mismatch')
        if r.get('account_id')!='fake-acct-1' or r.get('account_id')!=p.get('account_id'): errors.append('account_mismatch')
        if r.get('action') not in ('pay_bill','read_balance') or r.get('action') not in p.get('actions',[]): errors.append('action_not_allowed')
        try:
            if not epoch(p['starts_at'])<=epoch(now)<epoch(p['expires_at']): errors.append('permission_not_active')
        except (KeyError,ValueError,TypeError): errors.append('bad_permission_time')
        try:
            amt=Decimal(str(r['amount'])); limit=Decimal(str(p['max_amount'])); threshold=Decimal(str(p['confirm_over']))
            if not all(x.is_finite() for x in (amt,limit,threshold)) or amt<0 or limit<0 or threshold<0: raise ValueError()
        except (InvalidOperation,ValueError,TypeError,KeyError):
            amt=limit=threshold=None; errors.append('bad_amount')
        if r.get('action')=='pay_bill':
            if r.get('payee') not in p.get('payees',[]): errors.append('unapproved_payee')
            if amt is not None and (amt>limit or amt>self.ceiling): errors.append('spending_limit')
            if amt is not None and threshold is not None and amt>threshold:
                a=approval.get('body',{}) if isinstance(approval,dict) else {}
                valid=verify(approval,self.customer_key) and a.get('request_hash')==digest(r) and a.get('permission_id')==p.get('permission_id') and a.get('customer_id')=='customer-1' and a.get('approved') is True
                try: valid=valid and epoch(now)<epoch(a['expires_at'])
                except (KeyError,ValueError,TypeError): valid=False
                if not valid: hold.append('independent_customer_approval_required')
        elif r.get('action')=='read_balance':
            if amt is not None and amt!=0: errors.append('read_action_with_amount')
        # One shared, durable database transaction across restarts/instances.
        with sqlite3.connect(self.db_path,timeout=10,isolation_level=None) as c:
            c.execute('BEGIN IMMEDIATE')
            if c.execute('SELECT 1 FROM revoked WHERE permission_id=?',(p.get('permission_id'),)).fetchone(): errors.append('permission_revoked')
            if isinstance(rid,str) and c.execute('SELECT 1 FROM consumed WHERE request_id=?',(rid,)).fetchone(): errors.append('request_replay')
            verdict='BLOCK' if errors else 'HOLD' if hold else 'ALLOW'
            if verdict=='ALLOW': c.execute('INSERT INTO consumed VALUES (?,?,?)',(rid,digest(r),now))
            reasons=errors or hold
            old=c.execute('SELECT hash FROM decisions ORDER BY id DESC LIMIT 1').fetchone()
            previous=old[0] if old else 'GENESIS'
            record={'request_id':rid,'verdict':verdict,'reasons':reasons,'previous_hash':previous}
            c.execute('INSERT INTO decisions (request_id,verdict,reasons,previous_hash,hash) VALUES (?,?,?,?,?)',(str(rid),verdict,json.dumps(reasons),previous,digest(record)))
            c.execute('COMMIT')
        return {'decision':verdict,'reasons':reasons}
    def audit_chain_ok(self):
        with sqlite3.connect(self.db_path) as c:
            rows=c.execute('SELECT request_id,verdict,reasons,previous_hash,hash FROM decisions ORDER BY id').fetchall()
        previous='GENESIS'
        for rid,verdict,reasons,prev,h in rows:
            if prev!=previous or digest({'request_id':rid if rid!='None' else None,'verdict':verdict,'reasons':json.loads(reasons),'previous_hash':prev})!=h:return False
            previous=h
        return True

def grant(ids, **kw):
    p={'permission_id':'permit-1','agent_id':'agent-17','account_id':'fake-acct-1','actions':['pay_bill','read_balance'],'payees':['electric-co'],'max_amount':'200','confirm_over':'100','starts_at':'2026-10-22T00:00:00Z','expires_at':'2026-10-24T00:00:00Z'}
    p.update(kw);return seal(p,ids.issuer)
def action(ids,**kw):
    r={'request_id':'req-'+uuid.uuid4().hex,'agent_id':'agent-17','account_id':'fake-acct-1','action':'pay_bill','amount':'75','payee':'electric-co'}
    r.update(kw);return seal(r,ids.agent)
def customer_approval(ids, request, **kw):
    a={'request_hash':digest(request['body']),'permission_id':'permit-1','customer_id':'customer-1','approved':True,'expires_at':'2026-10-23T12:10:00Z'}
    a.update(kw);return seal(a,ids.customer)
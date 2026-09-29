"""
AAT core -- conformant reference implementation of the audit-record format,
tamper-evident chaining, and ES256 signature envelope from
draft-sharif-agent-audit-trail-06.

Canonicalization: JCS (RFC 8785) via `rfc8785`.
Chain hash:       prev_hash(N) = hex(SHA-256(JCS(record(N-1) minus batch)))   (Sec 6.1)
Signature:        ES256 = ECDSA P-256 over SHA-256 of JCS(record minus
                  signature/signature_classical/batch), encoded IEEE P1363
                  r||s (64 bytes) as base64url.                              (Sec 6.2)
"""
import uuid, hashlib, base64
from datetime import datetime, timezone

import rfc8785
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature, decode_dss_signature,
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

MANDATORY = (
    "record_id", "timestamp", "agent_id", "agent_version", "session_id",
    "action_type", "action_detail", "outcome", "trust_level",
    "parent_record_id", "prev_hash", "record_phase",
)
ACTION_TYPES = {"tool_call", "tool_response", "decision", "delegation",
                "escalation", "error", "lifecycle"}
OUTCOMES = {"success", "failure", "timeout", "denied", "escalated"}
TRUST_LEVELS = {"L0", "L1", "L2", "L3", "L4"}
PHASES = {"pre_execution", "post_execution", "concurrent"}

_SIG_VALUE_FIELDS = ("signature", "signature_classical")

# SECP256R1 (P-256) group order, for low-S signature normalization.
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


# ---- canonicalization & hashing (Sec 6.1) --------------------------------
def jcs(obj) -> bytes:
    """RFC 8785 JSON Canonicalization Scheme -> deterministic bytes."""
    return rfc8785.dumps(obj)


def _without(record: dict, keys) -> dict:
    return {k: v for k, v in record.items() if k not in keys}


def chain_hash(record: dict) -> str:
    """hex(SHA-256(JCS(record with any 'batch' removed))) -- for prev_hash."""
    canonical = jcs(_without(record, ("batch",)))
    return hashlib.sha256(canonical).hexdigest()


# ---- base64url (RFC 4648 s5, no padding) ---------------------------------
def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64url_d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ---- timestamp / ids -----------------------------------------------------
def now_rfc3339() -> str:
    dt = datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def new_uuid() -> str:
    return str(uuid.uuid4())


# ---- record construction -------------------------------------------------
def build_record(*, agent_id, agent_version, session_id, action_type,
                 action_detail, outcome, trust_level, record_phase,
                 parent_record_id, prev_hash,
                 record_id=None, timestamp=None) -> dict:
    if action_type not in ACTION_TYPES:
        raise ValueError(f"invalid action_type: {action_type}")
    if outcome not in OUTCOMES:
        raise ValueError(f"invalid outcome: {outcome}")
    if trust_level not in TRUST_LEVELS:
        raise ValueError(f"invalid trust_level: {trust_level}")
    if record_phase not in PHASES:
        raise ValueError(f"invalid record_phase: {record_phase}")
    return {
        "record_id": record_id or new_uuid(),
        "timestamp": timestamp or now_rfc3339(),
        "agent_id": agent_id,
        "agent_version": agent_version,
        "session_id": session_id,
        "action_type": action_type,
        "action_detail": action_detail,
        "outcome": outcome,
        "trust_level": trust_level,
        "parent_record_id": parent_record_id,
        "prev_hash": prev_hash,
        "record_phase": record_phase,
    }


# ---- signature envelope (Sec 6.2) ----------------------------------------
def sign_record(record: dict, private_key: ec.EllipticCurvePrivateKey,
                signer_kid: str) -> dict:
    """Add ES256 signature. sig_alg/signer_kid are set BEFORE signing so they
    are covered by the signature. Returns the same dict, mutated."""
    record["sig_alg"] = "ES256"
    record["signer_kid"] = signer_kid
    canonical = jcs(_without(record, _SIG_VALUE_FIELDS + ("batch",)))
    der = private_key.sign(canonical, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    if s > _P256_N // 2:            # low-S normalization (non-malleable)
        s = _P256_N - s
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")   # IEEE P1363 r||s
    record["signature"] = _b64url(raw)
    return record


def verify_signature(record: dict, public_key: ec.EllipticCurvePublicKey) -> bool:
    if "signature" not in record:
        return False
    if record.get("sig_alg", "ES256") != "ES256":
        raise ValueError("only ES256 supported in this reference impl")
    canonical = jcs(_without(record, _SIG_VALUE_FIELDS + ("batch",)))
    raw = _b64url_d(record["signature"])
    if len(raw) != 64:
        return False
    r = int.from_bytes(raw[:32], "big")
    s = int.from_bytes(raw[32:], "big")
    der = encode_dss_signature(r, s)
    try:
        public_key.verify(der, canonical, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


# ---- chain verification (Sec 6.3) ----------------------------------------
def verify_chain(records, public_keys=None):
    """Verify a session trail. public_keys: optional {signer_kid: public_key}
    to check signatures. Returns (ok: bool, issues: list[str])."""
    issues = []
    if not records:
        return True, issues
    g = records[0]
    if g.get("parent_record_id") is not None:
        issues.append("record 0: genesis parent_record_id must be null")
    if g.get("prev_hash") is not None:
        issues.append("record 0: genesis prev_hash must be null")
    for n in range(1, len(records)):
        prev, cur = records[n - 1], records[n]
        expected = chain_hash(prev)
        if cur.get("prev_hash") != expected:
            issues.append(f"record {n}: prev_hash mismatch (chain broken/tampered)")
        if cur.get("parent_record_id") != prev.get("record_id"):
            issues.append(f"record {n}: parent_record_id does not match previous record_id")
    if public_keys is not None:
        for n, rec in enumerate(records):
            if "signature" in rec:
                pk = public_keys.get(rec.get("signer_kid"))
                if pk is None:
                    issues.append(f"record {n}: no public key for signer_kid {rec.get('signer_kid')}")
                elif not verify_signature(rec, pk):
                    issues.append(f"record {n}: signature invalid")
    return (len(issues) == 0), issues


# ---- key helpers ---------------------------------------------------------
def gen_key():
    return ec.generate_private_key(ec.SECP256R1())


def kid_for(public_key: ec.EllipticCurvePublicKey) -> str:
    """RFC 7638 JWK thumbprint for a P-256 key: base64url(SHA-256(JCS of the
    required JWK members {crv, kty, x, y})), no padding."""
    nums = public_key.public_numbers()
    jwk = {
        "crv": "P-256",
        "kty": "EC",
        "x": _b64url(nums.x.to_bytes(32, "big")),
        "y": _b64url(nums.y.to_bytes(32, "big")),
    }
    return _b64url(hashlib.sha256(jcs(jwk)).digest())


# ---- session recorder (maintains the chain) ------------------------------
class Recorder:
    """Builds a signed, hash-chained AAT session. The first record emitted is
    the genesis (parent_record_id=null, prev_hash=null)."""

    def __init__(self, *, agent_id, agent_version, private_key,
                 trust_level="L2", signer_kid=None, session_id=None):
        self.agent_id = agent_id
        self.agent_version = agent_version
        self.key = private_key
        self.kid = signer_kid or kid_for(private_key.public_key())
        self.trust_level = trust_level
        self.session_id = session_id or new_uuid()
        self._last_id = None      # None => next record is genesis
        self._last_hash = None
        self.records = []

    @property
    def public_key(self):
        return self.key.public_key()

    def record(self, *, action_type, action_detail, outcome,
               record_phase, trust_level=None):
        rec = build_record(
            agent_id=self.agent_id,
            agent_version=self.agent_version,
            session_id=self.session_id,
            action_type=action_type,
            action_detail=action_detail,
            outcome=outcome,
            trust_level=trust_level or self.trust_level,
            record_phase=record_phase,
            parent_record_id=self._last_id,   # null for genesis
            prev_hash=self._last_hash,         # null for genesis
        )
        sign_record(rec, self.key, self.kid)
        # prev_hash for the NEXT record is over this complete signed record
        self._last_hash = chain_hash(rec)
        self._last_id = rec["record_id"]
        self.records.append(rec)
        return rec

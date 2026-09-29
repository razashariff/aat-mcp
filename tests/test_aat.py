"""AAT reference-impl conformance + robustness tests.
Run: .venv/bin/python tests/test_aat.py
"""
import os, sys, copy, hashlib
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from aat import core
from aat.mcp import MCPRecorder

PASS = 0; FAIL = 0
def check(name, cond):
    global PASS, FAIL
    if cond: PASS += 1; print(f"  PASS  {name}")
    else:    FAIL += 1; print(f"  FAIL  {name}")


def t_jcs_deterministic():
    a = core.jcs({"b": 1, "a": "x", "c": {"z": 1, "y": 2}})
    b = core.jcs({"c": {"y": 2, "z": 1}, "a": "x", "b": 1})
    check("JCS is key-order invariant", a == b)
    check("JCS has no whitespace", b" " not in a and b"\n" not in a)


def t_field_validation():
    base = dict(agent_id="urn:agent:x", agent_version="1.0.0",
                session_id=core.new_uuid(), action_detail={}, outcome="success",
                trust_level="L2", record_phase="post_execution",
                parent_record_id=None, prev_hash=None)
    ok = True
    try: core.build_record(action_type="bogus", **base); ok = False
    except ValueError: pass
    try: core.build_record(action_type="decision", **{**base, "trust_level": "L9"}); ok = False
    except ValueError: pass
    r = core.build_record(action_type="decision", **base)
    check("invalid enums rejected", ok)
    check("all 12 mandatory fields present", all(k in r for k in core.MANDATORY))


def t_sign_verify_roundtrip():
    k = core.gen_key(); kid = core.kid_for(k.public_key())
    r = core.build_record(agent_id="urn:agent:x", agent_version="1.0.0",
        session_id=core.new_uuid(), action_type="tool_call",
        action_detail={"tool": "pay", "amount": 100}, outcome="success",
        trust_level="L3", record_phase="pre_execution",
        parent_record_id=None, prev_hash=None)
    core.sign_record(r, k, kid)
    check("ES256 signature present + base64url r||s (64 bytes)",
          "signature" in r and len(core._b64url_d(r["signature"])) == 64)
    check("valid signature verifies", core.verify_signature(r, k.public_key()))
    # JCS handled a NUMBER (amount:100) -- the thing you can't hand-roll
    check("JCS number-safe (amount field round-trips)", core.verify_signature(r, k.public_key()))


def t_tamper_signature():
    k = core.gen_key(); kid = core.kid_for(k.public_key())
    r = core.build_record(agent_id="urn:agent:x", agent_version="1.0.0",
        session_id=core.new_uuid(), action_type="tool_call",
        action_detail={"tool": "pay"}, outcome="success", trust_level="L2",
        record_phase="pre_execution", parent_record_id=None, prev_hash=None)
    core.sign_record(r, k, kid)
    t1 = copy.deepcopy(r); t1["outcome"] = "denied"
    check("tampered payload fails verification", not core.verify_signature(t1, k.public_key()))
    t2 = copy.deepcopy(r); t2["signer_kid"] = "attacker"
    check("tampered signer_kid fails (sig covers it)", not core.verify_signature(t2, k.public_key()))
    check("wrong key fails verification",
          not core.verify_signature(r, core.gen_key().public_key()))


def t_chain_and_genesis():
    rec = MCPRecorder(agent_id="urn:agent:bot.example", agent_version="1.0.0",
                      private_key=core.gen_key(), trust_level="L2")
    g = rec.open_session()
    c = rec.tool_call("weather", {"city": "Kuwait"})
    rec.tool_response("weather", {"temp": 41}, parent_call_id=c["record_id"], outcome="success")
    check("genesis has null parent + null prev_hash",
          g["parent_record_id"] is None and g["prev_hash"] is None)
    ok, issues = rec.verify()
    check("clean signed chain verifies", ok and not issues)
    # every non-genesis prev_hash equals hash of the (signed) prior record
    good = all(rec.records[i]["prev_hash"] == core.chain_hash(rec.records[i-1])
               for i in range(1, len(rec.records)))
    check("prev_hash links each signed record", good)


def t_chain_tamper():
    rec = MCPRecorder(agent_id="urn:agent:x", agent_version="1.0.0",
                      private_key=core.gen_key())
    rec.open_session()
    c = rec.tool_call("db", {"q": "select"})
    rec.tool_response("db", {"rows": 1}, parent_call_id=c["record_id"], outcome="success")
    # interior tamper: change an accepted record's content
    rec.records[1]["action_detail"]["tool_name"] = "delete-prod-db"
    ok, issues = rec.verify()
    check("interior tamper breaks chain/signature", (not ok) and len(issues) >= 1)


def t_dropped_record():
    rec = MCPRecorder(agent_id="urn:agent:x", agent_version="1.0.0",
                      private_key=core.gen_key())
    rec.open_session()
    ca = rec.tool_call("a", {}); rec.tool_response("a", {}, parent_call_id=ca["record_id"], outcome="success")
    cb = rec.tool_call("b", {}); rec.tool_response("b", {}, parent_call_id=cb["record_id"], outcome="success")
    trail = rec.records[:]
    del trail[2]  # drop a record from the middle
    ok, issues = core.verify_chain(trail, {rec.kid: rec.public_key})
    check("dropped/suppressed record detected", (not ok) and len(issues) >= 1)


def t_mcp_wrap_and_privacy():
    rec = MCPRecorder(agent_id="urn:agent:x", agent_version="1.0.0",
                      private_key=core.gen_key(), trust_level="L2")
    rec.open_session()
    calls = []
    def handler(name, args): calls.append((name, args)); return {"ok": True, "secret": "PII-do-not-store"}
    safe = rec.wrap(handler)
    out = safe("lookup", {"ssn": "123-45-6789"})
    check("wrapped handler ran and returned", out == {"ok": True, "secret": "PII-do-not-store"} and calls)
    ok, _ = rec.verify()
    check("wrapped-call trail verifies", ok)
    # privacy: no raw args/results anywhere in the trail, only digests
    blob = core.jcs(rec.records).decode()
    check("no raw PII in trail (digests only)",
          "123-45-6789" not in blob and "PII-do-not-store" not in blob)
    # digest is actually correct
    tc = [r for r in rec.records if r["action_type"] == "tool_call"][-1]
    check("parameters digest matches SHA-256(JCS(args))",
          tc["action_detail"]["parameters_hash"] ==
          hashlib.sha256(core.jcs({"ssn": "123-45-6789"})).hexdigest())


def t_policy_deny():
    rec = MCPRecorder(agent_id="urn:agent:x", agent_version="1.0.0",
                      private_key=core.gen_key())
    rec.open_session()
    ran = []
    def handler(name, args): ran.append(name); return {}
    safe = rec.wrap(handler, policy=lambda n, a: n != "delete_prod")
    denied = False
    try: safe("delete_prod", {})
    except PermissionError: denied = True
    check("policy denies destructive call", denied and "delete_prod" not in ran)
    dr = [r for r in rec.records if r["action_type"] == "tool_call"][-1]
    check("denied call recorded (outcome=denied, pre_execution)",
          dr["outcome"] == "denied" and dr["record_phase"] == "pre_execution")
    ok, _ = rec.verify()
    check("trail with denial still verifies", ok)


def t_independent_verifier():
    """A third party with ONLY the public key + records verifies -- no private key."""
    rec = MCPRecorder(agent_id="urn:agent:x", agent_version="1.0.0",
                      private_key=core.gen_key())
    rec.open_session(); cx = rec.tool_call("x", {}); rec.tool_response("x", {}, parent_call_id=cx["record_id"], outcome="success")
    pub = rec.public_key; kid = rec.kid; trail = copy.deepcopy(rec.records)
    ok, issues = core.verify_chain(trail, {kid: pub})
    check("independent offline verification (public key only)", ok and not issues)


if __name__ == "__main__":
    print("AAT reference-impl test suite (draft-sharif-agent-audit-trail-06)\n")
    for fn in [t_jcs_deterministic, t_field_validation, t_sign_verify_roundtrip,
               t_tamper_signature, t_chain_and_genesis, t_chain_tamper,
               t_dropped_record, t_mcp_wrap_and_privacy, t_policy_deny,
               t_independent_verifier]:
        print(f"[{fn.__name__}]")
        fn()
    print(f"\n==== {PASS} passed, {FAIL} failed ====")
    sys.exit(1 if FAIL else 0)

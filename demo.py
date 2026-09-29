import os, sys, json, copy
sys.path.insert(0, os.path.dirname(__file__))
from aat import core
from aat.mcp import MCPRecorder

rec = MCPRecorder(agent_id="urn:agent:payment-bot.acme.example",
                  agent_version="2.1.0", private_key=core.gen_key(),
                  trust_level="L3")
rec.open_session()
safe = rec.wrap(lambda n, a: {"sent": True},
                policy=lambda n, a: n != "delete_prod_db")
safe("send_payment", {"to": "+100", "amount": 50})
try: safe("delete_prod_db", {"table": "customers"})
except PermissionError: pass

print("=== one signed AAT tool_call record (conformant) ===")
tc = [r for r in rec.records if r["action_type"] == "tool_call"][0]
print(json.dumps(tc, indent=2))

ok, issues = rec.verify()
print(f"\n=== trail: {len(rec.records)} records, verify -> {ok} (issues: {issues}) ===")
print("action flow:", [(r["action_type"], r["outcome"]) for r in rec.records])

tampered = copy.deepcopy(rec.records)
tampered[1]["outcome"] = "denied"     # flip an accepted record
ok2, issues2 = core.verify_chain(tampered, {rec.kid: rec.public_key})
print(f"\n=== after 1-field tamper -> verify {ok2}; caught: {issues2[0]} ===")

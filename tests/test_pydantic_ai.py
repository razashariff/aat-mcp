"""Real-client test: run a Pydantic AI agent (with TestModel, no LLM key) that
calls a tool, turn the run into an AAT trail, verify it, cross-verify vs omega.

Run: .venv/bin/python tests/test_pydantic_ai.py
"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from aat import core
from aat.mcp import MCPRecorder
from aat.pydantic_ai import record_run

PASS = 0; FAIL = 0
def check(name, cond):
    global PASS, FAIL
    if cond: PASS += 1; print(f"  PASS  {name}")
    else:    FAIL += 1; print(f"  FAIL  {name}")


def main():
    from pydantic_ai import Agent
    from pydantic_ai.models.test import TestModel

    agent = Agent(TestModel())

    @agent.tool_plain
    def add(a: int, b: int) -> int:
        """Add two numbers."""
        return a + b

    # REAL Pydantic AI run: TestModel invokes the registered tool
    result = agent.run_sync("add some numbers")

    rec = MCPRecorder(agent_id="urn:agent:pai.example", agent_version="1.0.0",
                      private_key=core.gen_key(), trust_level="L2")
    record_run(rec, result)

    types = [r["action_type"] for r in rec.records]
    check("Pydantic AI run produced AAT records", len(rec.records) >= 2)
    check("trail opens with genesis lifecycle", types[0] == "lifecycle")
    check("tool_call recorded from the run", "tool_call" in types)
    check("tool_response recorded from the run", "tool_response" in types)

    tcs = [r for r in rec.records if r["action_type"] == "tool_call"]
    trs = [r for r in rec.records if r["action_type"] == "tool_response"]
    if tcs and trs:
        check("tool_response.parent_call_id links a tool_call",
              trs[0]["action_detail"]["parent_call_id"] == tcs[0]["record_id"])
        check("recorded tool_name matches ('add')",
              tcs[0]["action_detail"]["tool_name"] == "add")

    ok, issues = rec.verify()
    check("Pydantic AI run trail verifies (chain + signatures)", ok and not issues)

    # cross-verify with omega-evidence (optional)
    omega_path = os.environ.get("OMEGA_EVIDENCE_PATH")
    if not omega_path:
        print("  SKIP  omega cross-verify (set OMEGA_EVIDENCE_PATH to enable)")
        return
    try:
        sys.path.insert(0, omega_path)
        from cryptography.hazmat.primitives import serialization
        import omega_evidence.interop.aat as oaat
        pem = rec.public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        res = oaat.verify_chain(rec.records, pubkey_pem=pem)
        check("omega verifies the Pydantic AI trail (ok, all sigs)",
              res.get("ok") is True and res.get("signatures_verified") == len(rec.records))
    except Exception as e:
        print(f"  SKIP  omega cross-verify ({type(e).__name__}: {e})")


if __name__ == "__main__":
    print("AAT x Pydantic AI real-client test\n")
    main()
    print(f"\n==== {PASS} passed, {FAIL} failed ====")
    sys.exit(1 if FAIL else 0)

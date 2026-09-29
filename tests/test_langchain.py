"""Real-client test: run actual LangChain tool execution through the AAT
callback handler and verify the resulting trail (chain + signatures), then
cross-verify against omega-evidence.

Run: .venv/bin/python tests/test_langchain.py
"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from aat import core
from aat.mcp import MCPRecorder
from aat.langchain import AATCallbackHandler

PASS = 0; FAIL = 0
def check(name, cond):
    global PASS, FAIL
    if cond: PASS += 1; print(f"  PASS  {name}")
    else:    FAIL += 1; print(f"  FAIL  {name}")


def main():
    from langchain_core.tools import tool

    @tool
    def add(a: int, b: int) -> int:
        """Add two numbers."""
        return a + b

    @tool
    def boom(x: int) -> int:
        """Always fails."""
        raise ValueError("kaboom")

    rec = MCPRecorder(agent_id="urn:agent:lc.example", agent_version="1.0.0",
                      private_key=core.gen_key(), trust_level="L2")
    handler = AATCallbackHandler(rec)

    # REAL LangChain tool execution -> triggers on_tool_start/on_tool_end
    result = add.invoke({"a": 2, "b": 3}, config={"callbacks": [handler]})
    check("real LangChain tool ran through handler", result == 5)

    # a failing tool -> on_tool_error
    try:
        boom.invoke({"x": 1}, config={"callbacks": [handler]})
    except ValueError:
        pass

    types = [r["action_type"] for r in rec.records]
    check("trail has lifecycle+tool_call+tool_response+error",
          types[0] == "lifecycle" and "tool_call" in types and
          "tool_response" in types and "error" in types)

    # tool_response links to its tool_call via parent_call_id
    tr = next(r for r in rec.records if r["action_type"] == "tool_response")
    tc = next(r for r in rec.records if r["action_type"] == "tool_call")
    check("tool_response.parent_call_id links the tool_call",
          tr["action_detail"]["parent_call_id"] == tc["record_id"])

    ok, issues = handler.verify()
    check("LangChain-generated trail verifies (chain + signatures)", ok and not issues)

    # privacy: raw tool args not stored
    blob = core.jcs(rec.records).decode()
    check("no raw args in trail (digest only)", '"a":2' not in blob and "'a': 2" not in blob)

    # cross-verify with omega-evidence's independent verifier (optional)
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
        check("omega verifies the LangChain trail (ok, all sigs)",
              res.get("ok") is True and res.get("signatures_verified") == len(rec.records))
    except Exception as e:
        print(f"  SKIP  omega cross-verify ({type(e).__name__}: {e})")


if __name__ == "__main__":
    print("AAT x LangChain real-client test\n")
    main()
    print(f"\n==== {PASS} passed, {FAIL} failed ====")
    sys.exit(1 if FAIL else 0)

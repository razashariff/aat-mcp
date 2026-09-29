# aat-mcp

Signed, tamper-evident **audit trail for MCP tool calls**, conformant to
**draft-sharif-agent-audit-trail-06**. Every agent tool invocation becomes a
signed, hash-chained record that an independent party can verify offline,
without trusting the producer.

Containment sandboxes control *what an agent may touch*. This records
*who did what, whether it was allowed, and proves it* — the governance +
evidence layer on top.

## What it does (per the spec)
- 12 mandatory record fields; **JCS (RFC 8785)** canonicalization.
- Chain: `prev_hash(N) = hex(SHA-256(JCS(record(N-1))))`.
- **ES256** signatures (ECDSA P-256 over SHA-256, IEEE-P1363 r‖s, base64url);
  `sig_alg`/`signer_kid` are covered by the signature.
- Pre-execution recording of enforcement decisions (deny is evidence).
- Privacy by design: inputs/outputs are **digested, never stored raw**.

## Quickstart
```python
from aat import core
from aat.mcp import MCPRecorder

rec = MCPRecorder(agent_id="urn:agent:bot.example", agent_version="1.0.0",
                  private_key=core.gen_key(), trust_level="L2")
rec.open_session()

# wrap any MCP tool handler; every call is recorded + policy-gated
safe = rec.wrap(handler, policy=lambda name, args: name != "delete_prod_db")
safe("send_payment", {"to": "+100", "amount": 50})

ok, issues = rec.verify()          # chain + every signature
```

## Verify offline (third party, public key only)
```python
from aat import core
ok, issues = core.verify_chain(records, {kid: public_key})
```

## Tests
`.venv/bin/python tests/test_aat.py` — 23/23 (chain, signatures, tamper on every
axis, dropped-record detection, MCP flow, policy-deny, privacy, independent verify).

Apache-2.0. Reference implementation of an open IETF draft.

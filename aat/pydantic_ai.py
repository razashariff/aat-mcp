"""
AAT x Pydantic AI -- turn a Pydantic AI run into a signed, hash-chained AAT
trail, conformant to draft-sharif-agent-audit-trail-06.

Pydantic AI records tool activity natively in the run's message stream
(ToolCallPart / ToolReturnPart, linked by tool_call_id). This reads that stream
and emits AAT tool_call / tool_response records, linked by parent_call_id.

    from aat import core
    from aat.mcp import MCPRecorder
    from aat.pydantic_ai import record_run

    result = agent.run_sync("...")
    rec = MCPRecorder(agent_id="urn:agent:pai.example", agent_version="1.0.0",
                      private_key=core.gen_key(), trust_level="L2")
    record_run(rec, result)
    ok, issues = rec.verify()

Args/content are digested (SHA-256 over JCS), never stored raw.
"""
import hashlib
from . import core


def _jsonable(v):
    if isinstance(v, (str, int, float, bool, type(None), list, dict)):
        return v
    return str(v)


def _digest(obj) -> str:
    return hashlib.sha256(core.jcs(_jsonable(obj))).hexdigest()


def record_run(recorder, result, *, open_session=True):
    """Walk a Pydantic AI run result's messages, emitting a signed AAT trail
    into `recorder` (an aat.mcp.MCPRecorder). Returns the recorder."""
    from pydantic_ai.messages import ToolCallPart, ToolReturnPart

    if open_session and not recorder.records:
        recorder.open_session()

    callmap = {}  # tool_call_id -> AAT record_id
    for msg in result.all_messages():
        for part in getattr(msg, "parts", []):
            if isinstance(part, ToolCallPart):
                args = part.args
                if isinstance(args, str):
                    try:
                        import json
                        args = json.loads(args)
                    except Exception:
                        pass
                rec = recorder.tool_call(part.tool_name, _jsonable(args))
                if getattr(part, "tool_call_id", None):
                    callmap[part.tool_call_id] = rec["record_id"]
            elif isinstance(part, ToolReturnPart):
                pid = callmap.get(getattr(part, "tool_call_id", None), "")
                outcome = "success"
                if getattr(part, "outcome", None) in core.OUTCOMES:
                    outcome = part.outcome
                recorder.tool_response(part.tool_name, _jsonable(part.content),
                                       parent_call_id=pid, outcome=outcome)
    return recorder

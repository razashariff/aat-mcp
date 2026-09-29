"""
AAT x MCP -- middleware emitting a signed, hash-chained AAT trail for MCP tool
invocations, conformant to draft-sharif-agent-audit-trail-06 action taxonomy
(Section 7) and genesis rules (Section 8.1).

Privacy by design (Sec 1/3): parameters and responses are DIGESTED
(SHA-256 over their JCS form), never stored raw, in action_detail.

Usage:
    rec = MCPRecorder(agent_id="urn:agent:bot.example", agent_version="1.0.0",
                      private_key=core.gen_key(), trust_level="L2")
    rec.open_session()
    safe = rec.wrap(handler, policy=lambda name, args: name != "delete_prod_db")
    result = safe("weather", {"city": "Kuwait"})
    ok, issues = rec.verify()
"""
import hashlib
from . import core


def _digest(obj) -> str:
    return hashlib.sha256(core.jcs(obj)).hexdigest()


class MCPRecorder(core.Recorder):
    # ---- lifecycle (Sec 7.7 / 8.1) --------------------------------------
    def open_session(self):
        """Genesis record: action_type=lifecycle, action_detail.event=session_start."""
        return self.record(
            action_type="lifecycle",
            action_detail={"event": "session_start", "recording_mode": "self"},
            outcome="success",
            record_phase="concurrent",   # genesis MUST be concurrent (Sec 8.1)
        )

    def close_session(self):
        return self.record(
            action_type="lifecycle",
            action_detail={"event": "session_end"},
            outcome="success",
            record_phase="post_execution",
        )

    # ---- tool call / response (Sec 7.1 / 7.2) ---------------------------
    def tool_call(self, tool_name, arguments, *, allowed=True, tool_server=None):
        """Pre-execution record (evidence of the enforcement decision, Sec 4)."""
        detail = {"tool_name": tool_name, "parameters_hash": _digest(arguments)}
        if tool_server:
            detail["tool_server"] = tool_server
        return self.record(
            action_type="tool_call",
            action_detail=detail,
            outcome="success" if allowed else "denied",
            record_phase="pre_execution",
        )

    def tool_response(self, tool_name, result, *, parent_call_id, outcome="success"):
        """Post-execution record; parent_call_id links back to the tool_call."""
        return self.record(
            action_type="tool_response",
            action_detail={
                "tool_name": tool_name,
                "response_hash": _digest(result),
                "parent_call_id": parent_call_id,
            },
            outcome=outcome,
            record_phase="post_execution",
        )

    # ---- error (Sec 7.6) ------------------------------------------------
    def error(self, error_code, error_message, *, error_category="internal",
              recoverable=False):
        return self.record(
            action_type="error",
            action_detail={
                "error_code": error_code,
                "error_message": error_message,
                "error_category": error_category,
                "recoverable": recoverable,
            },
            outcome="failure",
            record_phase="post_execution",
        )

    # ---- middleware -----------------------------------------------------
    def wrap(self, handler, *, policy=None):
        """Return wrapped(name, arguments) -> result that records a pre-execution
        tool_call and a post-execution tool_response (linked by parent_call_id)
        around every call. `policy(name, args) -> bool` may deny: a denied call is
        recorded (outcome=denied) and raises PermissionError without running the
        handler."""
        def wrapped(name, arguments):
            allowed = True if policy is None else bool(policy(name, arguments))
            call = self.tool_call(name, arguments, allowed=allowed)
            if not allowed:
                raise PermissionError(f"AAT policy denied tool '{name}'")
            try:
                result = handler(name, arguments)
            except Exception as e:
                self.error("handler_exception", type(e).__name__,
                           error_category="internal", recoverable=False)
                raise
            self.tool_response(name, result, parent_call_id=call["record_id"],
                               outcome="success")
            return result
        return wrapped

    def verify(self):
        return core.verify_chain(self.records, {self.kid: self.public_key})

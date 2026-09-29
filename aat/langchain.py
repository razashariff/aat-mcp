"""
AAT x LangChain -- a callback handler that emits a signed, hash-chained AAT
trail for every LangChain tool invocation, conformant to
draft-sharif-agent-audit-trail-06.

Drop it into any LangChain run:

    from aat import core
    from aat.mcp import MCPRecorder
    from aat.langchain import AATCallbackHandler

    rec = MCPRecorder(agent_id="urn:agent:lc.example", agent_version="1.0.0",
                      private_key=core.gen_key(), trust_level="L2")
    handler = AATCallbackHandler(rec)                 # opens the session
    result = my_tool.invoke({"x": 1}, config={"callbacks": [handler]})
    ok, issues = handler.verify()

Inputs/outputs are digested (SHA-256 over JCS), never stored raw.
"""
from langchain_core.callbacks.base import BaseCallbackHandler

from . import core


def _jsonable(v):
    """Coerce a LangChain value into something JCS can canonicalize."""
    if isinstance(v, (str, int, float, bool, type(None), list, dict)):
        return v
    return str(v)


def _digest(obj) -> str:
    import hashlib
    return hashlib.sha256(core.jcs(_jsonable(obj))).hexdigest()


class AATCallbackHandler(BaseCallbackHandler):
    def __init__(self, recorder, *, open_session=True):
        self.rec = recorder                # an aat.mcp.MCPRecorder
        self._runs = {}                    # run_id -> (tool_call record_id, tool_name)
        if open_session:
            self.rec.open_session()

    @staticmethod
    def _tool_name(serialized) -> str:
        serialized = serialized or {}
        if serialized.get("name"):
            return serialized["name"]
        idp = serialized.get("id")
        if isinstance(idp, list) and idp:
            return idp[-1]
        return "tool"

    def on_tool_start(self, serialized, input_str, *, run_id,
                      parent_run_id=None, inputs=None, **kwargs):
        name = self._tool_name(serialized)
        params = inputs if inputs is not None else input_str
        call = self.rec.tool_call(name, _jsonable(params))
        self._runs[str(run_id)] = (call["record_id"], name)

    def on_tool_end(self, output, *, run_id, **kwargs):
        rid, name = self._runs.pop(str(run_id), (None, "tool"))
        self.rec.tool_response(name, _jsonable(output),
                               parent_call_id=rid or "", outcome="success")

    def on_tool_error(self, error, *, run_id, **kwargs):
        self._runs.pop(str(run_id), None)
        self.rec.error("tool_error", type(error).__name__,
                       error_category="external", recoverable=False)

    def verify(self):
        return self.rec.verify()

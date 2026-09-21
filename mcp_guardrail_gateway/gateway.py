"""The gateway: a policy-enforcing man-in-the-middle for MCP stdio traffic.

The gateway speaks stdio to an upstream MCP client and, in turn, launches (or is
handed) a downstream MCP server. JSON-RPC messages are newline-delimited. On the
request path (client -> server) it applies policy and may block a `tools/call`
by synthesizing a JSON-RPC error back to the client without forwarding it. On
the response path (server -> client) it redacts the audit copy and forwards the
original untouched.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from typing import Any, Optional, TextIO

from .audit import Auditor
from .policy import ALLOW, PolicyEngine
from .redaction import Redactor

BLOCK_ERROR_CODE = -32001  # inside the JSON-RPC "server error" reserved range


@dataclass
class _Handled:
    forward: Optional[str]           # raw line to send to the server, or None
    client_reply: Optional[str]      # raw line to send back to the client, or None


class Gateway:
    def __init__(self, engine: PolicyEngine, redactor: Redactor, auditor: Auditor,
                 mode: str = "enforce", clock=time.monotonic):
        self.engine = engine
        self.redactor = redactor
        self.auditor = auditor
        self.mode = mode
        self.clock = clock
        self._pending = {}          # json-rpc id -> request start (perf clock)
        self._pending_lock = threading.Lock()
        self._out_lock = threading.Lock()

    # ---- request path -----------------------------------------------------

    def handle_client_line(self, line: str) -> _Handled:
        line = line.strip()
        if not line:
            return _Handled(None, None)
        try:
            msg = json.loads(line)
        except ValueError:
            self.auditor.record({"direction": "request", "method": "<parse-error>",
                                 "decision": "n/a", "forwarded": True})
            return _Handled(line, None)

        method = msg.get("method")
        msg_id = msg.get("id")

        if method != "tools/call":
            # Non tool-call traffic passes through; remember request start for latency.
            if msg_id is not None:
                with self._pending_lock:
                    self._pending[_key(msg_id)] = time.perf_counter()
            self.auditor.record({"direction": "request", "method": method or "<notification>",
                                 "id": msg_id, "decision": "n/a", "forwarded": True})
            return _Handled(line, None)

        params = msg.get("params") or {}
        tool = params.get("name", "")
        arguments = params.get("arguments", {})
        decision = self.engine.decide(tool, arguments, self.clock())

        red_args, n_red = self.redactor.redact_arguments(arguments)
        enforced = (not decision.allowed) and self.mode == "enforce"
        event = {
            "direction": "request",
            "method": method,
            "id": msg_id,
            "tool": tool,
            "decision": decision.code,
            "rule": decision.rule,
            "reason": decision.reason,
            "allowed": decision.allowed,
            "mode": self.mode,
            "enforced": enforced,
            "arguments": red_args,
            "redactions": n_red,
            "forwarded": (decision.allowed or self.mode == "monitor"),
        }
        self.auditor.record(event)

        if decision.allowed or self.mode == "monitor":
            if msg_id is not None:
                with self._pending_lock:
                    self._pending[_key(msg_id)] = time.perf_counter()
            return _Handled(line, None)

        # Enforced block: reply to the client, do not forward.
        reply = _block_reply(msg_id, decision)
        return _Handled(None, json.dumps(reply))

    # ---- response path ----------------------------------------------------

    def handle_server_line(self, line: str) -> Optional[str]:
        line = line.strip()
        if not line:
            return None
        try:
            msg = json.loads(line)
        except ValueError:
            self.auditor.record({"direction": "response", "method": "<parse-error>",
                                 "decision": "n/a"})
            return line

        msg_id = msg.get("id")
        latency_ms = None
        if msg_id is not None:
            with self._pending_lock:
                start = self._pending.pop(_key(msg_id), None)
            if start is not None:
                latency_ms = round((time.perf_counter() - start) * 1000, 3)

        _red_result, n_red = self.redactor.redact_value(msg.get("result", {}))
        self.auditor.record({
            "direction": "response",
            "id": msg_id,
            "decision": "n/a",
            "latency_ms": latency_ms,
            "is_error": "error" in msg,
            "redactions": n_red,
        })
        return line  # forward original untouched

    # ---- threaded run -----------------------------------------------------

    def run(self, client_in: TextIO, client_out: TextIO,
            server_in: TextIO, server_out: TextIO) -> None:
        def pump_responses():
            for raw in iter(server_out.readline, ""):
                out = self.handle_server_line(raw)
                if out is not None:
                    self._write(client_out, out)

        resp_thread = threading.Thread(target=pump_responses, daemon=True)
        resp_thread.start()

        try:
            for raw in iter(client_in.readline, ""):
                handled = self.handle_client_line(raw)
                if handled.forward is not None:
                    server_in.write(handled.forward.rstrip("\n") + "\n")
                    server_in.flush()
                if handled.client_reply is not None:
                    self._write(client_out, handled.client_reply)
        finally:
            try:
                server_in.close()
            except Exception:
                pass
            resp_thread.join(timeout=10)

    def _write(self, stream: TextIO, line: str) -> None:
        with self._out_lock:
            stream.write(line.rstrip("\n") + "\n")
            stream.flush()


def _key(msg_id: Any) -> str:
    return "%s:%r" % (type(msg_id).__name__, msg_id)


def _block_reply(msg_id: Any, decision) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {
            "code": BLOCK_ERROR_CODE,
            "message": "blocked by guardrail: %s" % (decision.reason or decision.code),
            "data": {"decision": decision.code, "rule": decision.rule},
        },
    }

import json
import unittest

from mcp_guardrail_gateway.audit import Auditor
from mcp_guardrail_gateway.config import Policy
from mcp_guardrail_gateway.gateway import Gateway
from mcp_guardrail_gateway.policy import PolicyEngine
from mcp_guardrail_gateway.redaction import Redactor


def make_gateway(obj, mode="enforce"):
    policy = Policy.from_obj(obj)
    engine = PolicyEngine(policy)
    redactor = Redactor(policy.redaction.arg_names, policy.redaction.patterns,
                        policy.redaction.builtin)
    auditor = Auditor()
    gw = Gateway(engine, redactor, auditor, mode=mode, clock=lambda: 0.0)
    return gw, auditor


def call(tool, arguments, msg_id=1):
    return json.dumps({"jsonrpc": "2.0", "id": msg_id, "method": "tools/call",
                       "params": {"name": tool, "arguments": arguments}})


class GatewayRequestTest(unittest.TestCase):
    def test_allowed_call_is_forwarded(self):
        gw, _ = make_gateway({"tools": {"default": "allow"}})
        handled = gw.handle_client_line(call("echo", {"text": "hi"}))
        self.assertIsNotNone(handled.forward)
        self.assertIsNone(handled.client_reply)

    def test_denied_call_is_blocked_with_error(self):
        gw, _ = make_gateway({"tools": {"deny": ["delete_file"]}})
        handled = gw.handle_client_line(call("delete_file", {"path": "x"}))
        self.assertIsNone(handled.forward)
        reply = json.loads(handled.client_reply)
        self.assertEqual(reply["id"], 1)
        self.assertIn("error", reply)
        self.assertEqual(reply["error"]["data"]["decision"], "deny-list")

    def test_monitor_mode_forwards_but_records_block(self):
        gw, auditor = make_gateway({"tools": {"deny": ["delete_file"]}}, mode="monitor")
        handled = gw.handle_client_line(call("delete_file", {"path": "x"}))
        self.assertIsNotNone(handled.forward)     # forwarded despite the deny
        self.assertIsNone(handled.client_reply)
        req = [e for e in auditor.events if e["direction"] == "request"][0]
        self.assertFalse(req["allowed"])
        self.assertFalse(req["enforced"])         # not enforced in monitor mode

    def test_password_argument_redacted_in_audit(self):
        gw, auditor = make_gateway(
            {"tools": {"default": "allow"}, "redaction": {"arg_names": ["password"]}})
        gw.handle_client_line(call("login", {"username": "shri", "password": "hunter2"}))
        req = [e for e in auditor.events if e["direction"] == "request"][0]
        self.assertEqual(req["arguments"]["password"], "[REDACTED]")
        self.assertEqual(req["arguments"]["username"], "shri")

    def test_non_toolcall_passes_through(self):
        gw, _ = make_gateway({"tools": {"default": "deny"}})
        handled = gw.handle_client_line(
            json.dumps({"jsonrpc": "2.0", "id": 9, "method": "tools/list"}))
        self.assertIsNotNone(handled.forward)
        self.assertIsNone(handled.client_reply)

    def test_malformed_line_is_forwarded(self):
        gw, auditor = make_gateway({"tools": {"default": "allow"}})
        handled = gw.handle_client_line("this is not json")
        self.assertEqual(handled.forward, "this is not json")

    def test_response_latency_and_redaction(self):
        gw, auditor = make_gateway({"tools": {"default": "allow"}})
        gw.handle_client_line(call("dump_config", {}, msg_id=7))
        resp = {"jsonrpc": "2.0", "id": 7,
                "result": {"content": [{"type": "text", "text": "api sk-abcdef0123456789"}]}}
        out = gw.handle_server_line(json.dumps(resp))
        # original forwarded untouched (secret still present downstream)
        self.assertIn("sk-abcdef0123456789", out)
        # but the audit copy counted a redaction
        resp_event = [e for e in auditor.events if e["direction"] == "response"][0]
        self.assertEqual(resp_event["id"], 7)
        self.assertGreaterEqual(resp_event["redactions"], 1)
        self.assertIsNotNone(resp_event["latency_ms"])


if __name__ == "__main__":
    unittest.main()

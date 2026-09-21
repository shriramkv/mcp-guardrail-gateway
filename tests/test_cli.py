import io
import os
import sys
import unittest
from contextlib import redirect_stdout

from mcp_guardrail_gateway import cli
from mcp_guardrail_gateway.audit import Auditor
from mcp_guardrail_gateway.config import load_file
from mcp_guardrail_gateway.gateway import Gateway
from mcp_guardrail_gateway.policy import PolicyEngine
from mcp_guardrail_gateway.redaction import Redactor

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE = os.path.join(HERE, "..", "mcp_guardrail_gateway", "samples", "policy.yaml")


class CheckCommandTest(unittest.TestCase):
    def test_check_valid(self):
        self.assertEqual(cli.main(["check", "--policy", SAMPLE]), 0)

    def test_check_invalid(self, ):
        bad = os.path.join(HERE, "_bad_policy.yaml")
        with open(bad, "w", encoding="utf-8") as fh:
            fh.write("mode: nonsense\n")
        try:
            self.assertEqual(cli.main(["check", "--policy", bad]), 1)
        finally:
            os.remove(bad)


class DemoEndToEndTest(unittest.TestCase):
    def _run(self, mode):
        policy = load_file(SAMPLE)
        engine = PolicyEngine(policy)
        redactor = Redactor(policy.redaction.arg_names, policy.redaction.patterns,
                            policy.redaction.builtin)
        auditor = Auditor()
        gw = Gateway(engine, redactor, auditor, mode=mode)
        server_cmd = [sys.executable, "-m", "mcp_guardrail_gateway.samples.server"]
        replies = cli.run_scripted(gw, server_cmd, cli.DEMO_SCRIPT)
        return replies, auditor

    def test_enforce_blocks_expected_calls(self):
        replies, auditor = self._run("enforce")
        by_id = {r["id"]: r for r in replies}
        # delete_file (id 10) deny-listed, read_file traversal (id 9) guarded,
        # third add (id 7) rate-limited -> all errors
        self.assertIn("error", by_id[10])
        self.assertIn("error", by_id[9])
        self.assertIn("error", by_id[7])
        # allowed ones came back fine
        self.assertIn("result", by_id[3])   # echo
        self.assertIn("result", by_id[8])   # read_file notes.txt
        self.assertIn("result", by_id[11])  # dump_config

        decisions = auditor.summary()["decisions"]
        self.assertEqual(decisions.get("deny-list"), 1)
        self.assertEqual(decisions.get("guard"), 1)
        self.assertEqual(decisions.get("rate-limited"), 1)

    def test_enforce_redacts_password_and_response_secret(self):
        replies, auditor = self._run("enforce")
        # password redacted on the request side
        login_req = [e for e in auditor.events
                     if e["direction"] == "request" and e.get("tool") == "login"][0]
        self.assertEqual(login_req["arguments"]["password"], "[REDACTED]")
        # dump_config response secret counted as a redaction in the audit copy...
        self.assertGreaterEqual(auditor.summary()["redactions"], 2)
        # ...but the client still received the real secret (gateway does not corrupt)
        cfg = [r for r in replies if r.get("id") == 11][0]
        text = cfg["result"]["content"][0]["text"]
        self.assertIn("sk-live", text)

    def test_monitor_mode_forwards_everything(self):
        replies, auditor = self._run("monitor")
        by_id = {r["id"]: r for r in replies}
        # in monitor mode nothing is blocked: delete_file reaches the server
        self.assertIn("result", by_id[10])
        self.assertIn("deleted", by_id[10]["result"]["content"][0]["text"])
        # but the audit still records what WOULD have been blocked
        blocked_observations = [e for e in auditor.events
                                if e["direction"] == "request" and e.get("allowed") is False]
        self.assertGreaterEqual(len(blocked_observations), 3)
        self.assertTrue(all(e["enforced"] is False for e in blocked_observations))

    def test_demo_command_runs(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.main(["demo"])
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertIn("BLOCKED", out)
        self.assertIn("session summary", out)


if __name__ == "__main__":
    unittest.main()

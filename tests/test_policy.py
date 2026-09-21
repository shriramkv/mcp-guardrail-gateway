import unittest

from mcp_guardrail_gateway.config import Policy
from mcp_guardrail_gateway.policy import (
    ALLOW, DENY_DEFAULT, DENY_LIST, GUARD, RATE_LIMITED, PolicyEngine,
)


def engine(obj):
    return PolicyEngine(Policy.from_obj(obj))


class DecisionTest(unittest.TestCase):
    def test_deny_list_blocks(self):
        e = engine({"tools": {"default": "allow", "deny": ["delete_file"]}})
        d = e.decide("delete_file", {}, 0.0)
        self.assertFalse(d.allowed)
        self.assertEqual(d.code, DENY_LIST)

    def test_default_deny_blocks_unlisted(self):
        e = engine({"tools": {"default": "deny", "allow": ["echo"]}})
        self.assertTrue(e.decide("echo", {}, 0.0).allowed)
        d = e.decide("other", {}, 0.0)
        self.assertFalse(d.allowed)
        self.assertEqual(d.code, DENY_DEFAULT)

    def test_default_allow_permits_unlisted(self):
        e = engine({"tools": {"default": "allow"}})
        self.assertTrue(e.decide("anything", {}, 0.0).allowed)

    def test_arg_guard_pattern(self):
        e = engine({"arg_guards": [
            {"id": "no-traversal", "applies_to": ["read_file"], "deny_pattern": r"\.\./"}]})
        self.assertTrue(e.decide("read_file", {"path": "notes.txt"}, 0.0).allowed)
        d = e.decide("read_file", {"path": "../../etc/passwd"}, 0.0)
        self.assertFalse(d.allowed)
        self.assertEqual(d.code, GUARD)
        self.assertEqual(d.rule, "no-traversal")

    def test_arg_guard_scoped_by_tool(self):
        e = engine({"arg_guards": [
            {"id": "t", "applies_to": ["read_file"], "deny_pattern": r"\.\./"}]})
        # other tools are not subject to this guard
        self.assertTrue(e.decide("echo", {"text": "../x"}, 0.0).allowed)

    def test_max_arg_bytes(self):
        e = engine({"arg_guards": [{"id": "big", "max_arg_bytes": 5}]})
        self.assertTrue(e.decide("echo", {"text": "hi"}, 0.0).allowed)
        self.assertFalse(e.decide("echo", {"text": "way too long"}, 0.0).allowed)

    def test_per_tool_rate_limit(self):
        e = engine({"rate_limits": {"per_tool": {"add": {"max_calls": 2, "per_seconds": 60}}}})
        self.assertTrue(e.decide("add", {}, 0.0).allowed)
        self.assertTrue(e.decide("add", {}, 1.0).allowed)
        d = e.decide("add", {}, 2.0)
        self.assertFalse(d.allowed)
        self.assertEqual(d.code, RATE_LIMITED)

    def test_rate_window_resets(self):
        e = engine({"rate_limits": {"per_tool": {"add": {"max_calls": 1, "per_seconds": 10}}}})
        self.assertTrue(e.decide("add", {}, 0.0).allowed)
        self.assertFalse(e.decide("add", {}, 5.0).allowed)
        self.assertTrue(e.decide("add", {}, 11.0).allowed)  # new window

    def test_global_rate_limit(self):
        e = engine({"rate_limits": {"global": {"max_calls": 1, "per_seconds": 60}}})
        self.assertTrue(e.decide("a", {}, 0.0).allowed)
        self.assertFalse(e.decide("b", {}, 0.0).allowed)

    def test_blocked_call_does_not_consume_rate_token(self):
        # deny-listed tool should not eat a global token
        e = engine({"tools": {"deny": ["bad"]},
                    "rate_limits": {"global": {"max_calls": 1, "per_seconds": 60}}})
        self.assertFalse(e.decide("bad", {}, 0.0).allowed)   # denied, no token used
        self.assertTrue(e.decide("good", {}, 0.0).allowed)   # token still available

    def test_allow_is_clean(self):
        e = engine({"tools": {"default": "allow"}})
        d = e.decide("echo", {"text": "hi"}, 0.0)
        self.assertTrue(d.allowed)
        self.assertEqual(d.code, ALLOW)


if __name__ == "__main__":
    unittest.main()

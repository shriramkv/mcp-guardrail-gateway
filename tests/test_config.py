import os
import unittest

from mcp_guardrail_gateway import yamlmini
from mcp_guardrail_gateway.config import Policy, PolicyError, load_file, load_text

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE = os.path.join(HERE, "..", "mcp_guardrail_gateway", "samples", "policy.yaml")

SAMPLE_YAML = """
version: 1
mode: enforce
tools:
  default: allow
  deny:
    - delete_file
rate_limits:
  per_tool:
    add:
      max_calls: 2
      per_seconds: 60
arg_guards:
  - id: no-path-traversal
    applies_to: [read_file]
    match_args: ["*"]
    deny_pattern: "\\\\.\\\\./"
redaction:
  builtin: true
  arg_names: [password]
  patterns:
    - "sk-[A-Za-z0-9]{10,}"
audit:
  log: null
"""


class YamlMiniTest(unittest.TestCase):
    def test_matches_pyyaml_on_sample(self):
        import yaml
        with open(SAMPLE, "r", encoding="utf-8") as fh:
            text = fh.read()
        self.assertEqual(yamlmini.load(text), yaml.safe_load(text))

    def test_flow_list_and_types(self):
        data = yamlmini.load("a: [1, 2, 3]\nb: true\nc: null\nd: hello\n")
        self.assertEqual(data["a"], [1, 2, 3])
        self.assertIs(data["b"], True)
        self.assertIsNone(data["c"])
        self.assertEqual(data["d"], "hello")

    def test_list_of_maps(self):
        data = yamlmini.load("items:\n  - id: one\n    n: 1\n  - id: two\n    n: 2\n")
        self.assertEqual(data["items"], [{"id": "one", "n": 1}, {"id": "two", "n": 2}])

    def test_comment_stripping(self):
        data = yamlmini.load("a: 1 # trailing\n# whole line\nb: 2\n")
        self.assertEqual(data, {"a": 1, "b": 2})


class ConfigLoadTest(unittest.TestCase):
    def test_vendored_and_pyyaml_agree(self):
        p_vendored = load_text(SAMPLE_YAML, prefer_pyyaml=False)
        p_pyyaml = load_text(SAMPLE_YAML, prefer_pyyaml=True)
        self.assertEqual(p_vendored.deny, p_pyyaml.deny)
        self.assertEqual(p_vendored.per_tool_limits.keys(), p_pyyaml.per_tool_limits.keys())
        self.assertEqual(len(p_vendored.arg_guards), len(p_pyyaml.arg_guards))

    def test_sample_file_loads(self):
        policy = load_file(SAMPLE)
        self.assertEqual(policy.mode, "enforce")
        self.assertIn("delete_file", policy.deny)
        self.assertIn("add", policy.per_tool_limits)
        self.assertEqual(policy.arg_guards[0].id, "no-path-traversal")
        self.assertIn("password", policy.redaction.arg_names)

    def test_json_policy(self):
        policy = load_text('{"mode": "monitor", "tools": {"default": "deny"}}')
        self.assertEqual(policy.mode, "monitor")
        self.assertEqual(policy.default, "deny")

    def test_bad_mode_rejected(self):
        with self.assertRaises(PolicyError):
            Policy.from_obj({"mode": "wibble"})

    def test_bad_default_rejected(self):
        with self.assertRaises(PolicyError):
            Policy.from_obj({"tools": {"default": "maybe"}})

    def test_guard_needs_a_rule(self):
        with self.assertRaises(PolicyError):
            Policy.from_obj({"arg_guards": [{"id": "empty"}]})

    def test_rate_limit_must_be_positive(self):
        with self.assertRaises(PolicyError):
            Policy.from_obj({"rate_limits": {"global": {"max_calls": 0, "per_seconds": 1}}})


if __name__ == "__main__":
    unittest.main()

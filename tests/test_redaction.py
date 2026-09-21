import unittest

from mcp_guardrail_gateway.redaction import PLACEHOLDER, Redactor


class RedactionTest(unittest.TestCase):
    def test_builtin_aws_and_sk(self):
        r = Redactor([], [], builtin=True)
        text, n = r.redact_text("key AKIAIOSFODNN7EXAMPLE and sk-abcdef0123456789xyz")
        self.assertNotIn("AKIA", text)
        self.assertNotIn("sk-abcdef", text)
        self.assertEqual(n, 2)

    def test_arg_name_redaction(self):
        r = Redactor(["password", "token"], [], builtin=False)
        red, n = r.redact_arguments({"username": "shri", "password": "hunter2"})
        self.assertEqual(red["username"], "shri")
        self.assertEqual(red["password"], PLACEHOLDER)
        self.assertEqual(n, 1)

    def test_user_pattern(self):
        r = Redactor([], ["SECRET-[0-9]+"], builtin=False)
        red, n = r.redact_value({"note": "value SECRET-42 here"})
        self.assertIn(PLACEHOLDER, red["note"])
        self.assertEqual(n, 1)

    def test_nested_value_redaction(self):
        r = Redactor([], [], builtin=True)
        red, n = r.redact_value({"a": ["ghp_" + "a" * 30], "b": {"c": "clean"}})
        self.assertIn(PLACEHOLDER, red["a"][0])
        self.assertEqual(red["b"]["c"], "clean")
        self.assertEqual(n, 1)

    def test_no_false_positive_on_plain_text(self):
        r = Redactor([], [], builtin=True)
        text, n = r.redact_text("the quick brown fox jumps over 12 lazy dogs")
        self.assertEqual(n, 0)
        self.assertEqual(text, "the quick brown fox jumps over 12 lazy dogs")


if __name__ == "__main__":
    unittest.main()

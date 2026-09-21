"""Secret redaction for audit records.

Redaction runs over the *audit copy* of requests and responses, never over the
bytes forwarded to the server or back to the client. The gateway records what
happened without persisting secrets into the audit trail.
"""

from __future__ import annotations

import re
from typing import Any, List, Tuple

PLACEHOLDER = "[REDACTED]"

# Conservative, low-false-positive built-in patterns for common secret shapes.
BUILTIN_PATTERNS = [
    r"AKIA[0-9A-Z]{16}",                       # AWS access key id
    r"ASIA[0-9A-Z]{16}",                       # AWS temporary access key id
    r"sk-[A-Za-z0-9_\-]{16,}",                 # OpenAI-style / generic sk- keys
    r"ghp_[A-Za-z0-9]{20,}",                   # GitHub personal access token
    r"xox[baprs]-[A-Za-z0-9\-]{10,}",          # Slack tokens
    r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",  # JWT
    r"(?i)bearer\s+[A-Za-z0-9._\-]{10,}",      # Bearer <token>
]


class Redactor:
    def __init__(self, arg_names: List[str], patterns: List[str], builtin: bool = True):
        self.arg_names = {a.lower() for a in arg_names}
        raw = list(patterns)
        if builtin:
            raw = raw + BUILTIN_PATTERNS
        self.regexes = [re.compile(p) for p in raw]

    def redact_text(self, text: str) -> Tuple[str, int]:
        """Redact secret-looking substrings. Returns (text, num_redactions)."""
        count = 0
        for rx in self.regexes:
            text, n = rx.subn(PLACEHOLDER, text)
            count += n
        return text, count

    def redact_value(self, value: Any) -> Tuple[Any, int]:
        """Recursively redact any string content inside a JSON-like value."""
        if isinstance(value, str):
            return self.redact_text(value)
        if isinstance(value, list):
            total = 0
            out = []
            for item in value:
                red, n = self.redact_value(item)
                out.append(red)
                total += n
            return out, total
        if isinstance(value, dict):
            total = 0
            out = {}
            for key, item in value.items():
                red, n = self.redact_value(item)
                out[key] = red
                total += n
            return out, total
        return value, 0

    def redact_arguments(self, arguments: Any) -> Tuple[Any, int]:
        """Redact tool-call arguments: named args by key, everything by pattern."""
        if not isinstance(arguments, dict):
            return self.redact_value(arguments)
        out = {}
        total = 0
        for key, value in arguments.items():
            if key.lower() in self.arg_names:
                out[key] = PLACEHOLDER
                total += 1
            else:
                red, n = self.redact_value(value)
                out[key] = red
                total += n
        return out, total

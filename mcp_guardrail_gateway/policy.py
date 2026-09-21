"""Runtime decision engine: turns a Policy into allow/deny decisions."""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass
from typing import Any, Dict, Optional

from .config import ArgGuard, Policy, RateLimit

# Decision codes used in the audit trail.
ALLOW = "allow"
DENY_LIST = "deny-list"
DENY_DEFAULT = "deny-default"
RATE_LIMITED = "rate-limited"
GUARD = "guard"


@dataclass
class Decision:
    allowed: bool
    code: str
    rule: Optional[str] = None
    reason: str = ""


class _FixedWindow:
    """A simple fixed-window rate limiter with an injectable clock."""

    def __init__(self, limit: RateLimit):
        self.limit = limit
        self._start = None
        self._count = 0

    def allow(self, now: float) -> bool:
        if self._start is None or (now - self._start) >= self.limit.per_seconds:
            self._start = now
            self._count = 0
        if self._count >= self.limit.max_calls:
            return False
        self._count += 1
        return True


class PolicyEngine:
    def __init__(self, policy: Policy):
        self.policy = policy
        self._allow = set(policy.allow)
        self._deny = set(policy.deny)
        self._global = _FixedWindow(policy.global_limit) if policy.global_limit else None
        self._per_tool: Dict[str, _FixedWindow] = {
            name: _FixedWindow(limit) for name, limit in policy.per_tool_limits.items()
        }
        self._guards = [(g, self._compile(g)) for g in policy.arg_guards]

    @staticmethod
    def _compile(guard: ArgGuard):
        if guard.deny_pattern is None:
            return None
        return re.compile(guard.deny_pattern)

    def decide(self, tool: str, arguments: Any, now: float) -> Decision:
        # 1. Explicit deny list wins.
        if tool in self._deny:
            return Decision(False, DENY_LIST, tool, "tool is on the deny list")
        # 2. Explicit allow list, else default disposition.
        if tool not in self._allow and self.policy.default == "deny":
            return Decision(
                False, DENY_DEFAULT, tool,
                "tool not on allow list and default is deny",
            )
        # 3. Argument guards.
        guard_decision = self._check_guards(tool, arguments)
        if guard_decision is not None:
            return guard_decision
        # 4. Rate limits (checked last so a blocked call does not consume a token).
        rl = self._check_rate(tool, now)
        if rl is not None:
            return rl
        return Decision(True, ALLOW, None, "")

    def _check_guards(self, tool: str, arguments: Any) -> Optional[Decision]:
        args = arguments if isinstance(arguments, dict) else {}
        for guard, regex in self._guards:
            if guard.applies_to and not _matches_any(tool, guard.applies_to):
                continue
            for key, value in args.items():
                if not _matches_any(key, guard.match_args):
                    continue
                text = value if isinstance(value, str) else json.dumps(value)
                if guard.max_arg_bytes is not None and len(text.encode("utf-8")) > guard.max_arg_bytes:
                    return Decision(
                        False, GUARD, guard.id,
                        "argument %r exceeds %d bytes" % (key, guard.max_arg_bytes),
                    )
                if regex is not None and regex.search(text):
                    return Decision(
                        False, GUARD, guard.id,
                        "argument %r matched deny pattern" % key,
                    )
        return None

    def _check_rate(self, tool: str, now: float) -> Optional[Decision]:
        window = self._per_tool.get(tool)
        if window is not None and not window.allow(now):
            return Decision(False, RATE_LIMITED, "per_tool:%s" % tool, "per-tool rate limit exceeded")
        if self._global is not None and not self._global.allow(now):
            return Decision(False, RATE_LIMITED, "global", "global rate limit exceeded")
        return None


def _matches_any(name: str, globs) -> bool:
    return any(fnmatch.fnmatchcase(name, g) for g in globs)

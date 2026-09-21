"""Audit trail: JSONL event log plus an aggregated session summary."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, Optional, TextIO


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class Auditor:
    """Collects audit events, optionally streaming them to a JSONL sink."""

    def __init__(self, sink: Optional[TextIO] = None):
        self._sink = sink
        self.events = []
        self.decisions = Counter()
        self.per_tool = defaultdict(Counter)
        self.blocked = 0
        self.allowed = 0
        self.redactions = 0
        self.requests = 0
        self.responses = 0

    def record(self, event: Dict[str, Any]) -> None:
        event.setdefault("ts", _now_iso())
        self.events.append(event)
        if self._sink is not None:
            self._sink.write(json.dumps(event, sort_keys=True) + "\n")
            self._sink.flush()

        direction = event.get("direction")
        if direction == "request":
            self.requests += 1
        elif direction == "response":
            self.responses += 1

        decision = event.get("decision")
        tool = event.get("tool")
        if decision and decision != "n/a":
            self.decisions[decision] += 1
            if tool:
                self.per_tool[tool][decision] += 1
            if event.get("allowed"):
                self.allowed += 1
            else:
                # A monitored (not enforced) block still counts as observed.
                self.blocked += 1
        self.redactions += int(event.get("redactions", 0) or 0)

    def summary(self) -> Dict[str, Any]:
        return {
            "requests": self.requests,
            "responses": self.responses,
            "allowed": self.allowed,
            "blocked": self.blocked,
            "redactions": self.redactions,
            "decisions": dict(self.decisions),
            "per_tool": {tool: dict(counts) for tool, counts in self.per_tool.items()},
        }

    def render(self, fmt: str = "console") -> str:
        s = self.summary()
        if fmt == "json":
            return json.dumps(s, indent=2, sort_keys=True)
        if fmt == "markdown":
            return _render_markdown(s)
        return _render_console(s)


def _render_console(s: Dict[str, Any]) -> str:
    lines = ["mcp-guardrail-gateway session summary",
             "-" * 38,
             "requests   : %d" % s["requests"],
             "responses  : %d" % s["responses"],
             "allowed    : %d" % s["allowed"],
             "blocked    : %d" % s["blocked"],
             "redactions : %d" % s["redactions"],
             "",
             "decisions:"]
    if s["decisions"]:
        for code, n in sorted(s["decisions"].items()):
            lines.append("  %-14s %d" % (code, n))
    else:
        lines.append("  (none)")
    if s["per_tool"]:
        lines.append("")
        lines.append("per tool:")
        for tool, counts in sorted(s["per_tool"].items()):
            detail = ", ".join("%s=%d" % (c, n) for c, n in sorted(counts.items()))
            lines.append("  %-16s %s" % (tool, detail))
    return "\n".join(lines)


def _render_markdown(s: Dict[str, Any]) -> str:
    lines = ["# Guardrail gateway session summary",
             "",
             "| metric | value |",
             "| --- | --- |",
             "| requests | %d |" % s["requests"],
             "| responses | %d |" % s["responses"],
             "| allowed | %d |" % s["allowed"],
             "| blocked | %d |" % s["blocked"],
             "| redactions | %d |" % s["redactions"],
             "",
             "## Decisions",
             "",
             "| decision | count |",
             "| --- | --- |"]
    for code, n in sorted(s["decisions"].items()):
        lines.append("| %s | %d |" % (code, n))
    return "\n".join(lines)

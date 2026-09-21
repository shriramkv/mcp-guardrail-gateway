"""Policy configuration: data model, loading (JSON / YAML), and validation."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from . import yamlmini

VALID_MODES = ("enforce", "monitor")
VALID_DEFAULT = ("allow", "deny")


class PolicyError(ValueError):
    """Raised when a policy file is structurally invalid."""


@dataclass
class RateLimit:
    max_calls: int
    per_seconds: float

    @staticmethod
    def from_obj(obj: Any, where: str) -> "RateLimit":
        if not isinstance(obj, dict):
            raise PolicyError("%s must be a mapping" % where)
        try:
            mc = int(obj["max_calls"])
            ps = float(obj["per_seconds"])
        except KeyError as exc:
            raise PolicyError("%s missing %s" % (where, exc))
        except (TypeError, ValueError):
            raise PolicyError("%s has non-numeric limit" % where)
        if mc <= 0 or ps <= 0:
            raise PolicyError("%s values must be positive" % where)
        return RateLimit(mc, ps)


@dataclass
class ArgGuard:
    id: str
    deny_pattern: Optional[str] = None
    max_arg_bytes: Optional[int] = None
    match_args: List[str] = field(default_factory=lambda: ["*"])
    applies_to: List[str] = field(default_factory=list)  # empty = all tools

    @staticmethod
    def from_obj(obj: Any, idx: int) -> "ArgGuard":
        if not isinstance(obj, dict):
            raise PolicyError("arg_guards[%d] must be a mapping" % idx)
        gid = str(obj.get("id") or "guard-%d" % idx)
        deny_pattern = obj.get("deny_pattern")
        max_arg_bytes = obj.get("max_arg_bytes")
        if deny_pattern is None and max_arg_bytes is None:
            raise PolicyError(
                "arg_guards[%d] (%s) needs deny_pattern or max_arg_bytes" % (idx, gid)
            )
        if max_arg_bytes is not None:
            try:
                max_arg_bytes = int(max_arg_bytes)
            except (TypeError, ValueError):
                raise PolicyError("arg_guards[%d] max_arg_bytes must be an int" % idx)
        match_args = _as_str_list(obj.get("match_args", ["*"]), "arg_guards[%d].match_args" % idx)
        applies_to = _as_str_list(obj.get("applies_to", []), "arg_guards[%d].applies_to" % idx)
        return ArgGuard(gid, deny_pattern, max_arg_bytes, match_args or ["*"], applies_to)


@dataclass
class RedactionConfig:
    arg_names: List[str] = field(default_factory=list)
    patterns: List[str] = field(default_factory=list)
    builtin: bool = True


@dataclass
class Policy:
    version: int = 1
    mode: str = "enforce"
    default: str = "allow"
    allow: List[str] = field(default_factory=list)
    deny: List[str] = field(default_factory=list)
    global_limit: Optional[RateLimit] = None
    per_tool_limits: Dict[str, RateLimit] = field(default_factory=dict)
    arg_guards: List[ArgGuard] = field(default_factory=list)
    redaction: RedactionConfig = field(default_factory=RedactionConfig)
    audit_log: Optional[str] = None

    @staticmethod
    def from_obj(obj: Any) -> "Policy":
        if not isinstance(obj, dict):
            raise PolicyError("top-level policy must be a mapping")

        mode = str(obj.get("mode", "enforce"))
        if mode not in VALID_MODES:
            raise PolicyError("mode must be one of %s" % (VALID_MODES,))

        tools = obj.get("tools", {}) or {}
        if not isinstance(tools, dict):
            raise PolicyError("tools must be a mapping")
        default = str(tools.get("default", "allow"))
        if default not in VALID_DEFAULT:
            raise PolicyError("tools.default must be 'allow' or 'deny'")
        allow = _as_str_list(tools.get("allow", []), "tools.allow")
        deny = _as_str_list(tools.get("deny", []), "tools.deny")

        rl = obj.get("rate_limits", {}) or {}
        if not isinstance(rl, dict):
            raise PolicyError("rate_limits must be a mapping")
        global_limit = None
        if rl.get("global"):
            global_limit = RateLimit.from_obj(rl["global"], "rate_limits.global")
        per_tool: Dict[str, RateLimit] = {}
        pt = rl.get("per_tool", {}) or {}
        if not isinstance(pt, dict):
            raise PolicyError("rate_limits.per_tool must be a mapping")
        for name, spec in pt.items():
            per_tool[str(name)] = RateLimit.from_obj(spec, "rate_limits.per_tool.%s" % name)

        guards_obj = obj.get("arg_guards", []) or []
        if not isinstance(guards_obj, list):
            raise PolicyError("arg_guards must be a sequence")
        guards = [ArgGuard.from_obj(g, i) for i, g in enumerate(guards_obj)]

        red_obj = obj.get("redaction", {}) or {}
        if not isinstance(red_obj, dict):
            raise PolicyError("redaction must be a mapping")
        redaction = RedactionConfig(
            arg_names=_as_str_list(red_obj.get("arg_names", []), "redaction.arg_names"),
            patterns=_as_str_list(red_obj.get("patterns", []), "redaction.patterns"),
            builtin=bool(red_obj.get("builtin", True)),
        )

        audit = obj.get("audit", {}) or {}
        if not isinstance(audit, dict):
            raise PolicyError("audit must be a mapping")
        audit_log = audit.get("log")
        if audit_log is not None:
            audit_log = str(audit_log)

        version = obj.get("version", 1)
        try:
            version = int(version)
        except (TypeError, ValueError):
            raise PolicyError("version must be an integer")

        return Policy(
            version=version,
            mode=mode,
            default=default,
            allow=allow,
            deny=deny,
            global_limit=global_limit,
            per_tool_limits=per_tool,
            arg_guards=guards,
            redaction=redaction,
            audit_log=audit_log,
        )


def _as_str_list(value: Any, where: str) -> List[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise PolicyError("%s must be a list" % where)
    return [str(v) for v in value]


def load_text(text: str, prefer_pyyaml: bool = True) -> Policy:
    """Parse a policy from JSON or YAML text."""
    stripped = text.lstrip()
    if stripped.startswith("{"):
        obj = json.loads(text)
    else:
        obj = _load_yaml(text, prefer_pyyaml)
    return Policy.from_obj(obj)


def load_file(path: str, prefer_pyyaml: bool = True) -> Policy:
    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read()
    ext = os.path.splitext(path)[1].lower()
    if ext == ".json":
        return Policy.from_obj(json.loads(text))
    return load_text(text, prefer_pyyaml)


def _load_yaml(text: str, prefer_pyyaml: bool) -> Any:
    if prefer_pyyaml:
        try:
            import yaml  # type: ignore
            return yaml.safe_load(text)
        except ImportError:
            pass
    return yamlmini.load(text)

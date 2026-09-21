"""Command-line interface for mcp-guardrail-gateway."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from typing import List, Optional

from . import __version__
from .audit import Auditor
from .config import Policy, PolicyError, load_file
from .gateway import Gateway
from .policy import PolicyEngine
from .redaction import Redactor

_HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE_POLICY = os.path.join(_HERE, "samples", "policy.yaml")


def build_stack(policy: Policy, mode: Optional[str], audit_sink=None, clock=None):
    engine = PolicyEngine(policy)
    redactor = Redactor(policy.redaction.arg_names, policy.redaction.patterns,
                        policy.redaction.builtin)
    auditor = Auditor(sink=audit_sink)
    kwargs = {"mode": mode or policy.mode}
    if clock is not None:
        kwargs["clock"] = clock
    gateway = Gateway(engine, redactor, auditor, **kwargs)
    return gateway, auditor


def _open_audit(policy: Policy, override: Optional[str]):
    path = override if override is not None else policy.audit_log
    if path in (None, "", "null", "-"):
        return None, None
    handle = open(path, "w", encoding="utf-8")
    return handle, handle


def cmd_run(args) -> int:
    try:
        policy = load_file(args.policy)
    except (OSError, PolicyError, ValueError) as exc:
        print("policy error: %s" % exc, file=sys.stderr)
        return 2
    if not args.server:
        print("no server command given (put it after '--')", file=sys.stderr)
        return 2

    sink, to_close = _open_audit(policy, args.audit_log)
    gateway, auditor = build_stack(policy, args.mode, audit_sink=sink)

    proc = subprocess.Popen(
        args.server, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        text=True, bufsize=1,
    )
    try:
        gateway.run(sys.stdin, sys.stdout, proc.stdin, proc.stdout)
    finally:
        proc.wait()
        if to_close is not None:
            to_close.close()

    if args.summary:
        print(auditor.render(args.summary), file=sys.stderr)
    return 0


def cmd_check(args) -> int:
    try:
        policy = load_file(args.policy)
    except (OSError, PolicyError, ValueError) as exc:
        print("INVALID: %s" % exc, file=sys.stderr)
        return 1
    print("OK: policy is valid (mode=%s, default=%s, %d deny, %d allow, %d guards)" % (
        policy.mode, policy.default, len(policy.deny), len(policy.allow),
        len(policy.arg_guards),
    ))
    return 0


DEMO_SCRIPT = [
    {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
    {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
     "params": {"name": "echo", "arguments": {"text": "hello"}}},
    {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
     "params": {"name": "login", "arguments": {"username": "shri", "password": "hunter2"}}},
    {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
     "params": {"name": "add", "arguments": {"a": 1, "b": 2}}},
    {"jsonrpc": "2.0", "id": 6, "method": "tools/call",
     "params": {"name": "add", "arguments": {"a": 3, "b": 4}}},
    {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
     "params": {"name": "add", "arguments": {"a": 5, "b": 6}}},
    {"jsonrpc": "2.0", "id": 8, "method": "tools/call",
     "params": {"name": "read_file", "arguments": {"path": "notes.txt"}}},
    {"jsonrpc": "2.0", "id": 9, "method": "tools/call",
     "params": {"name": "read_file", "arguments": {"path": "../../etc/passwd"}}},
    {"jsonrpc": "2.0", "id": 10, "method": "tools/call",
     "params": {"name": "delete_file", "arguments": {"path": "notes.txt"}}},
    {"jsonrpc": "2.0", "id": 11, "method": "tools/call",
     "params": {"name": "dump_config", "arguments": {}}},
]


def run_scripted(gateway: Gateway, server_cmd: List[str], script) -> List[dict]:
    """Drive a scripted client synchronously through the gateway. Deterministic."""
    proc = subprocess.Popen(server_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            text=True, bufsize=1)
    replies = []
    try:
        for msg in script:
            handled = gateway.handle_client_line(json.dumps(msg))
            if handled.forward is not None:
                proc.stdin.write(handled.forward.rstrip("\n") + "\n")
                proc.stdin.flush()
                server_line = proc.stdout.readline()
                out = gateway.handle_server_line(server_line)
                if out is not None:
                    replies.append(json.loads(out))
            if handled.client_reply is not None:
                replies.append(json.loads(handled.client_reply))
    finally:
        proc.stdin.close()
        proc.wait()
        proc.stdout.close()
    return replies


def cmd_demo(args) -> int:
    policy = load_file(SAMPLE_POLICY)
    gateway, auditor = build_stack(policy, args.mode)
    server_cmd = [sys.executable, "-m", "mcp_guardrail_gateway.samples.server"]
    replies = run_scripted(gateway, server_cmd, DEMO_SCRIPT)

    print("=== client-visible replies ===")
    for r in replies:
        if "error" in r:
            print("id %-2s BLOCKED  %s" % (r.get("id"), r["error"]["message"]))
        else:
            content = r.get("result", {}).get("content", [{}])
            text = content[0].get("text", "") if content else ""
            print("id %-2s ok       %s" % (r.get("id"), text))
    print()
    print(auditor.render(args.summary or "console"))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-guardrail-gateway",
        description="Policy-enforcing runtime proxy for MCP servers over stdio.",
    )
    parser.add_argument("--version", action="version",
                        version="mcp-guardrail-gateway %s" % __version__)
    sub = parser.add_subparsers(dest="command")

    p_run = sub.add_parser("run", help="run the gateway in front of an MCP server")
    p_run.add_argument("--policy", required=True, help="policy file (YAML or JSON)")
    p_run.add_argument("--mode", choices=["enforce", "monitor"], default=None,
                       help="override the policy's mode")
    p_run.add_argument("--audit-log", default=None, help="JSONL audit sink path")
    p_run.add_argument("--summary", choices=["console", "json", "markdown"], default=None,
                       help="print a session summary to stderr on exit")
    p_run.add_argument("server", nargs=argparse.REMAINDER,
                       help="-- then the server command to launch")
    p_run.set_defaults(func=cmd_run)

    p_check = sub.add_parser("check", help="validate a policy file (CI-gateable)")
    p_check.add_argument("--policy", required=True)
    p_check.set_defaults(func=cmd_check)

    p_demo = sub.add_parser("demo", help="run the bundled sample end to end")
    p_demo.add_argument("--mode", choices=["enforce", "monitor"], default=None)
    p_demo.add_argument("--summary", choices=["console", "json", "markdown"], default=None)
    p_demo.set_defaults(func=cmd_demo)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    # argparse REMAINDER keeps the leading "--"; drop it.
    if getattr(args, "server", None) and args.server and args.server[0] == "--":
        args.server = args.server[1:]
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

"""A minimal, self-contained stdio server that speaks enough JSON-RPC to be
proxied by the gateway. It is intentionally tiny and has no dependencies.

Tools:
  echo(text)              -> returns text
  add(a, b)               -> returns a + b
  login(username, pass..) -> returns "ok"  (used to show argument redaction)
  read_file(path)         -> returns pretend contents (path-traversal guard demo)
  delete_file(path)       -> returns "deleted" (deny-list demo; should be blocked)
  dump_config()           -> returns text containing a fake secret (response redaction)
"""

from __future__ import annotations

import json
import sys

TOOLS = [
    {"name": "echo", "description": "Echo text back"},
    {"name": "add", "description": "Add two numbers"},
    {"name": "login", "description": "Log in with a username and password"},
    {"name": "read_file", "description": "Read a file by path"},
    {"name": "delete_file", "description": "Delete a file by path"},
    {"name": "dump_config", "description": "Return the current configuration"},
]

FAKE_SECRET = "api_key=sk-live0123456789ABCDEFghij"


def _text_result(msg_id, text):
    return {"jsonrpc": "2.0", "id": msg_id,
            "result": {"content": [{"type": "text", "text": str(text)}]}}


def _error(msg_id, message):
    return {"jsonrpc": "2.0", "id": msg_id,
            "error": {"code": -32602, "message": message}}


def handle(msg):
    method = msg.get("method")
    msg_id = msg.get("id")
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": msg_id,
                "result": {"protocolVersion": "2024-11-05",
                           "serverInfo": {"name": "sample-server", "version": "0.1.0"},
                           "capabilities": {"tools": {}}}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": TOOLS}}
    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        if name == "echo":
            return _text_result(msg_id, args.get("text", ""))
        if name == "add":
            try:
                return _text_result(msg_id, float(args.get("a", 0)) + float(args.get("b", 0)))
            except (TypeError, ValueError):
                return _error(msg_id, "add expects numbers")
        if name == "login":
            return _text_result(msg_id, "ok")
        if name == "read_file":
            return _text_result(msg_id, "contents of %s" % args.get("path", ""))
        if name == "delete_file":
            return _text_result(msg_id, "deleted %s" % args.get("path", ""))
        if name == "dump_config":
            return _text_result(msg_id, "region=us-east-1\n%s" % FAKE_SECRET)
        return _error(msg_id, "unknown tool: %s" % name)
    if msg_id is None:
        return None  # notification, no reply
    return _error(msg_id, "unknown method: %s" % method)


def main():
    for raw in iter(sys.stdin.readline, ""):
        raw = raw.strip()
        if not raw:
            continue
        try:
            msg = json.loads(raw)
        except ValueError:
            continue
        reply = handle(msg)
        if reply is not None:
            sys.stdout.write(json.dumps(reply) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()

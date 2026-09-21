# mcp-guardrail-gateway

A policy-enforcing runtime proxy for [Model Context Protocol](https://modelcontextprotocol.io) servers over stdio. It sits transparently between an MCP client and an MCP server and enforces a declarative policy on every `tools/call`: allow/deny lists, per-tool and global rate limits, argument guards, secret redaction in the audit trail, and full JSONL audit logging. Standard library only. No runtime dependencies.

```
client  <-->  mcp-guardrail-gateway  <-->  MCP server
                     |
                     +--> policy decision (allow / deny-list / guard / rate-limited)
                     +--> redacted audit trail (JSONL)
```

## Where this fits in the AAIF MCP toolchain

MCP is one of the founding projects of the [Agentic AI Foundation](https://agenticaifoundation.org) (AAIF), donated under the Linux Foundation in December 2025 alongside goose and AGENTS.md. Most of the MCP tooling in this ecosystem answers the question *"is this server any good?"* by inspecting it **before** deployment:

- **mcp-scorecard** grades a server A to F and points to the deep-dive checkers below
- **mcp-server-audit** static security and hygiene audit
- **mcp-conformance-kit** valid-input protocol conformance
- **mcp-fuzz** negative and adversarial robustness testing
- **mcp-surface-diff** static tool-surface diffing (rug pulls, schema widening)
- **mcp-load-lab** load and latency profiling
- **mcp-context-budget** context-token cost grading
- **mcp-prompts-resources** prompts/resources primitive validation

Those tools tell you what is wrong. **mcp-guardrail-gateway is the piece that runs in production and stops it.** It is the one component in the set that lives in the live request path and makes an allow/deny decision while calls are actually happening, rather than grading a server offline.

It is the enforcement sibling of **mcp-replay**: replay records a session for behavioural regression testing, the gateway enforces policy on a session in real time. Both are stdio man-in-the-middle proxies and both redact secrets from what they persist.

The natural workflow: audit and grade a server with the analysis tools, then run it behind the gateway with a policy that encodes the boundaries those tools helped you find.

## Install

No dependencies. Clone and run, or install locally:

```bash
pip install -e .
```

Requires Python 3.9 or newer.

## Quick start

See it work end to end with the bundled sample server and policy:

```bash
python -m mcp_guardrail_gateway demo
```

Run the gateway in front of a real MCP server. Everything after `--` is the server command:

```bash
python -m mcp_guardrail_gateway run \
  --policy policy.yaml \
  --audit-log gateway-audit.jsonl \
  --summary console \
  -- python -m your_mcp_server
```

Validate a policy file in CI (exit code 1 if invalid):

```bash
python -m mcp_guardrail_gateway check --policy policy.yaml
```

## Policy

Policies are YAML or JSON. A policy file is loaded with the standard library alone; PyYAML is used automatically if present.

```yaml
version: 1
mode: enforce            # enforce = block; monitor = log only, never block

tools:
  default: allow         # disposition for tools not listed below (allow | deny)
  allow: [echo, add]     # explicit allow list
  deny: [delete_file]    # explicit deny list (always wins)

rate_limits:
  global:
    max_calls: 100
    per_seconds: 60
  per_tool:
    add:
      max_calls: 10
      per_seconds: 60

arg_guards:
  - id: no-path-traversal
    applies_to: [read_file]     # tools this guard covers (omit = all tools)
    match_args: ["*"]           # argument names to scan (glob)
    deny_pattern: "\\.\\./"     # block if a scanned string argument matches
  - id: cap-arg-size
    max_arg_bytes: 100000       # block oversized arguments

redaction:
  builtin: true                 # enable built-in secret patterns
  arg_names: [password, token]  # redact these argument values in the audit log
  patterns:                     # extra regexes to redact
    - "sk-[A-Za-z0-9]{16,}"

audit:
  log: gateway-audit.jsonl      # JSONL sink; null keeps the trail in memory
```

### Decision order

For each `tools/call` the gateway decides in this order, stopping at the first block:

1. **deny list** the tool is explicitly denied
2. **default deny** the tool is not on the allow list and `default: deny`
3. **argument guards** a scanned argument matches a deny pattern or exceeds the size cap
4. **rate limits** the per-tool or global window is exhausted

A blocked call never reaches the server and never consumes a rate-limit token. The client receives a JSON-RPC error with the matching id, so a well-behaved MCP client handles it as an ordinary tool failure.

### Enforce vs monitor

`mode: monitor` forwards every call but records what *would* have been blocked (`enforced: false` in the audit trail). This is the safe way to roll out a new policy: watch the audit log, confirm the gateway would only block what you intend, then switch to `enforce`.

## Redaction

Redaction runs over the **audit copy** of requests and responses. The bytes forwarded to the server and back to the client are never altered, so the gateway cannot corrupt a working integration. Secrets are kept out of the audit trail, not out of the traffic. Redaction combines argument-name matching, user-supplied regexes, and a conservative built-in set (AWS keys, GitHub and Slack tokens, JWTs, `sk-` style keys, bearer tokens).

## Audit trail

Each event is one JSON object per line:

```json
{"direction": "request", "method": "tools/call", "id": 4, "tool": "login",
 "decision": "allow", "allowed": true, "mode": "enforce", "enforced": false,
 "arguments": {"username": "shri", "password": "[REDACTED]"}, "redactions": 1}
{"direction": "response", "id": 4, "latency_ms": 1.83, "is_error": false, "redactions": 0}
```

The end-of-session summary aggregates decisions per tool and can be rendered as `console`, `json`, or `markdown`.

## What it is not

- Not a transport bridge. It speaks stdio in and stdio out. HTTP/SSE transports are out of scope for this version.
- Not a content firewall. Response redaction protects the audit trail, it does not scrub secrets out of what the client receives.
- Not an analysis tool. Grading and inspecting a server is what the companion tools above are for.

## Development

```bash
python -m unittest discover -s tests -v
```

## License

MIT. See [LICENSE](LICENSE).

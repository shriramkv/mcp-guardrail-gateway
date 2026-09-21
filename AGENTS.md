# AGENTS.md

Guidance for AI coding agents working in this repository.

## What this project is

`mcp-guardrail-gateway` is a policy-enforcing stdio proxy for MCP servers. It is the runtime-enforcement member of an AAIF MCP tooling suite whose other members are static analysers. Keep that boundary: this repo enforces policy on live traffic, it does not grade or inspect servers offline.

## Hard constraints

- Standard library only. Do not add runtime dependencies. PyYAML is an *optional* accelerator for policy loading and must never become required. The vendored `yamlmini` loader is the fallback and must stay in sync with the config shapes.
- Python 3.9+ compatible. No syntax or stdlib features newer than 3.9.
- The gateway must never corrupt traffic. Redaction applies to the audit copy only. Forwarded bytes to the server and back to the client are passed through untouched.
- A blocked call must not reach the server and must not consume a rate-limit token.

## Layout

- `config.py` policy model, validation, and loading
- `yamlmini.py` vendored YAML subset loader (keep zero-dependency)
- `policy.py` the decision engine (allow/deny, guards, rate limits)
- `redaction.py` audit-only secret redaction
- `gateway.py` the stdio proxy and per-message handling
- `audit.py` JSONL trail and session summary
- `cli.py` run / check / demo / version
- `samples/` bundled sample server and policy used by the demo and tests

## Testing

Run `python -m unittest discover -s tests -v`. Every behavioural change needs a test. The decision engine takes an injectable clock; use it for deterministic rate-limit tests rather than sleeping.

## Style

- No em dashes in prose or comments.
- Keep the decision order documented in the README and the engine in agreement.

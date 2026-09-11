# AAP — Agent Action Protocol

**Operator/tool/action descriptions that cross AI vendor boundaries.**

AAP describes *what an agent can do*. Its sibling [UACP](https://github.com/hn2/uacp) describes *what an agent knows*.

Spun out of UACP per ADR 0038. Sibling protocols: [UACP](https://github.com/hn2/uacp) (context payloads), [Capture-Manifest](https://github.com/hn2/capture-manifest) (capture provenance).

## Problem

Every AI vendor describes callable tools/actions differently: MCP tool schemas, OpenAI function definitions, and Anthropic tool-use blocks are structurally incompatible. An agent framework that wants to call the same action across vendors either locks itself to one vendor's format or hand-writes a per-vendor adapter for every tool. AAP defines one canonical Action Descriptor shape — name, input/output schema, side effects, authorization, invocation semantics — that a tool author writes once, so any AAP-aware router or agent can call it regardless of which vendor's tool-calling API sits in front.

## Spec

- [`spec/v0.1/AAP.md`](spec/v0.1/AAP.md) — normative specification
- [`schema/action-descriptor.schema.json`](schema/action-descriptor.schema.json) — JSON Schema
- [`examples/`](examples/) — concrete descriptors: MCP search_web, Anthropic computer_use, OpenAI get_weather

## Validate a descriptor

```bash
# one-off (no install)
npx aap-validate examples/mcp-search-web.json

# or install globally
npm install -g aap-validate
aap-validate my-action.json

# programmatic
import { validate } from 'aap-validate'
const result = validate(JSON.parse(fs.readFileSync('my-action.json', 'utf8')))
if (!result.valid) console.error(result.errors)
```

Exit code 0 = valid. Exit code 1 = validation errors. Exit code 2 = cannot read file.

## Worked example

[`examples/mcp-search-web.json`](examples/mcp-search-web.json) describes an MCP `search_web` tool as an AAP Action Descriptor:

```json
{
  "aap_version": "0.1",
  "id": "e8a2b4c6-1111-0000-aaaa-000000000001",
  "name": "search_web",
  "version": "1.0.0",
  "description": "Search the web and return top results. Mapped from MCP tool search_web.",
  "side_effects": ["network"],
  "input_schema": {
    "type": "object",
    "required": ["query"],
    "properties": {
      "query": { "type": "string", "minLength": 1, "maxLength": 1024, "description": "Search query string." }
    }
  },
  "output_schema": {
    "type": "object",
    "properties": {
      "results": {
        "type": "array",
        "items": {
          "type": "object",
          "properties": {
            "title": { "type": "string" },
            "url": { "type": "string" },
            "snippet": { "type": "string" }
          }
        }
      }
    }
  },
  "invocation": { "mode": "sync", "timeout_ms": 10000, "idempotent": true },
  "vendor": "generic",
  "descriptor_signature": "sha256:8831d493a172e0e1a7e7effb62df05f559531b2118053000d8eab3e8caffbe66"
}
```

`side_effects: ["network"]` tells a caller this action makes an outbound call before it invokes it. `invocation.idempotent: true` tells a retry layer it is safe to retry on timeout. `descriptor_signature` is the SHA-256 of the descriptor's own canonical JSON (with the signature field removed), so a caller can detect a tampered or stale descriptor.

## How to implement

1. Write an Action Descriptor JSON document for your action, following [`schema/action-descriptor.schema.json`](schema/action-descriptor.schema.json) — see the worked example above and the rest of [`examples/`](examples/) for the MCP, Anthropic and OpenAI shapes.
2. Validate it: `npx aap-validate my-action.json`.
3. Ship the descriptor next to your tool/operator. Any AAP-aware caller can read `input_schema`/`output_schema` without vendor-specific glue, and you can map it to a specific vendor's native tool format using the tables in [§8 of the spec](spec/v0.1/AAP.md).

## Run tests

```bash
npm test
```

## Key concepts

An **Action Descriptor** describes a callable action:
- `name`, `description`, `version`
- `side_effects` — `network`, `file_write`, `database_write`, `process`, etc.
- `input_schema` / `output_schema` — JSON Schema
- `authorization` — who must authorize
- `invocation` — sync/async/streaming, timeout, idempotent

Designed to round-trip with MCP, OpenAI function definitions, and Anthropic tool-use.
See [§8 of the spec](spec/v0.1/AAP.md) for mapping tables.

## License

Apache 2.0

# AAP — Agent Action Protocol

**Operator/tool/action descriptions that cross AI vendor boundaries.**

AAP describes *what an agent can do*. Its sibling [UACP](https://github.com/hn2/uacp) describes *what an agent knows*.

Spun out of UACP per ADR 0038. Sibling protocols: [UACP](https://github.com/hn2/uacp) (context payloads), [Capture-Manifest](https://github.com/hn2/capture-manifest) (capture provenance).

## Spec

- [`spec/v0.1/AAP.md`](spec/v0.1/AAP.md) — normative specification
- [`schema/action-descriptor.schema.json`](schema/action-descriptor.schema.json) — JSON Schema
- [`examples/`](examples/) — concrete descriptors: MCP search_web, Anthropic computer_use, OpenAI get_weather

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

# Agent Action Protocol (AAP) Specification v0.1 (Draft)

**AAP — Agent Action Protocol**

> **Status:** Draft v0.1 — initial scope and schema.
> Spun out from UACP per [ADR 0038](https://github.com/hn2/fusionlayer/blob/main/docs/decisions/0038-uacp-context-only-narrowing.md).
> Tracked in [hn2/aap#1](https://github.com/hn2/aap/issues/1).

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**,
**SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be
interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) when, and only when, they appear in
all capitals.

Sections labelled **(informative)** are explanatory and do not contain normative
requirements. All other sections are normative.

---

## §1 — Purpose and Scope

AAP (Agent Action Protocol) defines how operator/tool/action descriptions cross AI
vendor boundaries. Where UACP describes *what an agent knows*, AAP describes *what an
agent can do*.

### What AAP owns

- Callable shape: name, version, identifiers
- Input and output schemas (JSON Schema)
- Side-effect classification: read-only, mutating, network, file-system, etc.
- Authorization requirements: what principal must authorize invocation
- Invocation semantics: sync, async, or streaming

### What AAP does NOT own

- Operator implementation (engine code; never on the wire)
- Routing or selection logic (engine-internal)
- Per-vendor pricing or rate-limit policy (engine-internal)
- Context payloads (memory, policy, persona) — see [UACP](https://github.com/hn2/uacp)
- Capture provenance — see [Capture-Manifest](https://github.com/hn2/capture-manifest)

### Relationship to existing standards (informative)

AAP is designed to converge with or profile MCP (Anthropic), OpenAI function/tool
definitions, and Anthropic tool-use. A mapping table is in §8.

A vendor MAY implement UACP without AAP. AAP and UACP are siblings, not nested.

---

## §2 — Action Descriptor Structure

An **Action Descriptor** is a JSON document that describes a single callable action.
The normative schema is `schema/action-descriptor.schema.json`.

### Required fields

| Field | Type | Description |
|-------|------|-------------|
| `aap_version` | string | Always `"0.1"` in this spec version. |
| `id` | string | Stable identifier for this action. UUID v4 recommended. |
| `name` | string | Machine-readable name (snake_case, e.g., `search_web`, `read_file`). |
| `version` | string | Semver version of this action descriptor. |
| `description` | string | Human-readable description of what the action does (≤ 512 chars). |
| `side_effects` | array | Side-effect classification (see §4). MAY be empty. |
| `input_schema` | object | JSON Schema (draft-07) describing the input parameters. |
| `descriptor_signature` | string | Integrity signature. Format: `sha256:<hex>`. Field removed before hashing. |

### Optional fields

| Field | Type | Description |
|-------|------|-------------|
| `output_schema` | object | JSON Schema describing the output. |
| `authorization` | object | Authorization requirements (see §5). |
| `invocation` | object | Invocation semantics (see §6). |
| `vendor` | string | Vendor slug that exposes this action (e.g., `cursor`, `anthropic`). |
| `tags` | array of string | Free-form labels. |

### Minimum descriptor (JSON)

```json
{
  "aap_version": "0.1",
  "id": "d4e5f678-1234-5678-abcd-ef0123456789",
  "name": "search_web",
  "version": "1.0.0",
  "description": "Search the web and return top results.",
  "side_effects": ["network"],
  "input_schema": {
    "type": "object",
    "required": ["query"],
    "properties": {
      "query": { "type": "string", "minLength": 1, "maxLength": 1024 }
    }
  },
  "descriptor_signature": "sha256:3a1c8b4f..."
}
```

---

## §3 — Name Convention

The `name` field MUST follow `snake_case` using only lowercase ASCII letters, digits,
and underscores. It MUST NOT start with a digit. Maximum length: 128 characters.

Pattern: `^[a-z][a-z0-9_]*$`

Namespaced names for vendor-specific actions SHOULD use `<vendor>__<name>` (double
underscore) to avoid collisions (e.g., `cursor__open_file`, `anthropic__computer_use`).

---

## §4 — Side-Effect Classification

The `side_effects` array classifies what external state the action may change.

| Value | Description |
|-------|-------------|
| `none` | Pure computation; no external state changed. |
| `network` | Makes outbound network calls (HTTP, DNS, etc.). |
| `file_read` | Reads from the local file system. |
| `file_write` | Writes to the local file system. |
| `database_read` | Reads from a database. |
| `database_write` | Writes to a database. |
| `ui` | Interacts with a UI (clicks, keyboard, screenshot). |
| `process` | Spawns or interacts with OS processes. |
| `secret_access` | Reads credentials, tokens, or secrets. |

Rules:
- `none` MUST NOT appear with any other value.
- Implementations MUST declare all side effects they have reason to believe may occur.
- Consumers SHOULD require explicit user authorization for actions with `file_write`,
  `database_write`, `process`, or `secret_access` side effects.
- An empty `side_effects` array is equivalent to `["none"]`.

---

## §5 — Authorization Object

The optional `authorization` object specifies what principal must authorize invocation.

| Field | Type | Description |
|-------|------|-------------|
| `required` | boolean | If `true`, invocation requires explicit user authorization. Default: `false`. |
| `scopes` | array of string | OAuth2-style scope strings required. |
| `principal_kind` | string | Who must authorize: `user`, `operator`, `system`. Default: `user`. |

---

## §6 — Invocation Object

The optional `invocation` object specifies invocation semantics.

| Field | Type | Description |
|-------|------|-------------|
| `mode` | string | `sync` (default), `async`, or `streaming`. |
| `timeout_ms` | integer | Maximum execution time in milliseconds. |
| `idempotent` | boolean | Whether repeated calls with the same input produce the same result. |
| `cancellable` | boolean | Whether in-flight invocations can be cancelled. |

---

## §7 — Signing

The `descriptor_signature` field MUST be computed as follows:

1. Serialize the full descriptor to canonical JSON (keys sorted lexicographically,
   no extra whitespace).
2. Remove the `descriptor_signature` field from the serialized object.
3. Compute `sha256(<canonical-JSON-bytes>)` and encode as lowercase hexadecimal.
4. Set `descriptor_signature: sha256:<hex>`.

---

## §8 — Mapping to Existing Standards (informative)

### MCP tool → AAP mapping

| MCP field | AAP field |
|-----------|-----------|
| `name` | `name` |
| `description` | `description` |
| `inputSchema` | `input_schema` |
| — | `output_schema` (no MCP equivalent) |
| — | `side_effects` (no MCP equivalent) |
| — | `authorization` (no MCP equivalent) |

Round-trip: MCP → AAP is lossless. AAP → MCP loses `side_effects`, `authorization`,
`output_schema`, and `invocation`.

### OpenAI function definition → AAP mapping

| OpenAI field | AAP field |
|-------------|-----------|
| `name` | `name` |
| `description` | `description` |
| `parameters` | `input_schema` |
| — | `side_effects` |
| — | `authorization` |

### Anthropic tool-use → AAP mapping

| Anthropic field | AAP field |
|----------------|-----------|
| `name` | `name` |
| `description` | `description` |
| `input_schema` | `input_schema` |
| — | `side_effects` |
| — | `authorization` |

---

## Annex A — Change History

| Version | Date       | Summary |
|---------|------------|---------|
| v0.1    | 2026-05-21 | Initial AAP spec. Defines action descriptor structure, name convention, side-effect classification, authorization, invocation semantics, signing, and mapping to MCP/OpenAI/Anthropic tool formats. |

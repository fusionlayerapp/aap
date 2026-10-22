// AAP action descriptor validator tests
// Run: node --test tools/aap-validate/__tests__/validate.test.js

import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import {
  validate,
  canonicalJson,
  sha256Hex,
} from '../index.js'

function makeDescriptor(overrides = {}) {
  const base = {
    aap_version: '0.1',
    id: 'a1b2c3d4-0000-0000-0000-000000000001',
    name: 'search_web',
    version: '1.0.0',
    description: 'Search the web and return top results.',
    side_effects: ['network'],
    input_schema: {
      type: 'object',
      required: ['query'],
      properties: { query: { type: 'string' } },
    },
  }
  const merged = { ...base, ...overrides }
  // Compute signature over merged (without sig field)
  const clone = JSON.parse(JSON.stringify(merged))
  delete clone.descriptor_signature
  merged.descriptor_signature = `sha256:${sha256Hex(canonicalJson(clone))}`
  // Allow caller to override signature after computation
  if (overrides.descriptor_signature !== undefined) {
    merged.descriptor_signature = overrides.descriptor_signature
  }
  return merged
}

describe('valid descriptors', () => {
  test('minimal valid descriptor passes', () => {
    const r = validate(makeDescriptor())
    assert.equal(r.valid, true, JSON.stringify(r.errors))
  })

  test('descriptor with all optional fields passes', () => {
    const r = validate(makeDescriptor({
      output_schema: { type: 'object' },
      authorization: { required: true, scopes: ['web:read'], principal_kind: 'user' },
      invocation: { mode: 'async', timeout_ms: 5000, idempotent: false, cancellable: true },
      vendor: 'acme',
      tags: ['search', 'web'],
    }))
    assert.equal(r.valid, true, JSON.stringify(r.errors))
  })

  test('empty side_effects array is valid', () => {
    const r = validate(makeDescriptor({ side_effects: [] }))
    assert.equal(r.valid, true, JSON.stringify(r.errors))
  })

  test('side_effect none alone is valid', () => {
    const r = validate(makeDescriptor({ side_effects: ['none'] }))
    assert.equal(r.valid, true, JSON.stringify(r.errors))
  })

  test('vendor namespaced name (double underscore) is valid', () => {
    const r = validate(makeDescriptor({ name: 'cursor__open_file' }))
    assert.equal(r.valid, true, JSON.stringify(r.errors))
  })
})

describe('missing required fields', () => {
  for (const field of ['aap_version', 'id', 'name', 'version', 'description', 'side_effects', 'input_schema']) {
    test(`missing ${field} is rejected`, () => {
      const d = makeDescriptor()
      delete d[field]
      // Recompute sig after deletion so we don't get sig error instead
      const clone = JSON.parse(JSON.stringify(d))
      delete clone.descriptor_signature
      d.descriptor_signature = `sha256:${sha256Hex(canonicalJson(clone))}`
      const r = validate(d)
      assert.equal(r.valid, false)
      assert.ok(r.errors.some(e => e.includes(field)), `expected error for ${field}: ${JSON.stringify(r.errors)}`)
    })
  }
})

describe('field validation', () => {
  test('wrong aap_version rejected', () => {
    const r = validate(makeDescriptor({ aap_version: '0.2' }))
    assert.equal(r.valid, false)
    assert.ok(r.errors.includes('aap_version_must_be_0_1'))
  })

  test('name starting with digit rejected', () => {
    const r = validate(makeDescriptor({ name: '1bad' }))
    assert.equal(r.valid, false)
    assert.ok(r.errors.includes('name_invalid'), JSON.stringify(r.errors))
  })

  test('name with uppercase rejected', () => {
    const r = validate(makeDescriptor({ name: 'SearchWeb' }))
    assert.equal(r.valid, false)
    assert.ok(r.errors.includes('name_invalid'))
  })

  test('invalid semver rejected', () => {
    const r = validate(makeDescriptor({ version: 'v1.0' }))
    assert.equal(r.valid, false)
    assert.ok(r.errors.includes('version_must_be_semver'))
  })

  test('side_effect none with others rejected', () => {
    const r = validate(makeDescriptor({ side_effects: ['none', 'network'] }))
    assert.equal(r.valid, false)
    assert.ok(r.errors.includes('side_effect_none_with_others'))
  })

  test('unknown side_effect rejected', () => {
    const r = validate(makeDescriptor({ side_effects: ['teleportation'] }))
    assert.equal(r.valid, false)
    assert.ok(r.errors.some(e => e.startsWith('side_effect_unknown')))
  })

  test('duplicate side_effects rejected', () => {
    const r = validate(makeDescriptor({ side_effects: ['network', 'network'] }))
    assert.equal(r.valid, false)
    assert.ok(r.errors.some(e => e.startsWith('side_effect_duplicate')))
  })
})

describe('additional properties (schema: additionalProperties false)', () => {
  test('unknown top-level property rejected', () => {
    const r = validate(makeDescriptor({ totally_unknown_field: 'nope' }))
    assert.equal(r.valid, false)
    assert.ok(r.errors.includes('unknown_property:totally_unknown_field'), JSON.stringify(r.errors))
  })

  test('unknown authorization property rejected', () => {
    const r = validate(makeDescriptor({ authorization: { required: true, bogus: 1 } }))
    assert.equal(r.valid, false)
    assert.ok(r.errors.includes('authorization.unknown_property:bogus'), JSON.stringify(r.errors))
  })

  test('unknown invocation property rejected', () => {
    const r = validate(makeDescriptor({ invocation: { mode: 'sync', bogus: 1 } }))
    assert.equal(r.valid, false)
    assert.ok(r.errors.includes('invocation.unknown_property:bogus'), JSON.stringify(r.errors))
  })
})

describe('signature verification', () => {
  test('valid signature passes', () => {
    const d = makeDescriptor()
    const r = validate(d)
    assert.equal(r.valid, true, JSON.stringify(r.errors))
  })

  test('tampered descriptor fails signature', () => {
    const d = makeDescriptor()
    d.name = 'evil_action'  // tamper after signature computed
    const r = validate(d)
    assert.equal(r.valid, false)
    assert.ok(r.errors.includes('descriptor_signature_mismatch'))
  })

  test('malformed signature format rejected', () => {
    const d = makeDescriptor()
    d.descriptor_signature = 'not-a-hash'
    const r = validate(d)
    assert.equal(r.valid, false)
    assert.ok(r.errors.includes('descriptor_signature_invalid_format'))
  })
})

describe('authorization object', () => {
  test('valid authorization passes', () => {
    const r = validate(makeDescriptor({
      authorization: { required: true, scopes: ['files:read'], principal_kind: 'operator' },
    }))
    assert.equal(r.valid, true, JSON.stringify(r.errors))
  })

  test('unknown principal_kind rejected', () => {
    const r = validate(makeDescriptor({ authorization: { principal_kind: 'robot' } }))
    assert.equal(r.valid, false)
    assert.ok(r.errors.some(e => e.startsWith('authorization.principal_kind_unknown')))
  })
})

describe('invocation object', () => {
  test('valid invocation passes', () => {
    const r = validate(makeDescriptor({ invocation: { mode: 'streaming', timeout_ms: 30000 } }))
    assert.equal(r.valid, true, JSON.stringify(r.errors))
  })

  test('unknown mode rejected', () => {
    const r = validate(makeDescriptor({ invocation: { mode: 'fire_and_forget' } }))
    assert.equal(r.valid, false)
    assert.ok(r.errors.some(e => e.startsWith('invocation.mode_unknown')))
  })

  test('timeout_ms zero rejected', () => {
    const r = validate(makeDescriptor({ invocation: { timeout_ms: 0 } }))
    assert.equal(r.valid, false)
    assert.ok(r.errors.includes('invocation.timeout_ms_must_be_positive_integer'))
  })
})

describe('MCP / Anthropic / OpenAI round-trip shapes', () => {
  test('MCP tool shape maps to valid AAP descriptor', () => {
    // Simulate MCP → AAP mapping: name + description + inputSchema
    const mcpTool = {
      name: 'get_weather',
      description: 'Get current weather for a location.',
      inputSchema: {
        type: 'object',
        required: ['location'],
        properties: { location: { type: 'string' } },
      },
    }
    const d = makeDescriptor({
      name: mcpTool.name,
      description: mcpTool.description,
      input_schema: mcpTool.inputSchema,
      side_effects: ['network'],
    })
    const r = validate(d)
    assert.equal(r.valid, true, JSON.stringify(r.errors))
  })

  test('Anthropic tool shape maps to valid AAP descriptor', () => {
    const anthropicTool = {
      name: 'read_file',
      description: 'Read the contents of a file.',
      input_schema: {
        type: 'object',
        required: ['path'],
        properties: { path: { type: 'string' } },
      },
    }
    const d = makeDescriptor({
      name: anthropicTool.name,
      description: anthropicTool.description,
      input_schema: anthropicTool.input_schema,
      side_effects: ['file_read'],
    })
    const r = validate(d)
    assert.equal(r.valid, true, JSON.stringify(r.errors))
  })

  test('OpenAI function definition maps to valid AAP descriptor', () => {
    const openAiFn = {
      name: 'create_calendar_event',
      description: 'Create a new calendar event.',
      parameters: {
        type: 'object',
        required: ['title', 'date'],
        properties: {
          title: { type: 'string' },
          date: { type: 'string', format: 'date' },
        },
      },
    }
    const d = makeDescriptor({
      name: openAiFn.name,
      description: openAiFn.description,
      input_schema: openAiFn.parameters,
      side_effects: ['network', 'database_write'],
    })
    const r = validate(d)
    assert.equal(r.valid, true, JSON.stringify(r.errors))
  })
})

describe('distributed execution_plane, egress_class, and economy (#12)', () => {
  test('valid PAL/3 distributed peer descriptor with economy metadata passes', () => {
    const d = makeDescriptor({
      name: 'pal3__verify_contract_vault',
      execution_plane: 'pal3_peer',
      egress_class: 'peer-ok',
      economy: {
        billing_model: 'royalty',
        price_per_call_usd: 0.02,
        creator_royalty_bps: 1500,
        max_cost_usd: 0.1,
        sla_latency_ms: 2500,
      },
    })
    const r = validate(d)
    assert.equal(r.valid, true, JSON.stringify(r.errors))
  })

  test('unknown execution_plane or egress_class is rejected', () => {
    const r1 = validate(makeDescriptor({ execution_plane: 'quantum_cloud' }))
    assert.equal(r1.valid, false)
    assert.ok(r1.errors.includes('execution_plane_unknown:quantum_cloud'))

    const r2 = validate(makeDescriptor({ egress_class: 'public-internet' }))
    assert.equal(r2.valid, false)
    assert.ok(r2.errors.includes('egress_class_unknown:public-internet'))
  })

  test('invalid economy properties are rejected', () => {
    const r1 = validate(makeDescriptor({ economy: { billing_model: 'barter' } }))
    assert.equal(r1.valid, false)
    assert.ok(r1.errors.includes('economy.billing_model_unknown:barter'))

    const r2 = validate(makeDescriptor({ economy: { creator_royalty_bps: 12000 } }))
    assert.equal(r2.valid, false)
    assert.ok(r2.errors.includes('economy.creator_royalty_bps_must_be_bps_integer'))

    const r3 = validate(makeDescriptor({ economy: { price_per_call_usd: -0.01 } }))
    assert.equal(r3.valid, false)
    assert.ok(r3.errors.includes('economy.price_per_call_usd_must_be_non_negative_number'))

    const r4 = validate(makeDescriptor({ economy: { unknown_econ_field: 1 } }))
    assert.equal(r4.valid, false)
    assert.ok(r4.errors.includes('economy.unknown_property:unknown_econ_field'))
  })

  test('valid unified catalog_tier and Google ADK workflow composition metadata passes (#13)', () => {
    const d = makeDescriptor({
      name: 'pal3__dora_sequential_audit',
      catalog_tier: 'blueprint',
      execution_plane: 'hybrid',
      egress_class: 'peer-ok',
      adk: {
        workflow_type: 'sequential',
        output_key: 'dora_audit_verdict',
        sub_agents: ['pal3__ocr_extract', 'pal3__pii_redact_eu', 'pal3__verify_contract_vault'],
        transfer_allowed: true,
      },
      economy: {
        billing_model: 'royalty',
        price_per_call_usd: 0.03,
        creator_royalty_bps: 1500,
        compute_host_share_bps: 5000,
      },
    })
    const r = validate(d)
    assert.equal(r.valid, true, JSON.stringify(r.errors))
  })

  test('invalid catalog_tier or adk workflow_type is rejected (#13)', () => {
    const r1 = validate(makeDescriptor({ catalog_tier: 'nft_pack' }))
    assert.equal(r1.valid, false)
    assert.ok(r1.errors.includes('catalog_tier_unknown:nft_pack'))

    const r2 = validate(makeDescriptor({ adk: { workflow_type: 'random_walk' } }))
    assert.equal(r2.valid, false)
    assert.ok(r2.errors.includes('adk.workflow_type_unknown:random_walk'))
  })
})


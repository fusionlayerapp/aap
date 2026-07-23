#!/usr/bin/env node
/**
 * AAP Action Descriptor validator — CLI + programmatic API.
 *
 * Usage:
 *   node tools/aap-validate/index.js <descriptor.json>
 *
 * Programmatic:
 *   import { validate } from './tools/aap-validate/index.js'
 *   const result = validate(descriptor)   // { valid: bool, errors: string[] }
 */

import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'

const VALID_SIDE_EFFECTS = new Set([
  'none', 'network', 'file_read', 'file_write',
  'database_read', 'database_write', 'ui', 'process', 'secret_access',
])

const VALID_PRINCIPAL_KINDS = new Set(['user', 'operator', 'system'])
const VALID_INVOCATION_MODES = new Set(['sync', 'async', 'streaming'])

const NAME_PATTERN = /^[a-z][a-z0-9_]*$/
const SEMVER_PATTERN = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/
const SHA256_SIG_PATTERN = /^sha256:[0-9a-f]{64}$/

// additionalProperties: false in schema/action-descriptor.schema.json — kept in sync with it.
const KNOWN_ROOT_KEYS = new Set([
  'aap_version', 'id', 'name', 'version', 'description', 'side_effects',
  'input_schema', 'descriptor_signature', 'output_schema', 'authorization',
  'invocation', 'vendor', 'tags',
])
const KNOWN_AUTHORIZATION_KEYS = new Set(['required', 'scopes', 'principal_kind'])
const KNOWN_INVOCATION_KEYS = new Set(['mode', 'timeout_ms', 'idempotent', 'cancellable'])

function unknownKeys(obj, known) {
  return Object.keys(obj).filter((k) => !known.has(k))
}

function sortKeys(v) {
  if (Array.isArray(v)) return v.map(sortKeys)
  if (!v || typeof v !== 'object') return v
  const out = {}
  for (const k of Object.keys(v).sort()) out[k] = sortKeys(v[k])
  return out
}

function canonicalJson(obj) {
  return JSON.stringify(sortKeys(obj))
}

function sha256Hex(s) {
  return createHash('sha256').update(s, 'utf8').digest('hex')
}

export function validate(descriptor) {
  const errors = []

  if (!descriptor || typeof descriptor !== 'object') {
    return { valid: false, errors: ['descriptor_not_object'] }
  }

  // Required fields
  const required = ['aap_version', 'id', 'name', 'version', 'description', 'side_effects', 'input_schema', 'descriptor_signature']
  for (const f of required) {
    if (!(f in descriptor)) errors.push(`missing_required:${f}`)
  }

  if (errors.length) return { valid: false, errors }

  // Unknown top-level fields (schema: additionalProperties: false)
  for (const k of unknownKeys(descriptor, KNOWN_ROOT_KEYS)) {
    errors.push(`unknown_property:${k}`)
  }

  // aap_version
  if (descriptor.aap_version !== '0.1') errors.push('aap_version_must_be_0_1')

  // id
  if (typeof descriptor.id !== 'string' || descriptor.id.length < 1 || descriptor.id.length > 256) {
    errors.push('id_invalid')
  }

  // name
  if (typeof descriptor.name !== 'string' || !NAME_PATTERN.test(descriptor.name) || descriptor.name.length > 128) {
    errors.push('name_invalid')
  }

  // version
  if (typeof descriptor.version !== 'string' || !SEMVER_PATTERN.test(descriptor.version)) {
    errors.push('version_must_be_semver')
  }

  // description
  if (typeof descriptor.description !== 'string' || descriptor.description.length < 1 || descriptor.description.length > 512) {
    errors.push('description_invalid')
  }

  // side_effects
  if (!Array.isArray(descriptor.side_effects)) {
    errors.push('side_effects_must_be_array')
  } else {
    const seen = new Set()
    for (const v of descriptor.side_effects) {
      if (!VALID_SIDE_EFFECTS.has(v)) errors.push(`side_effect_unknown:${v}`)
      if (seen.has(v)) errors.push(`side_effect_duplicate:${v}`)
      seen.add(v)
    }
    if (seen.has('none') && seen.size > 1) errors.push('side_effect_none_with_others')
  }

  // input_schema
  if (!descriptor.input_schema || typeof descriptor.input_schema !== 'object') {
    errors.push('input_schema_must_be_object')
  }

  // descriptor_signature format
  if (!SHA256_SIG_PATTERN.test(descriptor.descriptor_signature)) {
    errors.push('descriptor_signature_invalid_format')
  } else {
    // Verify signature
    const clone = JSON.parse(JSON.stringify(descriptor))
    delete clone.descriptor_signature
    const computed = sha256Hex(canonicalJson(clone))
    const declared = descriptor.descriptor_signature.slice('sha256:'.length)
    if (computed !== declared) errors.push('descriptor_signature_mismatch')
  }

  // Optional: authorization
  if ('authorization' in descriptor) {
    const auth = descriptor.authorization
    if (!auth || typeof auth !== 'object') {
      errors.push('authorization_must_be_object')
    } else {
      for (const k of unknownKeys(auth, KNOWN_AUTHORIZATION_KEYS)) {
        errors.push(`authorization.unknown_property:${k}`)
      }
      if ('required' in auth && typeof auth.required !== 'boolean') errors.push('authorization.required_must_be_bool')
      if ('scopes' in auth) {
        if (!Array.isArray(auth.scopes)) errors.push('authorization.scopes_must_be_array')
        else {
          for (const s of auth.scopes) {
            if (typeof s !== 'string' || s.length < 1) errors.push('authorization.scope_entry_invalid')
          }
        }
      }
      if ('principal_kind' in auth && !VALID_PRINCIPAL_KINDS.has(auth.principal_kind)) {
        errors.push(`authorization.principal_kind_unknown:${auth.principal_kind}`)
      }
    }
  }

  // Optional: invocation
  if ('invocation' in descriptor) {
    const inv = descriptor.invocation
    if (!inv || typeof inv !== 'object') {
      errors.push('invocation_must_be_object')
    } else {
      for (const k of unknownKeys(inv, KNOWN_INVOCATION_KEYS)) {
        errors.push(`invocation.unknown_property:${k}`)
      }
      if ('mode' in inv && !VALID_INVOCATION_MODES.has(inv.mode)) {
        errors.push(`invocation.mode_unknown:${inv.mode}`)
      }
      if ('timeout_ms' in inv && (!Number.isInteger(inv.timeout_ms) || inv.timeout_ms < 1)) {
        errors.push('invocation.timeout_ms_must_be_positive_integer')
      }
      if ('idempotent' in inv && typeof inv.idempotent !== 'boolean') {
        errors.push('invocation.idempotent_must_be_bool')
      }
      if ('cancellable' in inv && typeof inv.cancellable !== 'boolean') {
        errors.push('invocation.cancellable_must_be_bool')
      }
    }
  }

  return { valid: errors.length === 0, errors }
}

export { canonicalJson, sha256Hex }

// CLI
if (process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/'))) {
  const file = process.argv[2]
  if (!file) {
    console.error('Usage: node tools/aap-validate/index.js <descriptor.json>')
    process.exit(1)
  }
  let descriptor
  try {
    descriptor = JSON.parse(readFileSync(file, 'utf8'))
  } catch (e) {
    console.error(`Failed to parse ${file}: ${e.message}`)
    process.exit(1)
  }
  const result = validate(descriptor)
  if (result.valid) {
    console.log('✓ Valid AAP action descriptor')
  } else {
    console.error('✗ Invalid:', result.errors.join(', '))
    process.exit(1)
  }
}

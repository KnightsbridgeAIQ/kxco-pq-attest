import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mlDsa } from 'kxco-post-quantum'
import { attest, verify } from '../src/index.js'

// These are the version 1 envelope tests. attest() now emits version 2 by
// default, so the v1 emission path is requested explicitly here. Every one of
// these assertions is unchanged otherwise: an archive of v1 envelopes has to
// keep verifying, and this file is what proves it.

// Generate once — keygen is the slow step
const keypair = mlDsa.ml_dsa65.keygen()
const otherKp = mlDsa.ml_dsa65.keygen()

test('attest: returns valid envelope shape', async () => {
  const env = await attest('hello', keypair, { version: '1' })
  assert.equal(env['kxco-attest'], '1')
  assert.ok(typeof env.payload === 'string')
  assert.ok(typeof env.kid === 'string' && env.kid.length === 16)
  assert.ok(typeof env.issuedAt === 'string' && !isNaN(Date.parse(env.issuedAt)))
  assert.ok(typeof env.signature === 'string' && env.signature.length > 0)
})

test('verify: valid envelope returns valid=true and original payload', async () => {
  const env = await attest('round trip', keypair)
  const result = verify(env, keypair.publicKey)
  assert.equal(result.valid, true)
  assert.equal(Buffer.from(result.payload).toString('utf-8'), 'round trip')
  assert.equal(result.signerKid, env.kid)
  assert.equal(result.issuedAt, env.issuedAt)
})

test('verify: binary payload round-trips correctly', async () => {
  const bytes = new Uint8Array([0, 1, 2, 3, 255, 254, 253])
  const env    = await attest(bytes, keypair)
  const result = verify(env, keypair.publicKey)
  assert.equal(result.valid, true)
  assert.deepEqual(result.payload, bytes)
})

test('verify: wrong public key returns valid=false', async () => {
  const env    = await attest('test', keypair)
  const result = verify(env, otherKp.publicKey)
  assert.equal(result.valid, false)
  assert.equal(result.error, 'signature invalid')
})

test('verify: tampered payload returns valid=false', async () => {
  const env     = await attest('original', keypair)
  const tampered = { ...env, payload: env.payload.slice(0, -4) + 'AAAA' }
  const result  = verify(tampered, keypair.publicKey)
  assert.equal(result.valid, false)
})

test('verify: tampered signature returns valid=false', async () => {
  const env     = await attest('original', keypair, { version: '1' })
  const tampered = { ...env, signature: env.signature.slice(0, -4) + 'AAAA' }
  const result  = verify(tampered, keypair.publicKey)
  assert.equal(result.valid, false)
})

test('verify: tampered issuedAt returns valid=false', async () => {
  const env     = await attest('original', keypair)
  const tampered = { ...env, issuedAt: '2000-01-01T00:00:00.000Z' }
  const result  = verify(tampered, keypair.publicKey)
  assert.equal(result.valid, false)
})

test('verify: missing signature field returns valid=false', async () => {
  const { signature: _, ...noSig } = await attest('x', keypair, { version: '1' })
  assert.equal(verify(noSig, keypair.publicKey).valid, false)
})

test('verify: unsupported version returns valid=false', async () => {
  const env    = { ...await attest('x', keypair), 'kxco-attest': '99' }
  const result = verify(env, keypair.publicKey)
  assert.equal(result.valid, false)
  assert.equal(result.error, 'unsupported version')
})

test('attest: anchor=true calls chain.anchorAttestation and adds chainAnchor', async () => {
  let captured = null
  const mockChain = {
    anchorAttestation: async (opts) => {
      captured = opts
      return { txHash: '0xabc', blockNumber: 1 }
    }
  }
  const env = await attest('anchored payload', keypair, {
    anchor: true, purpose: 'test-anchor', chain: mockChain, version: '1',
  })
  assert.ok(captured !== null, 'anchorAttestation should be called')
  assert.ok(typeof captured.payloadHash === 'string' && captured.payloadHash.length === 64)
  assert.equal(captured.purpose, 'test-anchor')
  assert.deepEqual(env.chainAnchor, { txHash: '0xabc', blockNumber: 1 })
})

test('attest: anchor=false does not call chain', async () => {
  let called = false
  const mockChain = { anchorAttestation: async () => { called = true } }
  await attest('not anchored', keypair, { anchor: false, chain: mockChain })
  assert.equal(called, false)
})

// Version 2 envelopes: the fields that carry the lock, the three modes, and
// dual signing.

import { createServer } from 'node:http'
import { test } from 'node:test'
import assert from 'node:assert/strict'

import { mlDsa, fingerprint } from 'kxco-post-quantum'
import { networkConfig, FAILURE } from 'kxco-pq-network'
import {
  attest, verify, verifyAsync, generateClassicalKeypair, CLASSICAL_ALGORITHMS,
  KxcoPqAttestError,
} from '../src/index.js'

const keypair = mlDsa.ml_dsa65.keygen()
const otherKp = mlDsa.ml_dsa65.keygen()
const KID = fingerprint(keypair.publicKey)
const TX = '0x' + 'ab'.repeat(32)
const LICENCE = 'kxco_live_0123456789abcdef'

// kxco-pq-chain 2.x reports whether the RELAY named the chain, and the envelope
// only states chainId when it did.
const mockChain = {
  anchorAttestation: async () => ({ txHash: TX, blockNumber: 90633, chainId: 1111111, chainIdConfirmed: true }),
}

/** An older chain client, or a bare object, that does not report confirmation. */
const unconfirmedChain = {
  anchorAttestation: async () => ({ txHash: TX, blockNumber: 90633 }),
}

async function registry(status = 'active') {
  const server = createServer((req, res) => {
    const kid = /^\/kids\/([0-9a-f]{16})$/.exec(req.url ?? '')?.[1]
    if (!kid) return void res.writeHead(404).end('{}')
    res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({
      kid, status, rotatedTo: null, institutionId: 'org_test', chainId: 1111111, asOfBlock: 1,
    }))
  })
  await new Promise((r) => server.listen(0, '127.0.0.1', r))
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    close: () => new Promise((r) => server.close(r)),
  }
}

// ── the shape ───────────────────────────────────────────────────────────────

test('an unanchored v2 envelope carries alg, kid, sig and a hint', async () => {
  const env = await attest('hello', keypair)
  assert.equal(env['kxco-attest'], '2')
  assert.equal(env.alg, 'ML-DSA-65')
  assert.equal(env.kid, KID)
  assert.ok(typeof env.sig === 'string' && env.sig.length > 0)
  assert.ok(!isNaN(Date.parse(env.issuedAt)))
  assert.equal(env.verifyModeHint, 'signature')
  // No chain was involved, so the envelope must not imply one.
  assert.equal(env.chainId, undefined)
  assert.equal(env.anchor, undefined)
})

test('an anchored envelope names Armature L1 and hints anchored', async () => {
  const env = await attest('hello', keypair, { anchor: true, purpose: 'test', chain: mockChain })
  assert.equal(env.chainId, 1111111)
  assert.deepEqual(env.anchor, { txHash: TX, blockNumber: 90633 })
  assert.equal(env.verifyModeHint, 'anchored')
})

test('anchor: true without a chain client is refused, and says what to pass', async () => {
  await assert.rejects(
    () => attest('x', keypair, { anchor: true }),
    (e) => e instanceof KxcoPqAttestError && /anchor: true needs a chain client/.test(e.message),
  )
})

// This is the reason version 2 exists. In v1 the anchor was attached AFTER
// signing, so anyone could staple a different transaction hash to a valid
// envelope. Here the anchor is inside the signed message.
test('the anchor is signed: swapping it breaks the signature', async () => {
  const env = await attest('hello', keypair, { anchor: true, chain: mockChain })
  assert.equal(verify(env, keypair.publicKey, { mode: 'anchored' }).valid, true)

  const swapped = { ...env, anchor: { txHash: '0x' + 'cd'.repeat(32), blockNumber: 1 } }
  assert.equal(verify(swapped, keypair.publicKey).valid, false)
})

test('changing the hint breaks the signature too', async () => {
  const env = await attest('hello', keypair)
  assert.equal(verify({ ...env, verifyModeHint: 'anchored' }, keypair.publicKey).valid, false)
})

test('a v2 envelope cannot name its own verification routine', async () => {
  const env = await attest('hello', keypair)
  const result = verify({ ...env, alg: 'ML-DSA-44' }, keypair.publicKey)
  assert.equal(result.valid, false)
  assert.match(result.error, /unsupported alg/)
})

test('the usual tampering all fails', async () => {
  const env = await attest('original', keypair)
  for (const [field, value] of [
    ['payload', env.payload.slice(0, -4) + 'AAAA'],
    ['sig', env.sig.slice(0, -4) + 'AAAA'],
    ['issuedAt', '2000-01-01T00:00:00.000Z'],
    ['kid', 'ffffffffffffffff'],
  ]) {
    assert.equal(verify({ ...env, [field]: value }, keypair.publicKey).valid, false, field)
  }
  assert.equal(verify(env, otherKp.publicKey).valid, false, 'wrong key')
})

// ── modes, synchronous ──────────────────────────────────────────────────────

// verify() was synchronous, and callers write `if (verify(e, k).valid)`.
// Making it async would turn each of those into a truthy Promise that silently
// passes. So it stays synchronous and refuses what it cannot honour.
test('verify stays synchronous and returns a result, not a promise', async () => {
  const result = verify(await attest('x', keypair), keypair.publicKey)
  assert.equal(typeof result.then, 'undefined')
  assert.equal(result.valid, true)
})

test('verify refuses anchored+live rather than quietly answering something weaker', async () => {
  const env = await attest('x', keypair, { anchor: true, chain: mockChain })
  assert.throws(
    () => verify(env, keypair.publicKey, { mode: 'anchored+live' }),
    /cannot be synchronous/,
  )
  assert.throws(() => verify(env, keypair.publicKey, { requireBoth: true }), /Use verifyAsync/)
})

test('anchored mode is decidable offline, in the synchronous path', async () => {
  const anchored = await attest('x', keypair, { anchor: true, chain: mockChain })
  const plain = await attest('x', keypair)

  assert.equal(verify(anchored, keypair.publicKey, { mode: 'anchored' }).valid, true)

  const missing = verify(plain, keypair.publicKey, { mode: 'anchored' })
  assert.equal(missing.valid, false)
  assert.equal(missing.reason, FAILURE.NOT_ANCHORED)
})

// ── modes, asynchronous ─────────────────────────────────────────────────────

test('anchored+live passes for an active kid', async (t) => {
  const server = await registry('active')
  t.after(() => server.close())

  const env = await attest('x', keypair, { anchor: true, chain: mockChain })
  const result = await verifyAsync(env, keypair.publicKey, {
    mode: 'anchored+live',
    config: networkConfig({ registryUrl: server.url, licenceKey: LICENCE }),
  })
  assert.equal(result.valid, true)
  assert.equal(result.registry.status, 'active')
  assert.equal(Buffer.from(result.payload).toString(), 'x')
})

test('a revoked kid fails anchored+live even though the maths is perfect', async (t) => {
  const server = await registry('revoked')
  t.after(() => server.close())

  const env = await attest('x', keypair, { anchor: true, chain: mockChain })
  // The signature itself is still valid. That is the whole point.
  assert.equal(verify(env, keypair.publicKey).valid, true)

  const result = await verifyAsync(env, keypair.publicKey, {
    mode: 'anchored+live',
    config: networkConfig({ registryUrl: server.url, licenceKey: LICENCE }),
  })
  assert.equal(result.valid, false)
  assert.equal(result.reason, FAILURE.KID_REVOKED)
})

test('anchored+live fails closed when the registry is unreachable', async () => {
  const env = await attest('x', keypair, { anchor: true, chain: mockChain })
  const result = await verifyAsync(env, keypair.publicKey, {
    mode: 'anchored+live',
    config: networkConfig({ registryUrl: 'http://127.0.0.1:1', licenceKey: LICENCE, timeoutMs: 400 }),
  })
  assert.equal(result.valid, false)
  assert.equal(result.reason, FAILURE.REGISTRY_UNREACHABLE)
})

test('an explicit mode beats the one baked into a shared config', async () => {
  const env = await attest('x', keypair)
  const config = networkConfig({ verifyMode: 'signature' })

  assert.equal((await verifyAsync(env, keypair.publicKey, { config })).valid, true)
  const stricter = await verifyAsync(env, keypair.publicKey, { config, mode: 'anchored' })
  assert.equal(stricter.valid, false)
  assert.equal(stricter.reason, FAILURE.NOT_ANCHORED)
})

test('verifyAsync with no config defaults to signature mode', async () => {
  assert.equal((await verifyAsync(await attest('x', keypair), keypair.publicKey)).valid, true)
})

test('verifyAsync still verifies v1 envelopes', async () => {
  const env = await attest('legacy', keypair, { version: '1' })
  const result = await verifyAsync(env, keypair.publicKey)
  assert.equal(result.valid, true)
  assert.equal(result.version, '1')
})

// ── dual signing ────────────────────────────────────────────────────────────

// The hedge nobody talks about: ML-DSA is young, and a break in it would be as
// bad as the quantum break it defends against.
test('an envelope can carry a classical co-signature, in either algorithm', async () => {
  for (const alg of CLASSICAL_ALGORITHMS) {
    const classical = await generateClassicalKeypair(alg)
    const env = await attest('dual', keypair, { classical })

    assert.equal(env.classical.alg, alg)
    assert.ok(typeof env.classical.sig === 'string')

    const result = await verifyAsync(env, keypair.publicKey, { requireBoth: true })
    assert.equal(result.valid, true, alg)
    assert.equal(result.classical.alg, alg)
  }
})

// Existing vectors have to keep passing, and an envelope that grew a second
// signature by default would break every verifier that checks the field set.
test('PQ-only stays the default', async () => {
  const env = await attest('plain', keypair)
  assert.equal(env.classical, undefined)
  assert.equal((await verifyAsync(env, keypair.publicKey)).valid, true)
})

test('requireBoth on a PQ-only envelope fails, and says why', async () => {
  const result = await verifyAsync(await attest('plain', keypair), keypair.publicKey, { requireBoth: true })
  assert.equal(result.valid, false)
  assert.equal(result.reason, 'classical_missing')
  assert.match(result.detail, /only the ML-DSA-65 signature/)
})

test('a tampered classical signature fails', async () => {
  const classical = await generateClassicalKeypair('Ed25519')
  const env = await attest('dual', keypair, { classical })
  const broken = { ...env, classical: { ...env.classical, sig: env.classical.sig.slice(0, -4) + 'AAAA' } }

  assert.equal((await verifyAsync(broken, keypair.publicKey, { requireBoth: true })).valid, false)
})

// A co-signature checked against a key the envelope supplied proves only that
// whoever wrote the envelope owns some key. Pinning is what makes it worth
// anything.
test('a pinned classical key that disagrees with the envelope is rejected', async () => {
  const classical = await generateClassicalKeypair('Ed25519')
  const other = await generateClassicalKeypair('Ed25519')
  const env = await attest('dual', keypair, { classical })

  assert.equal(
    (await verifyAsync(env, keypair.publicKey, { requireBoth: true, classicalPublicKey: classical.publicKey })).valid,
    true,
  )
  const wrong = await verifyAsync(env, keypair.publicKey, {
    requireBoth: true, classicalPublicKey: other.publicKey,
  })
  assert.equal(wrong.valid, false)
  assert.match(wrong.detail, /different classical public key/)
})

// Neither signature may be moved to a different envelope, because both cover
// the same message.
test('a classical signature cannot be lifted onto another envelope', async () => {
  const classical = await generateClassicalKeypair('Ed25519')
  const signed = await attest('the real payload', keypair, { classical })
  const other = await attest('a different payload', keypair, { classical })

  const spliced = { ...other, classical: signed.classical }
  assert.equal((await verifyAsync(spliced, keypair.publicKey, { requireBoth: true })).valid, false)
})

test('an unsupported classical algorithm is refused at both ends', async () => {
  await assert.rejects(() => generateClassicalKeypair('RSA'), /unsupported classical algorithm/)

  const classical = await generateClassicalKeypair('Ed25519')
  const env = await attest('x', keypair, { classical })
  const result = await verifyAsync(
    { ...env, classical: { ...env.classical, alg: 'RSA' } },
    keypair.publicKey,
    { requireBoth: true },
  )
  assert.equal(result.valid, false)
  assert.match(result.error, /unsupported classical alg/)
})

test('classical co-signing is not available on v1 envelopes', async () => {
  const classical = await generateClassicalKeypair('Ed25519')
  await assert.rejects(
    () => attest('x', keypair, { classical, version: '1' }),
    /need envelope version 2/,
  )
})

// Absence of confirmation is not confirmation. An envelope must not put the one
// fact it exists to prove into its signed message on this process's assumption.
test('an unconfirmed anchor does not claim a chain', async () => {
  const env = await attest('x', keypair, { anchor: true, chain: unconfirmedChain })
  assert.deepEqual(env.anchor, { txHash: TX, blockNumber: 90633 })
  assert.equal(env.chainId, undefined, 'the relay never named the chain, so the envelope must not')

  // Still anchored, and still verifiable: a missing chainId reads as unstated.
  assert.equal(verify(env, keypair.publicKey, { mode: 'anchored' }).valid, true)
})

test('a confirmed anchor states the chain, and it is covered by the signature', async () => {
  const env = await attest('x', keypair, { anchor: true, chain: mockChain })
  assert.equal(env.chainId, 1111111)
  assert.equal(verify({ ...env, chainId: undefined }, keypair.publicKey).valid, false)
})

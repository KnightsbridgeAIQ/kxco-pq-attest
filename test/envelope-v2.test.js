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

// ── payload kinds ───────────────────────────────────────────────────────────

test('an empty payload signs and verifies, as text and as bytes, in both versions', async () => {
  for (const version of ['1', '2']) {
    for (const empty of ['', new Uint8Array(0), Buffer.alloc(0)]) {
      const env = await attest(empty, keypair, { version })
      assert.equal(env.payload, '')
      const result = verify(env, keypair.publicKey)
      assert.equal(result.valid, true, `version ${version}: ${result.error}`)
      assert.equal(result.payload.length, 0)
      assert.equal((await verifyAsync(env, keypair.publicKey)).valid, true)
    }
  }
})

// The same encoding KxcoIdentity.attest in kxco-pq-sdk uses for an object.
test('a plain object payload is signed as the UTF-8 of its JSON text', async () => {
  const invoice = { ref: 'INV-2024-0042', amount: 50000, note: 'café' }
  const json = new TextEncoder().encode(JSON.stringify(invoice))
  for (const version of ['1', '2']) {
    const env = await attest(invoice, keypair, { version })
    const result = verify(env, keypair.publicKey)
    assert.equal(result.valid, true, result.error)
    assert.deepEqual(result.payload, json)
    assert.deepEqual(JSON.parse(new TextDecoder().decode(result.payload)), invoice)
  }
  const bare = Object.assign(Object.create(null), { a: 1 })
  assert.equal(Buffer.from(verify(await attest(bare, keypair), keypair.publicKey).payload).toString(), '{"a":1}')
})

test('the anchor posted for an object payload is the SHA-256 of its JSON text', async () => {
  let posted
  const chain = { anchorAttestation: async (a) => { posted = a; return mockChain.anchorAttestation() } }
  const invoice = { ref: 'INV-2024-0042', amount: 50000 }
  await attest(invoice, keypair, { anchor: true, chain })
  const expected = Buffer.from(await globalThis.crypto.subtle.digest(
    'SHA-256', new TextEncoder().encode(JSON.stringify(invoice)),
  )).toString('hex')
  assert.equal(posted.payloadHash, expected)
})

test('typed arrays and DataViews are signed as the bytes they cover', async () => {
  const backing = new Uint8Array([9, 9, 1, 0, 2, 0, 9, 9])
  for (const view of [
    new Uint16Array(backing.buffer, 2, 2),
    new DataView(backing.buffer, 2, 4),
    new Int8Array(backing.buffer, 2, 4),
  ]) {
    const result = verify(await attest(view, keypair), keypair.publicKey)
    assert.deepEqual(result.payload, new Uint8Array([1, 0, 2, 0]), view.constructor.name)
  }
  assert.deepEqual(verify(await attest(backing.buffer, keypair), keypair.publicKey).payload, backing)
})

test('a payload with no single byte form is refused with the package error', async () => {
  class Invoice { constructor() { this.ref = 'x' } }
  const cyclic = {}
  cyclic.self = cyclic
  for (const payload of [
    undefined, null, 0, 5, true, 10n, Symbol('x'), () => {}, [1, 2, 3], ['a'],
    new Date(0), new Map([['a', 1]]), new Invoice(),
    cyclic, { big: 1n }, { toJSON: () => undefined },
  ]) {
    await assert.rejects(
      () => attest(payload, keypair),
      (e) => e instanceof KxcoPqAttestError,
      typeof payload === 'symbol' ? 'symbol' : String(payload?.constructor?.name ?? payload),
    )
  }
})

// ── field types ─────────────────────────────────────────────────────────────

const MALFORMED = { valid: false, error: 'malformed envelope', reason: FAILURE.MALFORMED }

test('a signed field of any other type than the one attest writes is refused, not read as its text', async () => {
  const env = await attest('x', keypair, { anchor: true, chain: mockChain })
  const v1 = await attest('x', keypair, { version: '1' })
  const cases = [
    ['payload', { ...env, payload: [env.payload] }],
    ['kid', { ...env, kid: [env.kid] }],
    ['sig', { ...env, sig: [env.sig] }],
    ['issuedAt', { ...env, issuedAt: [env.issuedAt] }],
    ['verifyModeHint', { ...env, verifyModeHint: [env.verifyModeHint] }],
    ['chainId as text', { ...env, chainId: String(env.chainId) }],
    ['chainId as a fraction', { ...env, chainId: 1111111.5 }],
    ['anchor as text', { ...env, anchor: 'x' }],
    ['anchor as a list', { ...env, anchor: [env.anchor] }],
    ['anchor.txHash', { ...env, anchor: { ...env.anchor, txHash: [env.anchor.txHash] } }],
    ['anchor.blockNumber as text', { ...env, anchor: { ...env.anchor, blockNumber: String(env.anchor.blockNumber) } }],
    ['v1 payload', { ...v1, payload: [v1.payload] }],
    ['v1 kid', { ...v1, kid: [v1.kid] }],
    ['v1 issuedAt', { ...v1, issuedAt: [v1.issuedAt] }],
    ['v1 signature', { ...v1, signature: [v1.signature] }],
  ]
  for (const [name, tampered] of cases) {
    const viaJson = JSON.parse(JSON.stringify(tampered))
    assert.deepEqual(verify(viaJson, keypair.publicKey), MALFORMED, name)
    assert.deepEqual(verify(viaJson, keypair.publicKey, { mode: 'anchored' }), MALFORMED, name)
  }
  // An unanchored envelope does not become anything else with an anchor-shaped string attached.
  const plain = await attest('x', keypair)
  assert.deepEqual(verify({ ...plain, anchor: 'x' }, keypair.publicKey), MALFORMED)
})

test('verify returns a result, never a throw, for JSON fields that carry their own toString', async () => {
  const unconfirmed = await attest('x', keypair, { anchor: true, chain: unconfirmedChain })
  const v1 = await attest('x', keypair, { version: '1' })
  const odd = [{ toString: 1 }, { toString: null }, [{ toString: 1 }], { valueOf: null, toString: null }]
  const envelopes = []
  for (const value of odd) {
    envelopes.push(
      { 'kxco-attest': '2', payload: 'eA', alg: 'ML-DSA-65', kid: value, sig: 'AA', issuedAt: 't' },
      { ...unconfirmed, alg: value },
      { ...unconfirmed, verifyModeHint: value },
      { ...unconfirmed, issuedAt: value },
      { ...unconfirmed, anchor: { txHash: value } },
      { ...unconfirmed, anchor: { ...unconfirmed.anchor, blockNumber: value } },
      { ...v1, kid: value },
      { ...v1, chainAnchor: { txHash: TX, blockNumber: 1, chainId: value } },
    )
  }
  for (const env of envelopes.map((e) => JSON.parse(JSON.stringify(e)))) {
    for (const mode of ['signature', 'anchored']) {
      const sync = verify(env, keypair.publicKey, { mode })
      assert.equal(sync.valid, false)
      assert.equal(typeof sync.error, 'string')
      const later = await verifyAsync(env, keypair.publicKey, { mode })
      assert.equal(later.valid, false)
    }
  }
})

test('requireBoth refuses a classical key, signature or algorithm that is not text, rather than throwing', async () => {
  const classical = await generateClassicalKeypair('Ed25519')
  const env = await attest('dual', keypair, { classical })
  for (const bad of [5, null, {}, true, [], { toString: 1 }]) {
    for (const field of ['publicKey', 'sig', 'alg']) {
      const garbled = JSON.parse(JSON.stringify({ ...env, classical: { ...env.classical, [field]: bad } }))
      for (const opts of [{ requireBoth: true }, { requireBoth: true, classicalPublicKey: classical.publicKey }]) {
        const result = await verifyAsync(garbled, keypair.publicKey, opts)
        assert.equal(result.valid, false, `${field} ${JSON.stringify(bad)}`)
        assert.equal(result.reason, 'classical_invalid', `${field} ${JSON.stringify(bad)}`)
      }
    }
  }
})

// ── what the anchored modes read ────────────────────────────────────────────

test('an anchor attached to a version 2 envelope after signing is never read', async () => {
  const other = '0x' + 'cd'.repeat(32)
  const plain = await attest('x', keypair)
  const stapled = JSON.parse(JSON.stringify({ ...plain, chainAnchor: { txHash: other, blockNumber: 7, chainId: 1111111 } }))
  // The signature still holds, but the envelope was never anchored.
  const bare = verify(stapled, keypair.publicKey)
  assert.equal(bare.valid, true)
  assert.equal(bare.anchor, undefined)
  for (const result of [
    verify(stapled, keypair.publicKey, { mode: 'anchored' }),
    await verifyAsync(stapled, keypair.publicKey, { mode: 'anchored' }),
  ]) {
    assert.equal(result.valid, false)
    assert.equal(result.reason, FAILURE.NOT_ANCHORED)
  }

  // On an anchored envelope, the signed anchor is the one read.
  const anchored = await attest('x', keypair, { anchor: true, chain: mockChain })
  const both = JSON.parse(JSON.stringify({ ...anchored, chainAnchor: { txHash: other, blockNumber: 7 } }))
  for (const result of [
    verify(both, keypair.publicKey, { mode: 'anchored' }),
    await verifyAsync(both, keypair.publicKey, { mode: 'anchored' }),
  ]) {
    assert.equal(result.valid, true)
    assert.deepEqual(result.anchor, { txHash: TX, blockNumber: 90633, chainId: 1111111 })
  }

  // A version 1 anchor was always attached after signing, and is still read.
  const v1 = await attest('x', keypair, { version: '1', anchor: true, chain: mockChain })
  assert.equal(verify(v1, keypair.publicKey, { mode: 'anchored' }).valid, true)
})

test('a chain id added inside a version 2 anchor after signing is never read or returned', async () => {
  const unconfirmed = await attest('x', keypair, { anchor: true, chain: unconfirmedChain })
  for (const chainId of [1111111, 5, '1111111', { toString: 1 }, [{ toString: 1 }]]) {
    const env = JSON.parse(JSON.stringify({ ...unconfirmed, anchor: { ...unconfirmed.anchor, chainId } }))
    for (const result of [
      verify(env, keypair.publicKey, { mode: 'anchored' }),
      await verifyAsync(env, keypair.publicKey, { mode: 'anchored' }),
    ]) {
      assert.equal(result.valid, true, JSON.stringify(chainId))
      assert.equal(result.anchor.txHash, TX)
      // The signer never stated a chain, so the answer must not either.
      assert.equal(result.anchor.chainId, undefined, JSON.stringify(chainId))
    }
  }
  // Nor does one inside the anchor override the chain id that was signed.
  const confirmed = await attest('x', keypair, { anchor: true, chain: mockChain })
  const env = { ...confirmed, anchor: { ...confirmed.anchor, chainId: 5 } }
  for (const result of [
    verify(env, keypair.publicKey, { mode: 'anchored' }),
    await verifyAsync(env, keypair.publicKey, { mode: 'anchored' }),
  ]) {
    assert.equal(result.valid, true)
    assert.equal(result.anchor.chainId, 1111111)
  }
})

// ── line breaks ─────────────────────────────────────────────────────────────

// The version 2 signing message, as attest has always written it. Used to sign
// envelopes that attest itself no longer produces.
function signV2(fields) {
  const msg = new TextEncoder().encode([
    'kxco-attest-v2', fields.payload, fields.alg, fields.kid, fields.issuedAt, fields.chainId ?? '',
    fields.anchor?.txHash ?? '', fields.anchor?.blockNumber ?? '', fields.verifyModeHint ?? '',
  ].join('\n'))
  return { ...fields, sig: Buffer.from(mlDsa.sign(keypair.secretKey, msg), 'hex').toString('base64url') }
}

test('attest refuses a verify-mode hint or a receipt hash that is not one line of well-formed text', async () => {
  for (const verifyModeHint of ['5\nsignature', 'anchored\r', '\r\n', 'caf\uD800']) {
    await assert.rejects(() => attest('x', keypair, { verifyModeHint }), KxcoPqAttestError, JSON.stringify(verifyModeHint))
  }
  const chain = { anchorAttestation: async () => ({ txHash: TX + '\n5', chainIdConfirmed: true }) }
  await assert.rejects(() => attest('x', keypair, { anchor: true, chain }), KxcoPqAttestError)
})

test('a version 2 envelope signed over a line break is refused, and so is the same signature split another way', async () => {
  const base = {
    'kxco-attest': '2', payload: 'eA', alg: 'ML-DSA-65', kid: KID, issuedAt: new Date().toISOString(),
  }
  const signed = signV2({ ...base, verifyModeHint: '5\nsignature' })
  const split = { ...signed, issuedAt: signed.issuedAt + '\n', anchor: { blockNumber: 5 }, verifyModeHint: 'signature' }
  const inHash = signV2({ ...base, anchor: { txHash: 'a\n5' }, verifyModeHint: 'signature' })
  const inHashSplit = { ...inHash, anchor: { txHash: 'a', blockNumber: 5 }, verifyModeHint: '\nsignature' }
  for (const env of [signed, split, inHash, inHashSplit]) {
    for (const mode of ['signature', 'anchored']) {
      assert.deepEqual(verify(JSON.parse(JSON.stringify(env)), keypair.publicKey, { mode }), MALFORMED)
    }
  }
  // An unpaired surrogate encodes to the same bytes as U+FFFD.
  const replacement = signV2({ ...base, verifyModeHint: 'caf�' })
  assert.equal(verify(replacement, keypair.publicKey).valid, true)
  assert.deepEqual(verify({ ...replacement, verifyModeHint: 'caf\uD800' }, keypair.publicKey), MALFORMED)
})

test('attest refuses a verify-mode hint or a chain receipt of a type it cannot sign', async () => {
  await assert.rejects(() => attest('x', keypair, { verifyModeHint: 5 }), KxcoPqAttestError)
  await assert.rejects(() => attest('x', keypair, { verifyModeHint: ['anchored'] }), KxcoPqAttestError)
  for (const receipt of [
    { txHash: [TX], blockNumber: 1 },
    { txHash: TX, blockNumber: '1' },
    { txHash: TX, blockNumber: 1.5 },
  ]) {
    const chain = { anchorAttestation: async () => receipt }
    await assert.rejects(() => attest('x', keypair, { anchor: true, chain }), KxcoPqAttestError, JSON.stringify(receipt))
  }
})

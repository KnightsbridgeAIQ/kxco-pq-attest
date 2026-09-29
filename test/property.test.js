// Property-based tests with fast-check.
//
// attest.test.js and envelope-v2.test.js pin the envelope to worked examples.
// These ask the general question: for ANY payload, does attest() produce an
// envelope that verify() accepts byte for byte, and does changing any one
// signed field, the anchor included, make it fail? fast-check generates the
// inputs and, when a property breaks, shrinks the failing case to the smallest
// one that still breaks it, so a failure arrives as a minimal reproduction.
//
// No network. Anchored envelopes are built with a local stub chain object that
// returns a fixed transaction hash and block number, and verifyAsync is only
// asked for modes that are decided from the envelope alone.
//
// Runs on whichever backend kxco-post-quantum reports.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import fc from 'fast-check'
import { mlDsa, fingerprint } from 'kxco-post-quantum'
import { FAILURE } from 'kxco-pq-network'
import {
  attest, verify, verifyAsync, generateClassicalKeypair, CLASSICAL_ALGORITHMS,
  KxcoPqAttestError,
} from '../src/index.js'

// Every run signs at least once, so a modest run count keeps the file fast.
const RUNS = { numRuns: 40 }

const signer = mlDsa.ml_dsa65.keygen()
const other = mlDsa.ml_dsa65.keygen()
const KID = fingerprint(signer.publicKey)

const TX = '0x' + 'ab'.repeat(32)
const BLOCK = 90633

// Stands in for a KxcoChain. It records what it was asked to anchor and
// answers with a fixed receipt, the way kxco-pq-chain 2.x does when the relay
// has confirmed the chain.
function stubChain({ confirmed = true } = {}) {
  const calls = []
  return {
    calls,
    async anchorAttestation(args) {
      calls.push(args)
      return confirmed
        ? { txHash: TX, blockNumber: BLOCK, chainId: 1111111, chainIdConfirmed: true }
        : { txHash: TX, blockNumber: BLOCK }
    },
  }
}

const enc = new TextEncoder()
const bytesOf = (p) => (typeof p === 'string' ? enc.encode(p) : new Uint8Array(p))
const same = (a, b) => Buffer.from(a).equals(Buffer.from(b))

// Non-empty payloads: strings of ASCII or of any Unicode grapheme, and raw bytes.
const payload = fc.oneof(
  fc.string({ minLength: 1, maxLength: 200 }),
  fc.string({ unit: 'grapheme', minLength: 1, maxLength: 60 }),
  fc.uint8Array({ minLength: 1, maxLength: 512 }),
)

function flipByte(b64, at) {
  const bytes = Buffer.from(b64, 'base64url')
  bytes[at % bytes.length] ^= 0x01
  return bytes.toString('base64url')
}

test('the harness fails a property that is false', () => {
  assert.throws(() => fc.assert(fc.property(fc.integer(), (n) => n + 1 === n), { numRuns: 10 }))
})

test('version 2: any payload round-trips through attest and verify, byte for byte, and only under its own key', async () => {
  await fc.assert(fc.asyncProperty(payload, async (p) => {
    const env = await attest(p, signer)
    const r = verify(env, signer.publicKey)
    return env['kxco-attest'] === '2' &&
      env.verifyModeHint === 'signature' &&
      r.valid === true &&
      r.version === '2' &&
      r.signerKid === KID &&
      same(r.payload, bytesOf(p)) &&
      verify(env, other.publicKey).valid === false
  }), RUNS)
})

test('version 1: any payload still round-trips, so an archive of v1 envelopes keeps verifying', async () => {
  await fc.assert(fc.asyncProperty(payload, async (p) => {
    const env = await attest(p, signer, { version: '1' })
    const r = verify(env, signer.publicKey)
    return env['kxco-attest'] === '1' && r.valid === true && r.version === '1' && same(r.payload, bytesOf(p))
  }), { numRuns: 25 })
})

test('version 2: changing any one signed field, the anchor included, makes the envelope fail', async () => {
  const hex16 = fc.stringMatching(/^[0-9a-f]{16}$/)
  const txHash = fc.stringMatching(/^0x[0-9a-f]{64}$/)
  const iso = fc.date({ min: new Date('2000-01-01T00:00:00Z'), max: new Date('2100-01-01T00:00:00Z'), noInvalidDate: true })
    .map((d) => d.toISOString())
  const edit = fc.oneof(
    fc.nat().map((at) => ['payload', (e) => flipByte(e.payload, at)]),
    fc.nat().map((at) => ['sig', (e) => flipByte(e.sig, at)]),
    hex16.map((k) => ['kid', () => k]),
    iso.map((t) => ['issuedAt', () => t]),
    fc.integer().filter((n) => n !== 1111111).map((n) => ['chainId', () => n]),
    txHash.map((h) => ['anchor', (e) => ({ ...e.anchor, txHash: h })]),
    fc.nat().map((n) => ['anchor', (e) => ({ ...e.anchor, blockNumber: n })]),
    fc.string({ maxLength: 20 }).map((s) => ['verifyModeHint', () => s]),
    fc.string({ maxLength: 20 }).map((s) => ['alg', () => s]),
  )
  await fc.assert(fc.asyncProperty(payload, edit, async (p, [field, change]) => {
    const env = await attest(p, signer, { anchor: true, chain: stubChain() })
    const value = change(env)
    fc.pre(JSON.stringify(value) !== JSON.stringify(env[field]))
    const tampered = { ...env, [field]: value }
    return verify(env, signer.publicKey, { mode: 'anchored' }).valid === true &&
      verify(tampered, signer.publicKey).valid === false &&
      verify(tampered, signer.publicKey, { mode: 'anchored' }).valid === false
  }), RUNS)
})

test('anchored: the stub receipt travels inside the signature, and a missing chain confirmation is never stamped as one', async () => {
  await fc.assert(fc.asyncProperty(payload, fc.string({ maxLength: 30 }), fc.boolean(), async (p, purpose, confirmed) => {
    const chain = stubChain({ confirmed })
    const env = await attest(p, signer, { anchor: true, purpose, chain })
    const r = verify(env, signer.publicKey, { mode: 'anchored' })
    const plain = verify(await attest(p, signer), signer.publicKey, { mode: 'anchored' })
    return chain.calls.length === 1 &&
      chain.calls[0].purpose === purpose &&
      /^[0-9a-f]{64}$/.test(chain.calls[0].payloadHash) &&
      env.anchor.txHash === TX &&
      env.anchor.blockNumber === BLOCK &&
      env.chainId === (confirmed ? 1111111 : undefined) &&
      env.verifyModeHint === 'anchored' &&
      r.valid === true &&
      r.anchor.txHash === TX &&
      plain.valid === false &&
      plain.reason === FAILURE.NOT_ANCHORED
  }), { numRuns: 25 })
})

test('a version 1 signature never verifies when relabelled as version 2', async () => {
  await fc.assert(fc.asyncProperty(payload, async (p) => {
    const v1 = await attest(p, signer, { version: '1' })
    const relabelled = {
      'kxco-attest': '2', payload: v1.payload, alg: 'ML-DSA-65', kid: v1.kid,
      sig: v1.signature, issuedAt: v1.issuedAt, verifyModeHint: '',
    }
    return verify(v1, signer.publicKey).valid === true && verify(relabelled, signer.publicKey).valid === false
  }), { numRuns: 25 })
})

// The domain is every value of the envelope's own field types: strings, the
// numeric chain id and block number, and the anchor object. Fields of other
// JSON types are outside it.
test('verify fails closed on any well-typed envelope it did not sign: never valid, never a throw', () => {
  // Junk of any length, and junk exactly the length of an ML-DSA-65 signature,
  // so the check runs to the end rather than stopping at a length test.
  const junkB64 = fc.oneof(
    fc.uint8Array({ maxLength: 4000 }),
    fc.uint8Array({ minLength: 3309, maxLength: 3309 }),
  ).map((b) => Buffer.from(b).toString('base64url'))
  const fields = {
    'kxco-attest': fc.constantFrom('1', '2', 'x'),
    payload: fc.oneof(junkB64, fc.string()),
    alg: fc.constantFrom('ML-DSA-65', 'ML-DSA-44', ''),
    kid: fc.oneof(fc.constant(KID), fc.string()),
    sig: fc.oneof(junkB64, fc.string()),
    signature: fc.oneof(junkB64, fc.string()),
    issuedAt: fc.string(),
    chainId: fc.oneof(fc.constant(1111111), fc.integer()),
    anchor: fc.record({ txHash: fc.oneof(fc.constant(TX), fc.string()), blockNumber: fc.nat() }, { requiredKeys: [] }),
    verifyModeHint: fc.constantFrom('signature', 'anchored', ''),
  }
  // Complete envelopes reach the signature check; sparse ones test the field checks.
  const complete = fc.record(fields, { requiredKeys: ['kxco-attest', 'payload', 'alg', 'kid', 'sig', 'signature', 'issuedAt'] })
  const sparse = fc.record(fields, { requiredKeys: [] })
  const notAnEnvelope = fc.oneof(fc.string(), fc.double(), fc.boolean(), fc.constant(null), fc.array(fc.string()))
  fc.assert(fc.property(fc.oneof(complete, sparse, notAnEnvelope), fc.constantFrom('signature', 'anchored'), (env, mode) => {
    const r = verify(env, signer.publicKey, { mode })
    return r.valid === false && typeof r.error === 'string'
  }), { numRuns: 500 })
})

test('verify refuses what it cannot honour offline, for any input, with its own error', () => {
  fc.assert(fc.property(fc.jsonValue(), fc.constantFrom('live', 'both'), (env, ask) => {
    const opts = ask === 'live' ? { mode: 'anchored+live' } : { requireBoth: true }
    try {
      verify(env, signer.publicKey, opts)
      return false
    } catch (err) {
      return err instanceof KxcoPqAttestError
    }
  }), { numRuns: 200 })
})

test('dual signing: requireBoth passes with a genuine co-signature and fails when either half is broken', async () => {
  const classical = {}
  for (const alg of CLASSICAL_ALGORITHMS) classical[alg] = await generateClassicalKeypair(alg)
  const stranger = await generateClassicalKeypair('Ed25519')

  await fc.assert(fc.asyncProperty(payload, fc.constantFrom(...CLASSICAL_ALGORITHMS), fc.nat(), async (p, alg, at) => {
    const env = await attest(p, signer, { classical: classical[alg] })
    const ok = await verifyAsync(env, signer.publicKey, { requireBoth: true, classicalPublicKey: classical[alg].publicKey })
    const badClassical = await verifyAsync(
      { ...env, classical: { ...env.classical, sig: flipByte(env.classical.sig, at) } },
      signer.publicKey, { requireBoth: true },
    )
    const badPq = await verifyAsync({ ...env, sig: flipByte(env.sig, at) }, signer.publicKey, { requireBoth: true })
    const wrongPin = await verifyAsync(env, signer.publicKey, { requireBoth: true, classicalPublicKey: stranger.publicKey })
    const pqOnly = await verifyAsync(await attest(p, signer), signer.publicKey, { requireBoth: true })
    return ok.valid === true && ok.classical.alg === alg &&
      badClassical.valid === false && badClassical.reason === 'classical_invalid' &&
      badPq.valid === false && badPq.reason === FAILURE.SIGNATURE_INVALID &&
      wrongPin.valid === false && wrongPin.reason === 'classical_invalid' &&
      pqOnly.valid === false && pqOnly.reason === 'classical_missing'
  }), { numRuns: 25 })
})

test('dual signing: a garbled classical block on a genuine envelope never passes requireBoth', async () => {
  const env = await attest('a genuine envelope', signer)
  // Any length, and the lengths of a real Ed25519 key and signature, so some
  // keys import and the signature check itself has to say no.
  const b64 = (...sizes) => fc.oneof(
    fc.uint8Array({ maxLength: 128 }),
    ...sizes.map((n) => fc.uint8Array({ minLength: n, maxLength: n })),
  ).map((b) => Buffer.from(b).toString('base64url'))
  await fc.assert(fc.asyncProperty(fc.constantFrom(...CLASSICAL_ALGORITHMS, 'RSA', ''), b64(32, 65), b64(64), async (alg, publicKey, sig) => {
    const r = await verifyAsync({ ...env, classical: { alg, publicKey, sig } }, signer.publicKey, { requireBoth: true })
    return r.valid === false && r.reason === 'classical_invalid'
  }), { numRuns: 100 })
})

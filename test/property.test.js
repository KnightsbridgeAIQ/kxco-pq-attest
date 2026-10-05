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
import { mlDsa, mlDsa87, fingerprint } from 'kxco-post-quantum'
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
// A plain object is signed as the UTF-8 of its JSON text.
const bytesOf = (p) => {
  if (typeof p === 'string') return enc.encode(p)
  if (p instanceof Uint8Array) return new Uint8Array(p)
  return enc.encode(JSON.stringify(p))
}
const same = (a, b) => Buffer.from(a).equals(Buffer.from(b))

// Any payload, empty ones included: strings of ASCII or of any Unicode
// grapheme, raw bytes, and plain objects.
const payload = fc.oneof(
  fc.constantFrom('', new Uint8Array(0)),
  fc.string({ maxLength: 200, size: 'max' }),
  fc.string({ unit: 'grapheme', maxLength: 60, size: 'max' }),
  fc.uint8Array({ maxLength: 512, size: 'max' }),
  fc.dictionary(fc.string({ maxLength: 12 }), fc.jsonValue({ maxDepth: 2 }), { maxKeys: 4 }),
)

// JSON values of other types than a field's own, and objects that carry
// their own toString, which a field read as text would call.
const otherJson = fc.oneof(
  fc.jsonValue({ maxDepth: 2 }),
  fc.constantFrom({ toString: 1 }, { toString: null }, [{ toString: 1 }], { valueOf: null, toString: null }),
)
// A field's own type most of the time, any other JSON value the rest.
const orOther = (typed) => fc.oneof({ arbitrary: typed, weight: 3 }, { arbitrary: otherJson, weight: 1 })

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

test('ML-DSA-87: any payload round-trips under an ML-DSA-87 key, and never verifies under an ML-DSA-65 key', async () => {
  const signer87 = mlDsa87.ml_dsa87.keygen()
  await fc.assert(fc.asyncProperty(payload, async (p) => {
    const env = await attest(p, signer87)
    const r = verify(env, signer87.publicKey)
    return env.alg === 'ML-DSA-87' &&
      r.valid === true &&
      r.signerKid === fingerprint(signer87.publicKey) &&
      same(r.payload, bytesOf(p)) &&
      verify(env, signer.publicKey).valid === false
  }), { numRuns: 10 })
})

test('version 1: any payload still round-trips, so an archive of v1 envelopes keeps verifying', async () => {
  await fc.assert(fc.asyncProperty(payload, async (p) => {
    const env = await attest(p, signer, { version: '1' })
    const r = verify(env, signer.publicKey)
    return env['kxco-attest'] === '1' && r.valid === true && r.version === '1' && same(r.payload, bytesOf(p))
  }), { numRuns: 25 })
})

test('version 2: changing any one signed field, in value or in JSON type, the anchor included, makes the envelope fail', async () => {
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
    // The same value as another JSON type.
    fc.constantFrom('payload', 'alg', 'kid', 'sig', 'issuedAt', 'verifyModeHint').map((f) => [f, (e) => [e[f]]]),
    fc.constant(['chainId', (e) => String(e.chainId)]),
    fc.constant(['anchor', (e) => [e.anchor]]),
    fc.constant(['anchor', (e) => ({ ...e.anchor, txHash: [e.anchor.txHash] })]),
    fc.constant(['anchor', (e) => ({ ...e.anchor, blockNumber: String(e.anchor.blockNumber) })]),
  )
  await fc.assert(fc.asyncProperty(payload, edit, async (p, [field, change]) => {
    const env = await attest(p, signer, { anchor: true, chain: stubChain() })
    const value = change(env)
    fc.pre(JSON.stringify(value) !== JSON.stringify(env[field]))
    const tampered = JSON.parse(JSON.stringify({ ...env, [field]: value }))
    return verify(env, signer.publicKey, { mode: 'anchored' }).valid === true &&
      verify(tampered, signer.publicKey).valid === false &&
      verify(tampered, signer.publicKey, { mode: 'anchored' }).valid === false
  }), RUNS)
})

// The version 2 signing message, as attest has always written it.
function v2Message(f) {
  return enc.encode([
    'kxco-attest-v2', f.payload, f.alg, f.kid, f.issuedAt, f.chainId ?? '',
    f.anchor?.txHash ?? '', f.anchor?.blockNumber ?? '', f.verifyModeHint ?? '',
  ].join('\n'))
}

// A line break inside a text field is the one way two different envelopes
// could share a version 2 signing message. So attest refuses one in the hint,
// and an envelope signed over one anyway never verifies, however the signed
// text is split back into the eight fields.
test('version 2: a hint holding a line break is refused at attest, and an envelope signed over one never verifies, however its text is split into fields', async () => {
  const lineBreak = fc.constantFrom('\n', '\r', '\r\n')
  const piece = fc.oneof(fc.string({ maxLength: 8 }), fc.nat().map(String))
  const brokenHint = fc.tuple(piece, fc.array(fc.tuple(lineBreak, piece), { minLength: 1, maxLength: 3 }))
    .map(([head, rest]) => head + rest.map(([b, s]) => b + s).join(''))
  // One rank per line boundary; the seven highest-ranked boundaries are the cuts.
  const ranks = fc.array(fc.nat(), { minLength: 16, maxLength: 16 })
  await fc.assert(fc.asyncProperty(brokenHint, fc.boolean(), ranks, async (hint, anchored, rank) => {
    await assert.rejects(() => attest('x', signer, { verifyModeHint: hint }), KxcoPqAttestError)
    const fields = {
      'kxco-attest': '2', payload: 'eA', alg: 'ML-DSA-65', kid: KID, issuedAt: new Date().toISOString(),
      ...(anchored ? { chainId: 1111111, anchor: { txHash: TX, blockNumber: BLOCK } } : {}),
      verifyModeHint: hint,
    }
    const message = v2Message(fields)
    const signed = { ...fields, sig: Buffer.from(mlDsa.sign(signer.secretKey, message), 'hex').toString('base64url') }

    const lines = new TextDecoder().decode(message).split('\n').slice(1)
    const at = Array.from({ length: lines.length - 1 }, (_, i) => i + 1)
      .sort((x, y) => rank[y - 1] - rank[x - 1] || x - y).slice(0, 7).sort((x, y) => x - y)
    const parts = [0, ...at].map((from, i) => lines.slice(from, [...at, lines.length][i]).join('\n'))
    const number = (text) => (/^-?\d+$/.test(text) ? Number(text) : text)
    const resplit = {
      'kxco-attest': '2', payload: parts[0], alg: parts[1], kid: parts[2], issuedAt: parts[3],
      ...(parts[4] === '' ? {} : { chainId: number(parts[4]) }),
      ...(parts[5] === '' && parts[6] === '' ? {} : {
        anchor: {
          ...(parts[5] === '' ? {} : { txHash: parts[5] }),
          ...(parts[6] === '' ? {} : { blockNumber: number(parts[6]) }),
        },
      }),
      verifyModeHint: parts[7],
      sig: signed.sig,
    }
    for (const env of [signed, resplit]) {
      for (const mode of ['signature', 'anchored']) {
        if (verify(JSON.parse(JSON.stringify(env)), signer.publicKey, { mode }).valid !== false) return false
      }
    }
    return true
  }), { numRuns: 25 })
})

test('anchored: an anchor attached after signing, or a chain id added inside the signed one, is never read', async () => {
  const hash = fc.stringMatching(/^0x[0-9a-f]{64}$/)
  await fc.assert(fc.asyncProperty(payload, hash, fc.nat(), fc.oneof(fc.integer(), otherJson), fc.boolean(),
    async (p, tx, block, chainId, confirmed) => {
      const plain = await attest(p, signer)
      const anchored = await attest(p, signer, { anchor: true, chain: stubChain({ confirmed }) })
      const stapled = JSON.parse(JSON.stringify({ ...plain, chainAnchor: { txHash: tx, blockNumber: block, chainId } }))
      const added = JSON.parse(JSON.stringify({ ...anchored, anchor: { ...anchored.anchor, chainId } }))
      const results = [
        [stapled, verify(stapled, signer.publicKey, { mode: 'anchored' })],
        [stapled, await verifyAsync(stapled, signer.publicKey, { mode: 'anchored' })],
        [added, verify(added, signer.publicKey, { mode: 'anchored' })],
        [added, await verifyAsync(added, signer.publicKey, { mode: 'anchored' })],
      ]
      return results.every(([env, r]) => env === stapled
        ? r.valid === false && r.reason === FAILURE.NOT_ANCHORED
        : r.valid === true && r.anchor.txHash === TX && r.anchor.chainId === (confirmed ? 1111111 : undefined))
    }), { numRuns: 25 })
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

// The domain is every JSON value in every field: the envelope's own field
// types, any other JSON type, and objects that carry their own toString.
test('verify fails closed on any envelope it did not sign, whatever its field types: never valid, never a throw', async () => {
  // Junk of any length, and junk exactly the length of an ML-DSA-65 signature,
  // so the check runs to the end rather than stopping at a length test.
  const junkB64 = fc.oneof(
    fc.uint8Array({ maxLength: 4000, size: 'max' }),
    fc.uint8Array({ minLength: 3309, maxLength: 3309 }),
  ).map((b) => Buffer.from(b).toString('base64url'))
  const anchorOf = () => fc.record({
    txHash: orOther(fc.oneof(fc.constant(TX), fc.string())),
    blockNumber: orOther(fc.nat()),
    chainId: orOther(fc.constant(1111111)),
  }, { requiredKeys: [] })
  const fields = {
    'kxco-attest': orOther(fc.constantFrom('1', '2', 'x')),
    payload: orOther(fc.oneof(junkB64, fc.string())),
    alg: orOther(fc.constantFrom('ML-DSA-65', 'ML-DSA-44', '')),
    kid: orOther(fc.oneof(fc.constant(KID), fc.string())),
    sig: orOther(fc.oneof(junkB64, fc.string())),
    signature: orOther(fc.oneof(junkB64, fc.string())),
    issuedAt: orOther(fc.string()),
    chainId: orOther(fc.oneof(fc.constant(1111111), fc.integer())),
    anchor: orOther(anchorOf()),
    chainAnchor: orOther(anchorOf()),
    verifyModeHint: orOther(fc.constantFrom('signature', 'anchored', '')),
    classical: orOther(fc.record({
      alg: orOther(fc.constantFrom(...CLASSICAL_ALGORITHMS)), publicKey: orOther(junkB64), sig: orOther(junkB64),
    }, { requiredKeys: [] })),
  }
  // Complete envelopes reach the signature check; sparse ones test the field checks.
  const complete = fc.record(fields, { requiredKeys: ['kxco-attest', 'payload', 'alg', 'kid', 'sig', 'signature', 'issuedAt'] })
  const sparse = fc.record(fields, { requiredKeys: [] })
  const notAnEnvelope = fc.oneof(fc.string(), fc.double(), fc.boolean(), fc.constant(null), fc.array(fc.string()), otherJson)
  await fc.assert(fc.asyncProperty(fc.oneof(complete, sparse, notAnEnvelope), fc.constantFrom('signature', 'anchored'), async (env, mode) => {
    const r = verify(env, signer.publicKey, { mode })
    const later = await verifyAsync(env, signer.publicKey, { mode })
    const both = await verifyAsync(env, signer.publicKey, { mode, requireBoth: true })
    return r.valid === false && typeof r.error === 'string' && later.valid === false && both.valid === false
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

test('dual signing: a garbled classical block on a genuine envelope never passes requireBoth, whatever its field types', async () => {
  const env = await attest('a genuine envelope', signer)
  const genuine = await generateClassicalKeypair('Ed25519')
  // Any length, and the lengths of a real Ed25519 key and signature, so some
  // keys import and the signature check itself has to say no.
  const b64 = (...sizes) => fc.oneof(
    fc.uint8Array({ maxLength: 128, size: 'max' }),
    ...sizes.map((n) => fc.uint8Array({ minLength: n, maxLength: n })),
  ).map((b) => Buffer.from(b).toString('base64url'))
  await fc.assert(fc.asyncProperty(
    orOther(fc.constantFrom(...CLASSICAL_ALGORITHMS, 'RSA', '')), orOther(b64(32, 65)), orOther(b64(64)), fc.boolean(),
    async (alg, publicKey, sig, pinned) => {
      const opts = { requireBoth: true, ...(pinned ? { classicalPublicKey: genuine.publicKey } : {}) }
      const r = await verifyAsync({ ...env, classical: { alg, publicKey, sig } }, signer.publicKey, opts)
      return r.valid === false && r.reason === 'classical_invalid'
    }), { numRuns: 100 })
})

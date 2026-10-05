// ML-DSA-87 envelopes, and the ML-DSA-65 ones that came before.
//
// The signing key decides the parameter set, and the set goes into the
// envelope's `alg`, which is inside the signed message. A verifying key must
// be of the set the envelope names, so a key of one set is never checked as
// the other. Version 1 carries no alg and stays ML-DSA-65. Envelopes written
// by 2.0.7, before any of this, verify unchanged.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { mlDsa, mlDsa87, fingerprint } from 'kxco-post-quantum'
import { FAILURE } from 'kxco-pq-network'
import { attest, verify, verifyAsync, KxcoPqAttestError } from '../src/index.js'

const k65 = mlDsa.ml_dsa65.keygen()
const k87 = mlDsa87.ml_dsa87.keygen()
const otherK87 = mlDsa87.ml_dsa87.keygen()
const sigBytes = (env) => Buffer.from(env.sig, 'base64url').length

function stubChain() {
  return { async anchorAttestation() { return { txHash: '0x' + 'cd'.repeat(32), blockNumber: 77, chainIdConfirmed: true } } }
}

test('an ML-DSA-87 key signs a version 2 envelope as ML-DSA-87, and it verifies with that key', async () => {
  const env = await attest('category 5 document', k87)
  assert.equal(env['kxco-attest'], '2')
  assert.equal(env.alg, 'ML-DSA-87')
  assert.equal(env.kid, fingerprint(k87.publicKey))
  assert.equal(sigBytes(env), 4627)

  const r = verify(env, k87.publicKey)
  assert.equal(r.valid, true, JSON.stringify(r))
  assert.equal(Buffer.from(r.payload).toString(), 'category 5 document')
  assert.equal((await verifyAsync(env, k87.publicKey)).valid, true)
  assert.equal(verify(env, otherK87.publicKey).valid, false)
})

test('an anchored ML-DSA-87 envelope verifies in anchored mode', async () => {
  const env = await attest('anchored at category 5', k87, { anchor: true, chain: stubChain() })
  const r = verify(env, k87.publicKey, { mode: 'anchored' })
  assert.equal(r.valid, true, JSON.stringify(r))
  assert.equal(r.anchor.txHash, '0x' + 'cd'.repeat(32))
})

test('a key of one parameter set never verifies an envelope that names the other', async () => {
  const env87 = await attest('x', k87)
  const env65 = await attest('x', k65)
  for (const [env, key] of [[env87, k65.publicKey], [env65, k87.publicKey]]) {
    const r = verify(env, key)
    assert.equal(r.valid, false)
    assert.equal(r.reason, FAILURE.SIGNATURE_INVALID)
    assert.match(r.detail, new RegExp(`signed under ${env.alg}`))
    assert.equal((await verifyAsync(env, key)).valid, false)
  }
})

test('the algorithm is inside the signed message: relabelling an envelope breaks it', async () => {
  const env = await attest('x', k87)
  const as65 = { ...env, alg: 'ML-DSA-65' }
  assert.equal(verify(as65, k87.publicKey).valid, false)
  assert.equal(verify(as65, k65.publicKey).valid, false)
  const env65 = await attest('x', k65)
  assert.equal(verify({ ...env65, alg: 'ML-DSA-87' }, k87.publicKey).valid, false)
})

test('a keypair can name its set, and one that names or holds the other set is refused', async () => {
  const named = await attest('x', { ...k87, alg: 'ML-DSA-87' })
  assert.equal(named.alg, 'ML-DSA-87')
  assert.equal(verify(named, k87.publicKey).valid, true)
  assert.equal((await attest('x', { ...k65, alg: 'ML-DSA-65' })).alg, 'ML-DSA-65')

  const crossSet = /not used as another/
  const refusals = [
    ['ML-DSA-65 keys named ML-DSA-87', { ...k65, alg: 'ML-DSA-87' }, crossSet],
    ['ML-DSA-87 keys named ML-DSA-65', { ...k87, alg: 'ML-DSA-65' }, crossSet],
    ['ML-DSA-87 secret key, ML-DSA-65 public key', { publicKey: k65.publicKey, secretKey: k87.secretKey }, crossSet],
    ['ML-DSA-65 secret key, ML-DSA-87 public key', { publicKey: k87.publicKey, secretKey: k65.secretKey }, crossSet],
    ['a set this package does not sign', { ...k87, alg: 'ML-DSA-44' }, /unsupported keypair alg/],
  ]
  for (const [what, keypair, reason] of refusals) {
    await assert.rejects(() => attest('x', keypair), (err) => {
      assert.ok(err instanceof KxcoPqAttestError, `${what}: ${err?.name}: ${err?.message}`)
      assert.match(err.message, reason, what)
      return true
    })
  }
})

test('version 1 carries no algorithm, so an ML-DSA-87 key is refused there and ML-DSA-65 is unchanged', async () => {
  await assert.rejects(() => attest('x', k87, { version: '1' }), (err) => {
    assert.ok(err instanceof KxcoPqAttestError)
    assert.match(err.message, /version 2/)
    return true
  })
  const v1 = await attest('x', k65, { version: '1' })
  assert.equal(v1.alg, undefined)
  assert.equal(verify(v1, k65.publicKey).valid, true)
})

test('an ML-DSA-65 key still signs ML-DSA-65: alg, 3309-byte signature, and verification', async () => {
  const env = await attest('x', k65)
  assert.equal(env.alg, 'ML-DSA-65')
  assert.equal(sigBytes(env), 3309)
  assert.equal(verify(env, k65.publicKey).valid, true)
})

test('envelopes written by 2.0.7, before ML-DSA-87, verify unchanged', async () => {
  const fixture = JSON.parse(readFileSync(new URL('./fixtures/envelopes-2.0.7.json', import.meta.url), 'utf8'))
  const publicKey = Buffer.from(fixture.publicKey, 'hex')
  const { v1, v2, v2Anchored } = fixture.envelopes

  assert.equal(verify(v1, publicKey).valid, true)
  assert.equal(verify(v2, publicKey).valid, true)
  assert.equal(v2.alg, 'ML-DSA-65')
  const anchored = verify(v2Anchored, publicKey, { mode: 'anchored' })
  assert.equal(anchored.valid, true, JSON.stringify(anchored))
  assert.equal(anchored.anchor.chainId, 1111111)
  assert.equal((await verifyAsync(v2, publicKey)).valid, true)
  // A key passed as an ArrayBuffer was read as its bytes, and still is.
  const asArrayBuffer = publicKey.buffer.slice(publicKey.byteOffset, publicKey.byteOffset + publicKey.byteLength)
  assert.equal(verify(v2, asArrayBuffer).valid, true)
  // And they still fail closed: the same envelopes under another key do not verify.
  for (const env of [v1, v2, v2Anchored]) assert.equal(verify(env, k65.publicKey).valid, false)
})

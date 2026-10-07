// ML-DSA-87 is the default set.
//
// The key decides wherever it can: an `alg` on the keypair, or else the
// secret key's size in bytes. Only a key of neither size falls back to a
// default, and in a version 2 envelope that default is ML-DSA-87. Version 1
// carries no algorithm, so it stays ML-DSA-65. ML-DSA-65 keys, named or not,
// sign ML-DSA-65 exactly as before.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mlDsa, mlDsa87 } from 'kxco-post-quantum'
import { attest, verify, KxcoPqAttestError } from '../src/index.js'

const k65 = mlDsa.ml_dsa65.keygen()
const k87 = mlDsa87.ml_dsa87.keygen()
const asArrayBuffer = (key) => key.buffer.slice(key.byteOffset, key.byteOffset + key.byteLength)
const sigBytes = (env) => Buffer.from(env.sig, 'base64url').length

test('the README quick start, an ML-DSA-87 key with no set named, signs and verifies ML-DSA-87', async () => {
  const keypair = mlDsa87.ml_dsa87.keygen()
  const envelope = await attest('trade confirmed: BTC/USD 100k @ 67,200', keypair)
  assert.equal(envelope.alg, 'ML-DSA-87')
  assert.equal(sigBytes(envelope), 4627)
  assert.equal(verify(envelope, keypair.publicKey).valid, true)
})

test('a keypair held as ArrayBuffers is measured by byte length, so an ML-DSA-87 one signs ML-DSA-87', async () => {
  const env = await attest('x', { publicKey: asArrayBuffer(k87.publicKey), secretKey: asArrayBuffer(k87.secretKey) })
  assert.equal(env.alg, 'ML-DSA-87')
  assert.equal(verify(env, k87.publicKey).valid, true)
})

test('an ML-DSA-65 keypair held as ArrayBuffers still signs ML-DSA-65', async () => {
  const env = await attest('x', { publicKey: asArrayBuffer(k65.publicKey), secretKey: asArrayBuffer(k65.secretKey) })
  assert.equal(env.alg, 'ML-DSA-65')
  assert.equal(verify(env, k65.publicKey).valid, true)
})

test('a secret key of neither size, with no alg, is read as ML-DSA-87 in a version 2 envelope', async () => {
  // Read as ML-DSA-87, the ML-DSA-65 public key beside it is the other set's
  // size and the keypair is refused before anything is signed.
  await assert.rejects(() => attest('x', { publicKey: k65.publicKey, secretKey: new Uint8Array(100) }), (err) => {
    assert.ok(err instanceof KxcoPqAttestError, `${err?.name}: ${err?.message}`)
    assert.match(err.message, /keypair is ML-DSA-87 but its publicKey is 1952 bytes/)
    return true
  })
})

test('in a version 1 envelope a secret key of neither size is still read as ML-DSA-65', async () => {
  await assert.rejects(
    () => attest('x', { publicKey: k87.publicKey, secretKey: new Uint8Array(100) }, { version: '1' }),
    (err) => {
      assert.ok(err instanceof KxcoPqAttestError, `${err?.name}: ${err?.message}`)
      assert.match(err.message, /keypair is ML-DSA-65 but its publicKey is 2592 bytes/)
      return true
    },
  )
})

test('an ML-DSA-65 key, named or not, signs ML-DSA-65 in both versions and verifies', async () => {
  for (const keypair of [k65, { ...k65, alg: 'ML-DSA-65' }]) {
    const v2 = await attest('x', keypair)
    assert.equal(v2.alg, 'ML-DSA-65')
    assert.equal(sigBytes(v2), 3309)
    assert.equal(verify(v2, k65.publicKey).valid, true)
    const v1 = await attest('x', keypair, { version: '1' })
    assert.equal(verify(v1, k65.publicKey).valid, true)
  }
})

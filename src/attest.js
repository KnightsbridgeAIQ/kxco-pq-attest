// Attestation envelopes.
//
// An envelope is a payload, who signed it, when, and a signature — small
// enough to email, self-contained enough that a counterparty can check it with
// nothing but the public key.
//
// Version 2 adds the fields a verifier needs in order to apply a mode:
// `chainId`, `anchor`, and a `verifyModeHint` saying what the issuer intended.
// Version 1 envelopes still verify, unchanged, forever. An archive of signed
// documents that stopped verifying on a library upgrade would be worse than
// useless, so the v1 signing message is untouched and the v1 path is a
// separate function rather than a branch that could drift.
//
// Two deliberate choices about the API shape.
//
// `verify` stays SYNCHRONOUS. It was synchronous, and callers write
// `if (verify(e, k).valid)`. Making it async would turn every one of those
// into a truthy Promise that silently passes — a security failure introduced
// by an upgrade, in the one function whose job is to say no. So `verify`
// covers what can be decided without a network (signature, and anchored), and
// `verifyAsync` covers what cannot (anchored+live, dual signatures). Asking
// `verify` for a mode it cannot honour throws rather than degrading.
//
// Dual signing is opt-in and PQ-only is the default. Existing vectors have to
// keep passing, and an envelope that grew a second signature by default would
// break every verifier that checks the field set.

import { mlDsa, mlDsa87, fingerprint } from 'kxco-post-quantum'
import { applyVerifyMode, networkConfig, readAnchor, FAILURE } from 'kxco-pq-network'
import { KxcoPqAttestError } from './errors.js'

const V1 = '1'
const V2 = '2'
// The default set, and the only one a version 1 envelope can be.
const ALG = 'ML-DSA-65'

// The ML-DSA parameter sets a version 2 envelope may be signed under, with
// their FIPS 204 key sizes in bytes. The signing key decides the set, and the
// set goes into the envelope's `alg`, which is inside the signed message. A
// verifying key must be of the set the envelope names, so a key of one set is
// never used as the other.
const ML_DSA = {
  'ML-DSA-65': { module: mlDsa, publicKey: 1952, secretKey: 4032 },
  'ML-DSA-87': { module: mlDsa87, publicKey: 2592, secretKey: 4896 },
}
const mlDsaSet = (alg) => (typeof alg === 'string' && Object.hasOwn(ML_DSA, alg) ? ML_DSA[alg] : null)

/** Classical algorithms accepted alongside ML-DSA for dual signing. */
export const CLASSICAL_ALGORITHMS = ['Ed25519', 'ECDSA-P256']

const enc = new TextEncoder()

function b64url(bytes) {
  return Buffer.from(bytes).toString('base64url')
}

function fromB64url(str) {
  return new Uint8Array(Buffer.from(str, 'base64url'))
}

function isPlainObject(value) {
  if (value === null || typeof value !== 'object') return false
  const proto = Object.getPrototypeOf(value)
  return proto === Object.prototype || proto === null
}

// The bytes a payload is signed as. Bytes as they are, a string as its UTF-8,
// and a plain object as the UTF-8 of its JSON text, which is how
// KxcoIdentity.attest in kxco-pq-sdk encodes one. Anything else has no single
// obvious byte form, so it is refused rather than guessed at.
function payloadBytesOf(payload) {
  if (typeof payload === 'string') return enc.encode(payload)
  if (payload instanceof Uint8Array || payload instanceof ArrayBuffer) return new Uint8Array(payload)
  if (ArrayBuffer.isView(payload)) {
    return new Uint8Array(payload.buffer, payload.byteOffset, payload.byteLength).slice()
  }
  if (isPlainObject(payload)) {
    let json
    try {
      json = JSON.stringify(payload)
    } catch (err) {
      throw new KxcoPqAttestError(`payload object has no JSON text to sign: ${err.message}`)
    }
    if (typeof json !== 'string') throw new KxcoPqAttestError('payload object has no JSON text to sign')
    return enc.encode(json)
  }
  throw new KxcoPqAttestError('payload must be a string, bytes (Uint8Array, Buffer or ArrayBuffer) or a plain object')
}

// ── field types ─────────────────────────────────────────────────────────────
//
// The signing messages are built from each field's text. A field of another
// type would be read as whatever its text happens to be: a one-element array
// as its element, an object as its toString. So every field that goes into a
// message must be the type attest() writes, and one that is not is refused as
// malformed. An optional field may be absent, and null reads as absent, which
// is how the messages have always treated it.

const isText = (v) => typeof v === 'string' && v !== ''
const isAbsent = (v) => v === undefined || v === null
const optionalText = (v) => isAbsent(v) || typeof v === 'string'
const optionalInteger = (v) => isAbsent(v) || Number.isInteger(v)

// The v2 message is also one field per line. A text field holding a line
// break would let the same signature cover the same bytes split into
// different fields, so none may hold one. The text has to be well-formed
// Unicode too, because an unpaired surrogate encodes to the same bytes as
// U+FFFD.
const isOneLine = (v) => typeof v === 'string' && !/[\r\n]/.test(v) && v.isWellFormed()
const optionalLine = (v) => isAbsent(v) || isOneLine(v)

function anchorWellTyped(anchor) {
  if (isAbsent(anchor)) return true
  return isPlainObject(anchor) && optionalLine(anchor.txHash) && optionalInteger(anchor.blockNumber)
}

// What the anchored modes may read. A v2 anchor sits inside the signed
// message, so they see only the signed fields: a chainAnchor attached after
// signing, or a chainId added inside the anchor, is never read and never
// returned. A v1 anchor was always attached after signing and is read as it
// is, which is the reason version 2 exists.
function signedAnchorView(envelope) {
  if (envelope['kxco-attest'] !== V2) return envelope
  const { anchor, chainId } = envelope
  return {
    ...(isAbsent(chainId) ? {} : { chainId }),
    ...(isPlainObject(anchor) ? { anchor: { txHash: anchor.txHash, blockNumber: anchor.blockNumber } } : {}),
  }
}

// ── signing messages ────────────────────────────────────────────────────────

// v1. Frozen. Any change here invalidates every envelope ever issued.
function signingMsgV1(payloadB64, kid, issuedAt) {
  const parts = [
    enc.encode('kxco-attest-v1\n'),
    enc.encode(payloadB64),
    enc.encode('\n'),
    enc.encode(kid),
    enc.encode('\n'),
    enc.encode(issuedAt),
  ]
  const len = parts.reduce((n, a) => n + a.length, 0)
  const msg = new Uint8Array(len)
  let off = 0
  for (const p of parts) { msg.set(p, off); off += p.length }
  return msg
}

// v2. The anchor is inside the signed message, not merely attached to the
// envelope. In v1 the anchor was added AFTER signing, so anyone could staple a
// different transaction hash to a valid envelope and it would still verify.
// Here, changing the anchor changes the signature.
//
// The domain tag differs from v1's, so a v1 signature can never be replayed as
// a v2 one even where the other fields coincide.
function signingMsgV2({ payloadB64, alg, kid, issuedAt, chainId, anchor, verifyModeHint }) {
  return enc.encode([
    'kxco-attest-v2',
    payloadB64,
    alg,
    kid,
    issuedAt,
    chainId ?? '',
    anchor?.txHash ?? '',
    anchor?.blockNumber ?? '',
    verifyModeHint ?? '',
  ].join('\n'))
}

// ── classical co-signature ──────────────────────────────────────────────────
//
// Dual signing hedges the direction nobody talks about: ML-DSA is young, and a
// break in it would be as bad as the quantum break it defends against. A
// classical co-signature means an attacker has to break both.
//
// WebCrypto rather than node:crypto, because this package is used in
// Cloudflare Workers.

function subtleParams(alg) {
  if (alg === 'Ed25519') return { generate: { name: 'Ed25519' }, sign: { name: 'Ed25519' } }
  if (alg === 'ECDSA-P256') {
    return {
      generate: { name: 'ECDSA', namedCurve: 'P-256' },
      sign: { name: 'ECDSA', hash: 'SHA-256' },
    }
  }
  throw new KxcoPqAttestError(
    `unsupported classical algorithm '${alg}' — expected ${CLASSICAL_ALGORITHMS.join(' or ')}`,
  )
}

/**
 * Generate a classical keypair for co-signing, exported as raw bytes.
 *
 * @param {'Ed25519'|'ECDSA-P256'} alg
 * @returns {Promise<{ alg: string, publicKey: Uint8Array, privateKey: CryptoKey }>}
 */
export async function generateClassicalKeypair(alg = 'Ed25519') {
  const { generate } = subtleParams(alg)
  const pair = await globalThis.crypto.subtle.generateKey(generate, true, ['sign', 'verify'])
  return {
    alg,
    publicKey: new Uint8Array(await globalThis.crypto.subtle.exportKey('raw', pair.publicKey)),
    privateKey: pair.privateKey,
  }
}

async function classicalSign({ alg, privateKey }, message) {
  const { sign } = subtleParams(alg)
  const sig = await globalThis.crypto.subtle.sign(sign, privateKey, message)
  return new Uint8Array(sig)
}

async function classicalVerify(alg, rawPublicKey, message, signature) {
  const { generate, sign } = subtleParams(alg)
  try {
    const key = await globalThis.crypto.subtle.importKey('raw', rawPublicKey, generate, false, ['verify'])
    return await globalThis.crypto.subtle.verify(sign, key, signature, message)
  } catch {
    // A malformed key or signature is a failed verification, not a crash,
    // which is how mlDsa.verify already behaves.
    return false
  }
}

// ── attest ──────────────────────────────────────────────────────────────────

// The set a keypair signs under. An explicit `alg` on the keypair decides it;
// otherwise the secret key's size does, and a secret key of neither size is
// read as ML-DSA-65, as every keypair was before ML-DSA-87. Either way a
// keypair holding a key the size of the other set is refused.
function signingAlgorithm(keypair) {
  const sizes = { publicKey: keypair?.publicKey?.length, secretKey: keypair?.secretKey?.length }
  const alg = keypair?.alg ?? Object.keys(ML_DSA).find((a) => ML_DSA[a].secretKey === sizes.secretKey) ?? ALG
  if (!mlDsaSet(alg)) {
    throw new KxcoPqAttestError(`unsupported keypair alg '${alg}': expected ${Object.keys(ML_DSA).join(' or ')}`)
  }
  for (const part of ['publicKey', 'secretKey']) {
    const other = Object.keys(ML_DSA).find((a) => a !== alg && ML_DSA[a][part] === sizes[part])
    if (other) {
      throw new KxcoPqAttestError(
        `keypair is ${alg} but its ${part} is ${sizes[part]} bytes, the size of an ${other} key: ` +
        'a key of one parameter set is not used as another',
      )
    }
  }
  return alg
}

/**
 * Sign a payload into an attestation envelope.
 *
 * With no options this is signature mode: no network, no licence, no chain,
 * and the envelope verifies offline forever.
 *
 * The keypair decides the parameter set: ML-DSA-65 (the default) or, in a
 * version 2 envelope, ML-DSA-87. Its `alg` names it where given; otherwise the
 * secret key's size does.
 *
 * @param {string|Uint8Array|Buffer|object} payload (a plain object is signed as its JSON text)
 * @param {{ publicKey: Uint8Array, secretKey: Uint8Array, alg?: 'ML-DSA-65'|'ML-DSA-87' }} keypair
 * @param {object} [opts]
 * @param {boolean} [opts.anchor]   — anchor the envelope on Armature L1. Needs `chain`.
 * @param {string}  [opts.purpose]  — purpose recorded with the anchor
 * @param {object}  [opts.chain]    — a KxcoChain from kxco-pq-chain
 * @param {{ alg: string, privateKey: CryptoKey, publicKey?: Uint8Array }} [opts.classical]
 *        Co-sign with a classical algorithm as well. Off by default.
 * @param {string} [opts.verifyModeHint] — what the issuer expects verifiers to require
 * @param {'1'|'2'} [opts.version]  — envelope version. Default '2'.
 * @returns {Promise<object>} the envelope
 */
export async function attest(payload, keypair, opts = {}) {
  const {
    anchor = false, purpose, chain, classical, verifyModeHint, version = V2,
  } = opts

  if (version !== V1 && version !== V2) {
    throw new KxcoPqAttestError(`unsupported envelope version '${version}'`)
  }
  if (anchor && !chain) {
    throw new KxcoPqAttestError(
      'anchor: true needs a chain client. Pass chain: new KxcoChain({ identity, licenceKey }) ' +
      'from kxco-pq-chain, or omit anchor to sign in signature mode.',
    )
  }
  if (version === V1 && (classical || verifyModeHint)) {
    throw new KxcoPqAttestError('classical co-signing and verifyModeHint need envelope version 2')
  }
  if (!optionalLine(verifyModeHint)) {
    throw new KxcoPqAttestError('verifyModeHint must be one line of well-formed text')
  }
  const alg = signingAlgorithm(keypair)
  if (version === V1 && alg !== ALG) {
    throw new KxcoPqAttestError(
      `envelope version 1 carries no algorithm and is ${ALG} only; an ${alg} key needs envelope version 2`,
    )
  }

  const payloadBytes = payloadBytesOf(payload)
  const payloadB64 = b64url(payloadBytes)
  const kid = fingerprint(keypair.publicKey)
  const issuedAt = new Date().toISOString()

  if (version === V1) {
    return attestV1({ payloadB64, kid, issuedAt, keypair, anchor, purpose, chain })
  }

  // The anchor is written BEFORE signing, because in v2 it is inside the
  // signed message. That is the point of the version: a v1 anchor was stapled
  // on afterwards and could be swapped for another without breaking the
  // signature.
  let chainAnchor = null
  // Whether the RELAY named the chain, as opposed to this process assuming it.
  let chainConfirmed = false
  if (anchor) {
    const digest = await globalThis.crypto.subtle.digest('SHA-256', payloadBytes)
    const result = await chain.anchorAttestation({
      payloadHash: Buffer.from(digest).toString('hex'),
      purpose: purpose ?? '',
    })
    chainAnchor = { txHash: result.txHash, blockNumber: result.blockNumber }
    // Signed, so it has to be of the types verify() accepts, or the envelope
    // would never verify.
    if (!anchorWellTyped(chainAnchor)) {
      throw new KxcoPqAttestError(
        'the chain client returned an anchor that is not { txHash: one line of text, blockNumber: integer }',
      )
    }
    // kxco-pq-chain 2.x reports this. An older client, or a bare object a
    // caller passed in, does not — and absence is not confirmation, so it is
    // read strictly rather than defaulted to true.
    chainConfirmed = result.chainIdConfirmed === true
  }

  // An envelope states `chainId` only when the relay actually said so. Stamping
  // 1111111 onto an anchor whose chain was never confirmed would put the one
  // fact the envelope exists to prove into the signed message on this
  // process's assumption rather than the relay's answer. A verifier reads a
  // missing chainId as unstated, which is true, rather than as wrong.
  const chainId = chainAnchor && chainConfirmed ? 1111111 : undefined
  const hint = verifyModeHint ?? (chainAnchor ? 'anchored' : 'signature')

  const msg = signingMsgV2({
    payloadB64, alg, kid, issuedAt, chainId, anchor: chainAnchor, verifyModeHint: hint,
  })

  const envelope = {
    'kxco-attest': V2,
    payload: payloadB64,
    alg,
    kid,
    sig: b64url(Buffer.from(ML_DSA[alg].module.sign(new Uint8Array(keypair.secretKey), msg), 'hex')),
    issuedAt,
    ...(chainId ? { chainId } : {}),
    ...(chainAnchor ? { anchor: chainAnchor } : {}),
    verifyModeHint: hint,
  }

  if (classical) {
    if (!classical.publicKey) {
      throw new KxcoPqAttestError(
        'classical co-signing needs the raw public key alongside the private key, so the ' +
        'envelope can name what verifies it',
      )
    }
    envelope.classical = {
      alg: classical.alg,
      publicKey: b64url(classical.publicKey),
      // Over the same message the PQ signature covers, so neither signature
      // can be moved to a different envelope.
      sig: b64url(await classicalSign(classical, msg)),
    }
  }

  return envelope
}

async function attestV1({ payloadB64, kid, issuedAt, keypair, anchor, purpose, chain }) {
  const msg = signingMsgV1(payloadB64, kid, issuedAt)
  const envelope = {
    'kxco-attest': V1,
    payload: payloadB64,
    kid,
    issuedAt,
    signature: b64url(Buffer.from(mlDsa.sign(new Uint8Array(keypair.secretKey), msg), 'hex')),
  }

  if (anchor) {
    const bytes = enc.encode(JSON.stringify(envelope))
    const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes)
    envelope.chainAnchor = await chain.anchorAttestation({
      payloadHash: Buffer.from(digest).toString('hex'),
      purpose: purpose ?? '',
    })
  }

  return envelope
}

// ── verify ──────────────────────────────────────────────────────────────────

/**
 * Verify an envelope. SYNCHRONOUS, as it has always been.
 *
 * Covers `signature` and `anchored`, both of which are decidable offline.
 * `anchored+live` and dual-signature checks need `verifyAsync`, and asking for
 * them here throws rather than quietly returning the weaker answer.
 *
 * @param {unknown} envelope
 * @param {Uint8Array|Buffer} publicKey
 * @param {{ mode?: 'signature'|'anchored' }} [opts]
 * @returns {{ valid: boolean, ... }}
 */
export function verify(envelope, publicKey, opts = {}) {
  const mode = opts.mode ?? 'signature'

  if (mode === 'anchored+live') {
    throw new KxcoPqAttestError(
      "anchored+live performs a live registry lookup and cannot be synchronous. " +
      'Use verifyAsync(envelope, publicKey, { mode, config }).',
    )
  }
  if (opts.requireBoth) {
    throw new KxcoPqAttestError(
      'requireBoth verifies a classical co-signature, which is asynchronous. Use verifyAsync.',
    )
  }

  const checked = checkSignature(envelope, publicKey)
  if (!checked.valid) return checked

  if (mode === 'signature') return checked

  // anchored, decided from what the envelope carries.
  const anchor = readAnchor(signedAnchorView(envelope))
  if (!anchor) {
    return {
      valid: false,
      error: 'not anchored',
      reason: FAILURE.NOT_ANCHORED,
      detail: 'this envelope carries no Armature L1 anchor; re-issue it with anchor: true',
    }
  }
  if (anchor.chainId !== undefined && anchor.chainId !== 1111111) {
    return {
      valid: false,
      error: 'wrong chain',
      reason: FAILURE.WRONG_CHAIN,
      detail: `anchor names chain ${anchor.chainId}, expected 1111111 (Armature L1)`,
    }
  }
  return { ...checked, anchor }
}

/**
 * Verify an envelope, with the modes and the dual-signature check.
 *
 * @param {unknown} envelope
 * @param {Uint8Array|Buffer} publicKey
 * @param {object} [opts]
 * @param {'signature'|'anchored'|'anchored+live'} [opts.mode]
 * @param {object} [opts.config]   — a networkConfig() from kxco-pq-network
 * @param {object} [opts.registry] — a shared KeyRegistry, to share its cache
 * @param {boolean} [opts.requireBoth] — require a valid classical co-signature too
 * @param {Uint8Array} [opts.classicalPublicKey]
 *        Pin the classical key rather than trusting the one in the envelope.
 * @returns {Promise<{ valid: boolean, ... }>}
 */
export async function verifyAsync(envelope, publicKey, opts = {}) {
  const { mode, config, registry, requireBoth = false, classicalPublicKey } = opts

  const checked = checkSignature(envelope, publicKey)
  if (!checked.valid) {
    return { ...checked, reason: FAILURE.SIGNATURE_INVALID }
  }

  // The classical half, before the mode: a missing co-signature is a fact
  // about the document, and reporting it as a revocation would mislead.
  let classical
  if (requireBoth) {
    classical = await checkClassical(envelope, classicalPublicKey)
    if (!classical.valid) return classical
  }

  const resolved = config ?? networkConfig({ verifyMode: mode ?? 'signature' })
  const applied = await applyVerifyMode({
    envelope: signedAnchorView(envelope),
    signatureValid: true,
    kid: checked.signerKid,
    // An explicit mode argument beats the one baked into a shared config, so a
    // caller can hold one config and still demand more for one document.
    config: mode && mode !== resolved.verifyMode ? { ...resolved, verifyMode: mode } : resolved,
    registry,
  })

  if (!applied.valid) {
    return { valid: false, error: applied.reason, reason: applied.reason, detail: applied.detail, mode: applied.mode }
  }

  return {
    ...checked,
    mode: applied.mode,
    ...(applied.anchor ? { anchor: applied.anchor } : {}),
    ...(applied.registry ? { registry: applied.registry } : {}),
    ...(classical ? { classical: classical.classical } : {}),
  }
}

// ── internals ───────────────────────────────────────────────────────────────

function checkSignature(envelope, publicKey) {
  if (!envelope || typeof envelope !== 'object') {
    return { valid: false, error: 'malformed envelope', reason: FAILURE.MALFORMED }
  }

  const version = envelope['kxco-attest']
  if (version !== V1 && version !== V2) {
    return { valid: false, error: 'unsupported version', reason: FAILURE.MALFORMED }
  }
  // The anchored modes read the chain id an anchor names and write a wrong
  // one into their answer. It has to be an integer to be read at all.
  if (!optionalInteger(readAnchor(signedAnchorView(envelope))?.chainId)) {
    return { valid: false, error: 'malformed envelope', reason: FAILURE.MALFORMED }
  }
  return version === V1 ? checkSignatureV1(envelope, publicKey) : checkSignatureV2(envelope, publicKey)
}

function checkSignatureV1(envelope, publicKey) {
  const { payload: payloadB64, kid, issuedAt, signature } = envelope
  if (typeof payloadB64 !== 'string' || !isText(kid) || !isText(issuedAt) || !isText(signature)) {
    return { valid: false, error: 'malformed envelope', reason: FAILURE.MALFORMED }
  }

  const msg = signingMsgV1(payloadB64, kid, issuedAt)
  if (!pqVerify(publicKey, msg, signature)) {
    return { valid: false, error: 'signature invalid', reason: FAILURE.SIGNATURE_INVALID }
  }
  return { valid: true, payload: fromB64url(payloadB64), signerKid: kid, issuedAt, version: V1 }
}

function checkSignatureV2(envelope, publicKey) {
  const { payload: payloadB64, alg, kid, sig, issuedAt, chainId, anchor, verifyModeHint } = envelope
  if (![payloadB64, kid, issuedAt].every(isOneLine) || !isText(kid) || !isText(issuedAt) || !isText(sig) ||
      !optionalText(alg) || !optionalInteger(chainId) || !anchorWellTyped(anchor) || !optionalLine(verifyModeHint)) {
    return { valid: false, error: 'malformed envelope', reason: FAILURE.MALFORMED }
  }
  // The algorithm is checked against what this package signs, and then bound
  // to the verifying key: the caller's key is what is trusted, so it has to be
  // of the set the envelope names. An envelope cannot name its own
  // verification routine, and cannot have a key checked as the other set.
  const set = mlDsaSet(alg)
  if (!set) {
    return { valid: false, error: `unsupported alg '${alg}'`, reason: FAILURE.MALFORMED }
  }
  // byteLength first, so a key passed as an ArrayBuffer is measured as the
  // bytes pqVerify reads from it.
  const keyLength = publicKey?.byteLength ?? publicKey?.length
  if (keyLength !== set.publicKey) {
    return {
      valid: false,
      error: 'signature invalid',
      reason: FAILURE.SIGNATURE_INVALID,
      detail: `the envelope is signed under ${alg}, which takes a ${set.publicKey}-byte public key, ` +
        `and the key given is ${keyLength} bytes`,
    }
  }

  const msg = signingMsgV2({ payloadB64, alg, kid, issuedAt, chainId, anchor, verifyModeHint })
  if (!pqVerify(publicKey, msg, sig, set.module)) {
    return { valid: false, error: 'signature invalid', reason: FAILURE.SIGNATURE_INVALID }
  }

  return {
    valid: true,
    payload: fromB64url(payloadB64),
    signerKid: kid,
    issuedAt,
    version: V2,
    ...(verifyModeHint ? { verifyModeHint } : {}),
  }
}

function pqVerify(publicKey, message, sigB64, module = mlDsa) {
  try {
    return module.verify(
      new Uint8Array(publicKey),
      message,
      Buffer.from(fromB64url(sigB64)).toString('hex'),
    )
  } catch {
    return false
  }
}

async function checkClassical(envelope, pinnedPublicKey) {
  if (envelope['kxco-attest'] !== V2 || !envelope.classical) {
    return {
      valid: false,
      error: 'no classical co-signature',
      reason: 'classical_missing',
      detail: `requireBoth was set but this envelope carries only the ${envelope['kxco-attest'] === V2 ? envelope.alg : ALG} signature`,
    }
  }

  const { alg, publicKey: envelopePublicKey, sig } = envelope.classical
  if (typeof alg !== 'string' || typeof envelopePublicKey !== 'string' || typeof sig !== 'string') {
    return { valid: false, error: 'malformed classical co-signature', reason: 'classical_invalid' }
  }
  if (!CLASSICAL_ALGORITHMS.includes(alg)) {
    return { valid: false, error: `unsupported classical alg '${alg}'`, reason: 'classical_invalid' }
  }

  // A co-signature checked against a key the envelope supplied proves only
  // that whoever wrote the envelope owns some key. Pinning is what makes it
  // worth anything, so a pinned key that disagrees is a rejection.
  const raw = pinnedPublicKey ? new Uint8Array(pinnedPublicKey) : fromB64url(envelopePublicKey)
  if (pinnedPublicKey && !buffersEqual(raw, fromB64url(envelopePublicKey))) {
    return {
      valid: false,
      error: 'classical key mismatch',
      reason: 'classical_invalid',
      detail: 'the envelope names a different classical public key than the one pinned',
    }
  }

  const msg = signingMsgV2({
    payloadB64: envelope.payload,
    alg: envelope.alg,
    kid: envelope.kid,
    issuedAt: envelope.issuedAt,
    chainId: envelope.chainId,
    anchor: envelope.anchor,
    verifyModeHint: envelope.verifyModeHint,
  })

  const ok = await classicalVerify(alg, raw, msg, fromB64url(sig))
  if (!ok) {
    return { valid: false, error: 'classical signature invalid', reason: 'classical_invalid' }
  }
  return { valid: true, classical: { alg, publicKey: raw } }
}

function buffersEqual(a, b) {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}

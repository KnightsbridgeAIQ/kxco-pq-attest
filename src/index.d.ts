/// <reference types="node" />

export interface Keypair {
  publicKey: Uint8Array | Buffer
  secretKey: Uint8Array | Buffer
}

/** Classical algorithms accepted alongside ML-DSA-65 for dual signing. */
export type ClassicalAlgorithm = 'Ed25519' | 'ECDSA-P256'

export const CLASSICAL_ALGORITHMS: ClassicalAlgorithm[]

export interface ClassicalKeypair {
  alg: ClassicalAlgorithm
  /** Raw public key bytes. 32 for Ed25519, 65 for uncompressed P-256. */
  publicKey: Uint8Array
  privateKey: CryptoKey
}

/**
 * Generate a classical keypair for co-signing.
 *
 * Uses WebCrypto, so it works in Node, Cloudflare Workers and browsers alike.
 */
export function generateClassicalKeypair(alg?: ClassicalAlgorithm): Promise<ClassicalKeypair>

// ── envelopes ───────────────────────────────────────────────────────────────

/**
 * Version 1. Still emitted on request and still verified, forever. The anchor
 * here was attached AFTER signing, so it is not covered by the signature —
 * which is the reason version 2 exists.
 */
export interface AttestationEnvelopeV1 {
  'kxco-attest': '1'
  payload:      string
  kid:          string
  issuedAt:     string
  signature:    string
  chainAnchor?: { txHash: string; blockNumber: number }
}

/** Version 2. The anchor and the mode hint are inside the signed message. */
export interface AttestationEnvelopeV2 {
  'kxco-attest': '2'
  /** base64url payload bytes */
  payload:   string
  alg:       'ML-DSA-65'
  /** 16-hex fingerprint of the signing public key */
  kid:       string
  /** base64url ML-DSA-65 signature */
  sig:       string
  issuedAt:  string
  /**
   * Present only when the relay CONFIRMED the chain — that is, when the chain
   * client reported `chainIdConfirmed: true`. An anchor whose chain was never
   * confirmed is written without this field rather than with an assumed value,
   * because it sits inside the signed message and would otherwise put the one
   * fact the envelope exists to prove on the signer's assumption.
   *
   * A verifier reads its absence as "unstated", which is true, not as "wrong".
   */
  chainId?:  1111111
  anchor?:   { txHash: string; blockNumber: number }
  /** What the issuer expects verifiers to require. Not a guarantee — a hint. */
  verifyModeHint: string
  /** Present only when the envelope was dual-signed. */
  classical?: { alg: ClassicalAlgorithm; publicKey: string; sig: string }
}

export type AttestationEnvelope = AttestationEnvelopeV1 | AttestationEnvelopeV2

/** Minimal chain client interface — accepts a kxco-pq-chain KxcoChain. */
export interface AttestChainClient {
  anchorAttestation(opts: { payloadHash: string; purpose: string }): Promise<{
    txHash: string
    blockNumber: number
    /**
     * Reported by kxco-pq-chain 2.x. Anything else omits it, and absence is
     * read as NOT confirmed rather than defaulted to true.
     */
    chainIdConfirmed?: boolean
  }>
}

export interface AttestOptions {
  /** Anchor the envelope on Armature L1. Requires `chain`. */
  anchor?: boolean
  /** Purpose recorded with the anchor. */
  purpose?: string
  chain?: AttestChainClient
  /** Co-sign classically as well. Off by default, so existing vectors pass. */
  classical?: ClassicalKeypair
  /** Override the mode hint written into the envelope. */
  verifyModeHint?: string
  /** Envelope version. Default '2'. */
  version?: '1' | '2'
}

// ── results ─────────────────────────────────────────────────────────────────

export interface VerifySuccess {
  valid:     true
  payload:   Uint8Array
  signerKid: string
  issuedAt:  string
  version:   '1' | '2'
  verifyModeHint?: string
  mode?:     string
  anchor?:   { txHash: string; blockNumber?: number }
  registry?: Record<string, unknown>
  classical?: { alg: ClassicalAlgorithm; publicKey: Uint8Array }
}

export interface VerifyFailure {
  valid: false
  error: string
  /** A FAILURE code from kxco-pq-network, or a classical_* code. */
  reason?: string
  detail?: string
  mode?: string
}

export type VerifyResult = VerifySuccess | VerifyFailure

/**
 * Verify an envelope. **Synchronous**, as it has always been.
 *
 * Covers `signature` and `anchored`, both decidable offline. `anchored+live`
 * and `requireBoth` need `verifyAsync`, and asking for them here THROWS rather
 * than returning a weaker answer — a caller writing `if (verify(e, k).valid)`
 * must never be handed a Promise that is always truthy.
 */
export function verify(
  envelope: unknown,
  publicKey: Uint8Array | Buffer,
  opts?: { mode?: 'signature' | 'anchored' },
): VerifyResult

/** Verify an envelope with the full mode set and the dual-signature check. */
export function verifyAsync(
  envelope: unknown,
  publicKey: Uint8Array | Buffer,
  opts?: {
    mode?: 'signature' | 'anchored' | 'anchored+live'
    /** A networkConfig() from kxco-pq-network. */
    config?: Record<string, unknown>
    /** A shared KeyRegistry, so several verifications share one cache. */
    registry?: unknown
    /** Require a valid classical co-signature as well. */
    requireBoth?: boolean
    /** Pin the classical key rather than trusting the one in the envelope. */
    classicalPublicKey?: Uint8Array
  },
): Promise<VerifyResult>

/**
 * Sign a payload into an attestation envelope.
 *
 * With no options this is signature mode: no network, no licence, no chain,
 * and the envelope verifies offline forever.
 */
export function attest(
  payload: string | Uint8Array | Buffer,
  keypair: Keypair,
  opts?: AttestOptions,
): Promise<AttestationEnvelope>

export class KxcoPqAttestError extends Error {
  name: 'KxcoPqAttestError'
}

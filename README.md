# kxco-pq-attest

**Post-quantum document signing any counterparty can verify offline, years later, with nobody to ask.**

[![npm](https://img.shields.io/npm/v/kxco-pq-attest?label=npm&color=b0964f)](https://www.npmjs.com/package/kxco-pq-attest)
[![downloads](https://img.shields.io/npm/dm/kxco-pq-attest?label=downloads&color=b0964f)](https://www.npmjs.com/package/kxco-pq-attest)
[![NIST ACVP](https://img.shields.io/badge/NIST_ACVP-1,793_passed,_0_failed-2ea44f)](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/CONFORMANCE.md)
[![npm provenance](https://img.shields.io/badge/npm-provenance-2ea44f)](https://www.npmjs.com/package/kxco-pq-attest)
[![Socket](https://socket.dev/api/badge/npm/package/kxco-pq-attest)](https://socket.dev/npm/package/kxco-pq-attest)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)
[![node](https://img.shields.io/node/v/kxco-pq-attest.svg)](https://nodejs.org)

Signs arbitrary data (strings, Buffers, objects) with ML-DSA-65 (NIST FIPS 204) and produces a self-contained JSON envelope any counterparty can verify without trust delegation. Optionally anchors the envelope hash on Armature L1 via the KXCO relay, creating a permanent timestamped on-chain record.

- **Verification needs nothing from us.** `verify(envelope, publicKey)` returns from the JSON alone: no endpoint, no account and no licence, now or in ten years.
- **Every field is bound.** Payload, key id and issue time sit inside the signed bytes behind a version prefix, so no field can be reordered or replayed against a different timestamp.
- **Survives key rotation.** Each envelope names its key, so an envelope signed under a since-rotated key still verifies years later.
- **Time the chain itself vouches for.** Anchor on Armature L1 and the transaction hash and block number travel inside the signed message, still checkable by an air-gapped verifier.
- **Hybrid when a policy asks for it.** `attest(payload, keypair, { classical })` adds an Ed25519 or ECDSA-P256 co-signature over the same message, and `verifyAsync(envelope, key, { requireBoth: true })` demands both.
- **Three levels of proof.** `signature` and `anchored` verify offline for good; `anchored+live` adds the KXCO registry's answer that the signing key is still trusted now.
- **Runs where you do.** Node.js 20.19 and later, and Cloudflare Workers.
- **Proven underneath.** 1,793 NIST ACVP vectors passed, 0 failed, and 225 interoperability checks against liboqs, Bouncy Castle and the Python reference implementations, 0 failed, in [`kxco-post-quantum`](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/CONFORMANCE.md).
- **A supply chain you can check.** SLSA provenance and a CycloneDX SBOM on every release since 1.1.5, third-party dependencies pinned to exact versions, and every GitHub Action pinned by commit SHA.

**The migration has dates.**

- **NIST** published [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) and [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) in August 2024.
- **United States:** [Executive Order 14412](https://www.federalregister.gov/documents/2026/06/25/2026-12909/securing-the-nation-against-advanced-cryptographic-attacks), signed on 22 June 2026, moves federal high-value and high-impact systems to post-quantum key establishment by 31 December 2030 and to post-quantum signatures by 31 December 2031. [OMB M-26-15](https://www.whitehouse.gov/wp-content/uploads/2026/06/M-26-15-Execution-of-the-Migration-to-Post-Quantum-Cryptography.pdf) requires PQC-agile libraries for all new applications.
- **United Kingdom:** the [NCSC](https://www.ncsc.gov.uk/guidance/pqc-migration-timelines) sets 2028, 2031 and 2035 as its migration milestones.

[Quick start](#quick-start) · [Envelope format](#envelope-format) · [For institutions](#for-institutions) · [Assessment notes](./ASSESSMENT.md) · [Changelog](./CHANGELOG.md) · [kxco.ai](https://kxco.ai)

## When to use this

- Regulatory filings that need a tamper-evident signature
- Document signing where you need to prove content existed at a specific point in time
- Trade confirmations and settlement records
- Any payload where the question "did this exist, unchanged, at this timestamp?" needs a verifiable answer

## Install

```sh
npm install kxco-pq-attest
```

Requires Node.js >= 20.19 or Cloudflare Workers.

## Quick start

**Sign and verify a string:**

```js
import { attest, verify } from 'kxco-pq-attest'
import { mlDsa } from 'kxco-post-quantum'

const keypair = mlDsa.ml_dsa65.keygen()

const envelope = await attest('trade confirmed: BTC/USD 100k @ 67,200', keypair)

const result = verify(envelope, keypair.publicKey)
// { valid: true, payload: Uint8Array, signerKid: '...', issuedAt: '2026-...' }
```

**Anchor on-chain:**

```js
import { attest } from 'kxco-pq-attest'
import { KxcoChain } from 'kxco-pq-chain' // Armature L1 relay client

const chain = new KxcoChain({
  identity:   institutionIdentity,           // a KxcoIdentity from kxco-pq-sdk
  licenceKey: process.env.KXCO_LICENCE_KEY,  // the hosted anchoring service
})

const envelope = await attest(
  { ref: 'INV-2024-0042', amount: 50000 },
  keypair,
  { anchor: true, purpose: 'invoice-sign', chain }
)
// envelope.chainAnchor: { txHash: '0x...', blockNumber: 1234567 }
```

## For institutions

The cryptography is free under Apache-2.0, works offline and needs nothing from
KXCO, now or in ten years. What KXCO sells is the part that has to be operated:
an answer about the present.

| Service | What you get |
|---|---|
| Hosted key registry | Whether a key is active, revoked or rotated, answered at verification time |
| Meta-transaction relay | KXCO validates your signed intent, pays the gas and submits it, so you never hold a token or run a node |
| On-chain anchoring | A timestamp on Armature L1 that the chain itself has verified |
| Live revocation | `anchored+live` verification, which confirms the signing key is still trusted now |
| Support and SLA | Availability commitments, an escalation path and a named contact |

Priced in USD, per seat, per year. No tokens, no nodes and no wallets. The line
between free and paid is set out in
[LICENCE-PRODUCT.md](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/LICENCE-PRODUCT.md).

**Talk to us: [admin@kxco.ai](mailto:admin@kxco.ai)** · [kxco.ai](https://kxco.ai)

## API

### `attest(payload, keypair, options?)`

Signs `payload` with ML-DSA-65 and returns an envelope. Returns a Promise.

| Parameter | Type | Description |
|-----------|------|-------------|
| `payload` | `string \| Buffer \| Uint8Array` | Data to sign. Strings are UTF-8 encoded. |
| `keypair` | `{ secretKey, publicKey }` | ML-DSA-65 keypair from `kxco-post-quantum`. |
| `options.anchor` | `boolean` | Default `false`. When `true`, anchors the envelope hash on-chain. Requires `chain`. |
| `options.purpose` | `string` | Optional label stored with the on-chain anchor (e.g. `'trade-confirm'`). |
| `options.chain` | `object` | Armature L1 relay client. Required when `anchor: true`. Must implement `anchorAttestation({ payloadHash, purpose })`. |
| `options.classical` | `{ alg, privateKey, publicKey }` | Optional Ed25519 or ECDSA-P256 co-signature over the same message the ML-DSA-65 signature covers. Generate the pair with `generateClassicalKeypair(alg)`, which uses WebCrypto and runs in Node, Workers and browsers. |

When `anchor: true`, the envelope hash (SHA-256 of the signed JSON) is posted to the relay and the result is attached to the envelope as `chainAnchor`.

---

### `verify(envelope, publicKey)`

Verifies the ML-DSA-65 signature on an envelope. Returns synchronously.

| Parameter | Type | Description |
|-----------|------|-------------|
| `envelope` | `object` | Envelope produced by `attest()`. |
| `publicKey` | `Uint8Array` | ML-DSA-65 public key corresponding to the signer. |

```js
// success
{ valid: true, payload: Uint8Array, signerKid: string, issuedAt: string }

// failure
{ valid: false, error: string }
```

`payload` is the raw bytes of the original data. For strings, decode with `new TextDecoder().decode(result.payload)`.

---

### `verifyAsync(envelope, publicKey, opts?)`

The full verifier, for the checks that need more than the JSON.

| Option | Type | Description |
|-----------|------|-------------|
| `opts.mode` | `'signature' \| 'anchored' \| 'anchored+live'` | `anchored+live` asks the KXCO registry whether the signing key is still trusted now, and fails closed. |
| `opts.requireBoth` | `boolean` | Require a valid classical co-signature as well as the ML-DSA-65 signature. |
| `opts.classicalPublicKey` | `Uint8Array` | Pin the classical key rather than accepting the one the envelope names. |

## Envelope format

```json
{
  "kxco-attest": "2",
  "payload": "<base64url-encoded bytes>",
  "alg": "ML-DSA-65",
  "kid": "<ML-DSA-65 public key fingerprint>",
  "sig": "<base64url-encoded ML-DSA-65 signature>",
  "issuedAt": "2026-09-29T09:32:11.000Z",
  "chainId": 1111111,
  "anchor": {
    "txHash": "0xabc123...",
    "blockNumber": 1234567
  },
  "verifyModeHint": "anchored"
}
```

`anchor` is present when the envelope was anchored on-chain, `chainId` when the relay confirmed the chain, and `classical` when the envelope was co-signed. The envelope is self-contained either way: `verify()` works from the JSON alone, with no external calls.

The signing message is a deterministic concatenation behind a version prefix: `kxco-attest-v2`, then the payload, algorithm, kid, issue time, chain id, anchor transaction hash and block number, and the verify-mode hint, one per line. No field can be reordered, replayed against a different timestamp or given a different anchor without invalidating the signature.

## The KXCO post-quantum family

This signs, so anyone can prove where a payload came from and that it is
unchanged. The rest of the family covers the jobs around it:

| You need to | Install |
|---|---|
| Put the whole stack in one install | [`kxco-pq`](https://www.npmjs.com/package/kxco-pq) |
| Use ML-DSA, ML-KEM and SLH-DSA directly | [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) |
| Keep signing keys on the HSM you already run | [`kxco-pq-hsm`](https://www.npmjs.com/package/kxco-pq-hsm) |
| Sign a document or record anyone can verify offline | [`kxco-pq-attest`](https://www.npmjs.com/package/kxco-pq-attest) |
| Keep a tamper-evident audit trail | [`kxco-pq-audit`](https://www.npmjs.com/package/kxco-pq-audit) |
| Verify a signature in a browser, with no server | [`kxco-verify`](https://www.npmjs.com/package/kxco-verify) |
| Issue institution identity credentials | [`kxco-pq-sdk`](https://www.npmjs.com/package/kxco-pq-sdk) |
| Encrypt files and payloads to one or many recipients | [`kxco-pq-vault`](https://www.npmjs.com/package/kxco-pq-vault) |
| Encrypt Node streams and WebSockets | [`kxco-pq-tls`](https://www.npmjs.com/package/kxco-pq-tls) |
| Sign and verify webhooks | [`kxco-post-quantum-webhook`](https://www.npmjs.com/package/kxco-post-quantum-webhook) |
| Give an AI agent an identity a verified institution sponsors | [`kxco-pq-agent`](https://www.npmjs.com/package/kxco-pq-agent) |
| Have Armature L1 verify a signature in consensus | [`kxco-pq-chain`](https://www.npmjs.com/package/kxco-pq-chain) |
| Prove an envelope at three levels, offline to on-chain | [`kxco-pq-network`](https://www.npmjs.com/package/kxco-pq-network) |
| Generate and rotate keys from a terminal | [`kxco-pq-cli`](https://www.npmjs.com/package/kxco-pq-cli) |
| Find quantum-vulnerable cryptography in a dependency tree | [`kxco-pq-scan`](https://www.npmjs.com/package/kxco-pq-scan) |
| Fail the build when code reaches past the wrapper | [`eslint-plugin-kxco-pq`](https://www.npmjs.com/package/eslint-plugin-kxco-pq) |

## Release integrity

Every release since 1.1.5 carries a SLSA provenance attestation tying the published tarball to
the commit and workflow that built it: verify with `npm audit signatures`, or read
it from `registry.npmjs.org/-/npm/v1/attestations/kxco-pq-attest@<version>`. A CycloneDX
SBOM is published, from v1.1.5, as a GitHub Release asset at
`releases/download/v<version>/sbom.cyclonedx.json`, a permanent unauthenticated
URL. Sibling `kxco-*` packages sit on caret ranges so a correctness fix in the
base package reaches you on the next install, with no release of every package
above it.

## Security

**ML-DSA-65** (NIST FIPS 204) via [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum), running on the OpenSSL 3.5 primitives where the runtime provides them. No custom cryptography.

Evidenced, and reproducible on your own machine:

- **1,793 NIST ACVP vectors passed, 0 failed** across FIPS 203, 204 and 205, pinned by digest, per [CONFORMANCE.md](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/CONFORMANCE.md). The other 310 are pairings the library refuses as weaker than the parameter set
- **225 interoperability checks passed, 0 failed**, against OpenSSL 3.5, liboqs, Bouncy Castle and dilithium-py/kyber-py, in both directions
- **SLSA provenance** on every release since 1.1.5: verify with `npm audit signatures`
- **CycloneDX SBOM** published with every release since 1.1.5
- `npm run evidence` regenerates the whole bundle from source

Dependency audit history is recorded in [AUDIT.md](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/AUDIT.md).

Version 2 envelopes carry the on-chain anchor **inside** the signed message, so a transaction hash cannot be stapled onto an otherwise valid envelope. The algorithm is resolved from an allowlist, never from the envelope.

To report a vulnerability, open a [private security advisory](https://github.com/KnightsbridgeAIQ/kxco-pq-attest/security/advisories/new) or email **security@kxco.ai**.

## License

Apache-2.0 © 2026 Knightsbridge Financial Ltd, trading as KXCO. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).

## Maintainers

Shayne Heffernan and John Heffernan, [KXCO by Knightsbridge](https://kxco.ai)

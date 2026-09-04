# kxco-pq-attest

[![npm](https://img.shields.io/npm/v/kxco-pq-attest?label=npm&color=b0964f)](https://www.npmjs.com/package/kxco-pq-attest)
[![Socket](https://socket.dev/api/badge/npm/package/kxco-pq-attest)](https://socket.dev/npm/package/kxco-pq-attest)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)
[![node](https://img.shields.io/node/v/kxco-pq-attest.svg)](https://nodejs.org)

Post-quantum document signing and on-chain attestation.

Signs arbitrary data — strings, Buffers, objects — with ML-DSA-65 (NIST FIPS 204) and produces a self-contained JSON envelope any counterparty can verify without trust delegation. Optionally anchors the envelope hash on Armature L1 via the KXCO relay, creating a permanent timestamped on-chain record.

## Release integrity

Every release of this package is checkable without asking us for anything.

- **Provenance.** Each release carries a SLSA provenance attestation tying the
  published tarball to the commit and workflow that built it. Verify with
  `npm audit signatures`, or read it directly from
  `registry.npmjs.org/-/npm/v1/attestations/kxco-pq-attest@<version>`.
- **Bill of materials.** A CycloneDX SBOM is published as a GitHub Release asset
  at `releases/download/v<version>/sbom.cyclonedx.json`, a permanent
  unauthenticated URL. Not an expiring build artifact.
- **Pinned where it matters.** Third-party dependencies are pinned to exact
  versions, never ranges, so the code that performs the cryptography cannot
  change without a release. Sibling `kxco-*` packages sit on caret ranges
  deliberately: it means a correctness fix in the base package reaches you
  without a release of every package above it. That is not theoretical. When
  `@noble/post-quantum` 0.7.1 was found to fail NIST SLH-DSA verification
  vectors, the revert in the base package propagated here on the next install.
  Every GitHub Action is pinned by 40-character commit SHA.
- **Conformance underneath.** The cryptography comes from
  [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum), which
  is run against **2,103 NIST ACVP vectors: 1,793 passed, 0 failed, 310 skipped** and a **225-check
  cross-implementation interoperability matrix** against liboqs, Bouncy Castle
  and two pure-Python implementations, in both directions and with negative
  controls. Its published tarball also rebuilds bit-for-bit from its own tag,
  verified in CI on every run.

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
import { createChain } from 'kxco-chain' // Armature L1 relay client

const chain = createChain({ endpoint: 'https://chain.kxco.ai' })

const envelope = await attest(
  { ref: 'INV-2024-0042', amount: 50000 },
  keypair,
  { anchor: true, purpose: 'invoice-sign', chain }
)
// envelope.chainAnchor: { txHash: '0x...', blockNumber: 1234567 }
```

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

## Envelope format

```json
{
  "kxco-attest": "1",
  "payload": "<base64url-encoded bytes>",
  "kid": "<ML-DSA-65 public key fingerprint>",
  "issuedAt": "2026-05-28T09:32:11.000Z",
  "signature": "<base64url-encoded ML-DSA-65 signature>",
  "chainAnchor": {
    "txHash": "0xabc123...",
    "blockNumber": 1234567
  }
}
```

`chainAnchor` is present only when the envelope was anchored on-chain. The envelope is self-contained without it — `verify()` works from the JSON alone, with no external calls.

The signing message is a deterministic concatenation: `kxco-attest-v1\n<payloadB64>\n<kid>\n<issuedAt>`. No field can be silently reordered or replayed against a different timestamp without invalidating the signature.

## Where this fits

This signs, so anyone can prove where a payload came from and that it has not
changed. The envelope is readable by design: a counterparty verifies it without
a key exchange, offline, years later.

- [`kxco-pq-vault`](https://www.npmjs.com/package/kxco-pq-vault) when the payload must be unreadable as well as provable
- [`kxco-pq-sdk`](https://www.npmjs.com/package/kxco-pq-sdk) to issue and verify identity credentials
- [`kxco-pq-hsm`](https://www.npmjs.com/package/kxco-pq-hsm) for key generation, storage and rotation in hardware

## Part of the KXCO stack

| Package | Purpose |
|---------|---------|
| [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) | ML-DSA-65 and ML-KEM-768 primitives (NIST FIPS 204/203) |
| `kxco-pq-attest` | This package — payload signing and on-chain attestation |
| `kxco-pq-vault` | Post-quantum encryption |
| [`kxco-pq-sdk`](https://www.npmjs.com/package/kxco-pq-sdk) | KxcoIdentity credential issuance and verification |

## Security

**ML-DSA-65** (NIST FIPS 204) via [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum), running on the OpenSSL 3.5 primitives where the runtime provides them. No custom cryptography.

Evidenced, and reproducible on your own machine:

- **2,103 NIST ACVP vectors** across FIPS 203, 204 and 205, pinned by digest: 1,793 passed, 0 failed, 310 skipped, where each skip is the library refusing a pre-hash weaker than the parameter set
- **225 interoperability checks passed, 0 failed, 42 not applicable** against OpenSSL 3.5, liboqs, Bouncy Castle and dilithium-py/kyber-py, in both directions
- **SLSA provenance** on every published release — verify with `npm audit signatures`
- **CycloneDX SBOM** published with each release
- `npm run evidence` regenerates the whole bundle from source

Dependency audit history is recorded in [AUDIT.md](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/AUDIT.md).

Version 2 envelopes carry the on-chain anchor **inside** the signed message, so a transaction hash cannot be stapled onto an otherwise valid envelope. The algorithm is resolved from an allowlist, never from the envelope.

To report a vulnerability, open a [private security advisory](https://github.com/KnightsbridgeAIQ/kxco-pq-attest/security/advisories/new) or email **security@kxco.ai**.

## License

Apache-2.0 © 2026 KXCO by Knightsbridge

## Maintainers

Shayne Heffernan and John Heffernan — [KXCO by Knightsbridge](https://kxco.ai)

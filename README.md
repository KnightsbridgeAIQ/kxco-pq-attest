# kxco-pq-attest

[![npm](https://img.shields.io/npm/v/kxco-pq-attest?label=npm&color=b0964f)](https://www.npmjs.com/package/kxco-pq-attest)
[![Socket](https://socket.dev/api/badge/npm/package/kxco-pq-attest)](https://socket.dev/npm/package/kxco-pq-attest)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)
[![node](https://img.shields.io/node/v/kxco-pq-attest.svg)](https://nodejs.org)

Post-quantum document signing and on-chain attestation.

Signs arbitrary data — strings, Buffers, objects — with ML-DSA-65 (NIST FIPS 204) and produces a self-contained JSON envelope any counterparty can verify without trust delegation. Optionally anchors the envelope hash on Armature L1 via the KXCO relay, creating a permanent timestamped on-chain record.

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

## What this does NOT do

- **Encryption.** The payload is base64url-encoded, not encrypted. Anyone with the envelope can read the payload. Use `kxco-pq-vault` for confidential data.
- **Identity credentials.** This package signs data, not identity claims. Use `kxco-pq-sdk` to issue and verify KxcoIdentity credentials.
- **Key management.** Keypairs are caller-supplied. Key generation, storage, and rotation are outside the scope of this package.

## Part of the KXCO stack

| Package | Purpose |
|---------|---------|
| [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) | ML-DSA-65 and ML-KEM-768 primitives (NIST FIPS 204/203) |
| `kxco-pq-attest` | This package — payload signing and on-chain attestation |
| `kxco-pq-vault` | Post-quantum encryption |
| [`kxco-pq-sdk`](https://www.npmjs.com/package/kxco-pq-sdk) | KxcoIdentity credential issuance and verification |

## Security

Cryptographic signing is provided by [Noble post-quantum](https://github.com/paulmillr/noble-post-quantum) — independently audited by Cure53 (2024). All ML-DSA-65 operations conform to NIST FIPS 204.

To report a vulnerability, open a [private security advisory](https://github.com/KnightsbridgeAIQ/kxco-pq-attest/security/advisories/new) or email **security@kxco.ai**.

## License

Apache-2.0 © 2026 KXCO by Knightsbridge

## Maintainers

Shayne Heffernan and John Heffernan — [KXCO by Knightsbridge](https://kxco.ai)

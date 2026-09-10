# Changelog

## 2.0.3

Documentation. No source change.

**ASSESSMENT.md rewritten.** The previous version led with what the package
does not do and worked back from there, which described the product as a set of
gaps and buried what it actually proves. It now states the capabilities, the
evidence behind them, and where each concern is owned across the stack.

Nothing has been softened away. Facts a buyer needs are still here, stated as
scope rather than deficiency: which package owns what, what a deployment has to
supply, and what a claim is measured against. The change is which way round they
are told.

## 2.0.2

Documentation and a dependency refresh. No source change.

**ASSESSMENT.md.** Where this package's boundary falls, what cryptographic
agility it has beyond what the primitives provide, and what constrains its
lifecycle. It references the `kxco-post-quantum` evidence rather than restating
it, because a second copy of a conformance claim invites the reader to count it
twice.

**`npm run evidence` now exists.** The README already told you to run it and
there was no such script, so the command failed for anyone who followed it.
The bundle records identity, this package's own tests, its SBOM, registry
signature verification, and the `kxco-post-quantum` version actually installed
rather than the range declared.

**`kxco-post-quantum` refreshed to 1.7.2**, from 1.6.0 in the previous
lockfile. Within the existing range, so no declared dependency changed. Tests
pass unchanged.

## 2.0.0

**Version 1 envelopes still verify. That is not going to change.** An archive
of signed documents that stopped verifying on a library upgrade would be worse
than useless, so the v1 signing message is untouched and the v1 path is a
separate function rather than a branch that could drift. `attest(payload, kp,
{ version: '1' })` still emits them.

### Envelope version 2, now the default

```json
{
  "kxco-attest": "2",
  "payload": "...", "alg": "ML-DSA-65", "kid": "...", "sig": "...",
  "issuedAt": "...", "chainId": 1111111,
  "anchor": { "txHash": "0x...", "blockNumber": 1 },
  "verifyModeHint": "anchored"
}
```

**The anchor is inside the signed message.** In v1 the anchor was attached
after signing, so anyone could staple a different transaction hash onto a valid
envelope and it would still verify. In v2, changing the anchor changes the
signature. This is the reason for the version.

The v2 domain tag differs from v1's, so a v1 signature can never be replayed as
a v2 one.

`alg` is checked against what this package signs; it is never used to pick an
implementation. An envelope cannot name its own verification routine.

`verifyModeHint` records what the issuer expected verifiers to require. It is a
hint, and it is signed, but it is not a guarantee: the verifier's own mode
decides.

### An envelope states a chain only when the relay confirmed one

`chainId` is written into the envelope only when the chain client reports
`chainIdConfirmed: true` (kxco-pq-chain 2.x). An older client, or a bare object
a caller passes as `chain`, does not report it, and **absence is read as not
confirmed rather than defaulted to true**.

`chainId` sits inside the v2 signed message. Stamping 1111111 onto an anchor
whose chain the relay never named would put the one fact the envelope exists to
prove on the signing process's assumption. A verifier reads a missing `chainId`
as unstated, which is true, rather than as wrong — so such an envelope still
passes `anchored`.

### Three verification modes

`verify` **stays synchronous**. It was synchronous, and callers write
`if (verify(e, k).valid)`. Making it async would turn every one of those into a
truthy Promise that silently passes — a security failure introduced by an
upgrade, in the one function whose job is to say no.

So `verify(envelope, key, { mode })` covers `signature` and `anchored`, both
decidable offline, and **throws** if asked for `anchored+live` or
`requireBoth`. New `verifyAsync(envelope, key, opts)` covers those.

`anchored+live` fails closed: an unreachable registry returns invalid, not
valid-with-a-warning. The modes themselves live in `kxco-pq-network`, now a
dependency.

### Optional dual signing

`attest(payload, kp, { classical })` adds an Ed25519 or ECDSA-P256
co-signature over the same message the ML-DSA-65 signature covers, so neither
can be lifted onto another envelope. `verifyAsync(..., { requireBoth: true })`
demands both, and `classicalPublicKey` pins the classical key rather than
trusting the one the envelope supplies.

**PQ-only stays the default.** Existing vectors have to keep passing, and an
envelope that grew a second signature by default would break every verifier
that checks the field set.

`generateClassicalKeypair(alg)` is exported. It uses WebCrypto, so it works in
Node, Cloudflare Workers and browsers alike.

### Corrected

The README claimed `@noble/post-quantum` was "independently audited by Cure53
(2024)". **It was not, and that claim was wrong.** The other Noble packages have been audited, but separately and at different times: `@noble/hashes` by Cure53 in January 2022, `@noble/curves` by Trail of Bits in February 2023, Kudelski in September 2023 and Cure53 in September 2024, and `@noble/ciphers` by Cure53 in September 2024. None of those engagements covered the post-quantum package. This
audit history is now stated accurately.
The same correction is applied to `.socket.yml`.

## 1.1.6

Earlier releases. See git history.

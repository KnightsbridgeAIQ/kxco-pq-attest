# Assessment notes

The answers a buyer's readiness assessment asks for: what this package does,
how it moves when algorithms move, and what it takes to run it.

Algorithm conformance belongs to
[`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum), which
runs 2,103 NIST ACVP vectors and a cross-implementation interoperability matrix
and publishes the lot. Cited here, proven there.

## What this package is

A payload wrapped in a self-contained JSON envelope carrying an ML-DSA-65
signature, the signer's key fingerprint and an issue time.

**Verification needs nothing from us, and that is the product.**
`verify(envelope, publicKey)` returns synchronously from the JSON alone. A
counterparty holding the envelope and the public key needs no endpoint, no
account, no licence and no cooperation from KXCO, now or in ten years. An
attestation that depended on a vendor being reachable would be worth less
precisely when it mattered most, which is why this one does not.

**Every field is bound.** The signed message is
`kxco-attest-v1\n<payloadB64>\n<kid>\n<issuedAt>`, a deterministic concatenation
with a version prefix inside the signature. No field can be reordered, and an
envelope cannot be replayed against a different timestamp without invalidating
the signature. The version prefix being *inside* the signed bytes is what stops
an attacker stripping it to force a different interpretation.

**The envelope names its key.** A `kid` per envelope means a verifier holding
several keys selects the right one, so an envelope signed under a since-rotated
key still verifies years later. Long-lived attestations are the normal case
here, not the awkward one.

**Time can be anchored.** `chainAnchor` carries a transaction hash and block
number when the envelope was anchored on Armature L1, which is an independent
bound on when the signature existed rather than the signer's own assertion. The
envelope stays self-contained either way: `verify()` works from the JSON with no
external call, and the anchor travels inside it, so even the anchored form is
checkable by an air-gapped verifier.

## Scope

This package answers one question completely: was this payload signed by the
holder of this key, and is it unmodified. It answers it offline, in constant
time, with no dependencies beyond the primitives.

Key identity is a separate question with a purpose-built answer.
[`kxco-pq-network`](https://www.npmjs.com/package/kxco-pq-network) resolves
whether a kid is `active`, `revoked`, `rotated` or `expired` against the
registry, in three explicit modes so a caller chooses how much assurance a given
decision warrants. Keeping the two apart is what lets verification stay offline
by default and become live only where a caller asks for it.

Records that accumulate belong in
[`kxco-pq-audit`](https://www.npmjs.com/package/kxco-pq-audit); an envelope
travels rather than accrues.

## Agility

**Inherited.** Parameter sets and the two interchangeable backends belong to
`kxco-post-quantum`.

**Versioned inside the signature.** `kxco-attest-v1` is signed rather than
written alongside, so a v2 envelope format is distinguishable from v1 by
something an attacker cannot strip. That is the property a format migration
needs, and it is why introducing a second algorithm later is a v2 the existing
mechanism already accommodates.

## Running it

**Release integrity.** Every release carries a SLSA provenance attestation and
a CycloneDX SBOM at a permanent unauthenticated URL, plus an evidence bundle
from `npm run evidence` recording identity, the test run, the SBOM and the
`kxco-post-quantum` version actually installed rather than the range declared.

**Supported versions.** One line moving forward. Fixes land in the next release.

**Cost.** One ML-DSA-65 signature per envelope and one verification per check,
so cost is per envelope rather than per byte of payload. The payload is
base64url encoded into the JSON, which inflates it by about a third; attest a
digest where the payload is large and the envelope is what travels.

**Runtime.** Node 20.19 and later, with Node 24 and later running the primitives
in OpenSSL 3.5 for roughly 4x to 8x per operation.

## Correcting this document

Every claim here is checkable against `src/` and the envelope format in the
README. If one does not match, that is a defect worth reporting through the
repository's issues.

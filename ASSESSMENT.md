# Assessment notes

Where this package's boundary falls, what agility it has, and what constrains
its lifecycle.

Algorithm conformance belongs to
[`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) and is
published in that package's evidence bundle. It is referenced here, never
restated.

## Boundary

**What the assessed thing is.** A library that wraps a payload in a
self-contained JSON envelope carrying an ML-DSA-65 signature, the signer's key
fingerprint, an issue time and, optionally, a chain anchor.

**Operate: verification makes no network calls, and that is the product.**
`verify(envelope, publicKey)` returns synchronously from the JSON alone. A
counterparty holding the envelope and the public key needs nothing from KXCO,
no endpoint, no account and no cooperation. Anything that made verification
depend on us would undo the reason to use this.

The corollary is that trust in the key is entirely outside this package.
`verify` tells you the envelope was signed by the holder of the key you passed
in. It cannot tell you that key belongs to who you think, and it does not try.
[`kxco-pq-network`](https://www.npmjs.com/package/kxco-pq-network) is the
package that answers key identity, in three explicit levels; this one answers
one question and answers it offline.

**Signing binds every field, by construction.** The signed message is
`kxco-attest-v1\n<payloadB64>\n<kid>\n<issuedAt>`, a deterministic
concatenation with a version prefix. No field can be reordered, and an envelope
cannot be replayed against a different timestamp without invalidating the
signature.

**`issuedAt` is the signer's clock.** It is signed, so it cannot be altered
after the fact, and a signed clock is still the signer's clock. A signer who
sets their system time back produces a valid envelope with an earlier time.
Where the time matters, the independent bound is `chainAnchor`, which is
present only when the envelope was anchored, and the anchor is what a verifier
should be reading rather than the field.

**Start and update.** No release signing of its own. Published through CI with
npm provenance.

**Protect records.** Not this package's role: an envelope travels, it is not a
log. [`kxco-pq-audit`](https://www.npmjs.com/package/kxco-pq-audit) is the
append-only record.

**Retain history, and this package is better placed than its siblings.** The
envelope carries a `kid`, so a verifier holding several keys can select the
right one, which is what makes an envelope signed under a since-rotated key
still verifiable. `kxco-pq-audit` has no equivalent and cannot do this.

What is still missing is validity: nothing here records whether the key was
trusted at `issuedAt`, and there is no revocation. So an envelope signed by a
key that was later compromised verifies exactly as cleanly as one that was not.
For long-lived attestations the anchor is the thing that pins the signature to a
point in time, and the key-status question at that point in time is not
answered anywhere in this stack.

## Agility

**Inherited.** Parameter sets and backends belong to `kxco-post-quantum`. See
that package's `AGILITY.md`.

**The addition: a version prefix inside the signed bytes.** `kxco-attest-v1`
is signed, not merely written alongside. A v2 envelope format is therefore
distinguishable from v1 by something an attacker cannot strip, which is the
property a format migration needs and the reason the prefix is inside the
signature rather than beside it.

**The limit: the algorithm is not named in the envelope.** The format carries
`kid` and a signature, and no algorithm identifier. A verifier resolves the
algorithm by knowing it is ML-DSA-65, not by reading it. Compare
`kxco-pq-vault`, whose header carries an explicit `algorithm:` line, and
`kxco-pq-tls`, whose frame sizes make the algorithm unambiguous on the wire.

That is workable while exactly one algorithm exists, and it is the field a
second one would need. Adding it later means a v2 format, which the version
prefix already allows for; the point is that the move is a release of this
package rather than a configuration.

## Lifecycle

**Assess `origin/main`, and know that this working tree is ahead of it.**
Verified 8 September 2026: `origin/main`, this checkout and npm all read 2.0.1,
so the published artefact does correspond to `origin/main`.

What differs is the local working branch. `feat/verification-modes-and-registry`
carries 8 commits that have never been pushed to the remote, and is 2 behind
`origin/main`. The same pattern holds in `kxco-pq-sdk`, `kxco-pq-cli` and
`kxco-pq`. So a clone of this repository from GitHub is not what sits on the
maintainer's machine, and unpublished work exists in only one place. The
evidence bundle records the branch it was built from in `01-identity.json`,
which is why that field is there.

**Supported versions.** One line moving forward, matching the family. This
package is at 2.x while much of the family is at 1.x; the major numbers are per
package and do not indicate a coordinated release train.

**Pins.** `kxco-post-quantum` is declared `^1.6.0` and the tree the evidence
bundle was last built from resolved it to **1.6.0**, against a current
primitives release of 1.7.2. That the range and the resolution currently agree
is a fact about this tree, not a guarantee: another install of this same package
version may resolve differently. `02-primitives.json` records what was actually
installed, which is the point of recording it.

The primitives package pins its own dependencies exactly and explains why. That
rule is not applied here, and applying it would cost a release of this package
per primitives release.

**Ceiling.** No hardware ceiling. One ML-DSA-65 signature per envelope and one
verification per check, so cost is per envelope rather than per byte of
payload. The payload is base64url encoded into the JSON, which inflates it by
about a third, so large payloads are a transport and storage cost rather than a
cryptographic one. Attest a digest instead where that matters.

**Roadmap.** No external audit of this package, no bug bounty, no formal
analysis of the envelope format.

## Correcting this document

Every claim here is checkable against `src/` and the envelope format in the
README. If one does not match, that is a defect worth reporting through the
repository's issues.

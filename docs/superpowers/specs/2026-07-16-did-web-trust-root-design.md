# `greentic-trust` — did:web trust root (Slice S1)

**Date:** 2026-07-16
**Status:** Design, approved for planning
**Scope:** S1 only — the verification library. S2–S5 are named here for context but are separate specs.

## Problem

Nothing in Greentic can answer "is this really a Greentic key?" without a human pasting one in
out of band. Every verifier we have is complete except for its trust anchor:

| Verifier | Trust anchor today |
|---|---|
| `greentic-runner` `mcp_store_pull` | `GREENTIC_MCP_TRUSTED_SIGNERS`, a comma-separated env var. **Set in zero deployments** — only in tests. |
| `packc verify` | The user supplies a public key file. No trust root, no discovery. |
| `greentic-distributor-client` | Good DSSE/in-toto code; `VerificationPolicy::default()` is `require_signature: false, trusted_keys: []`. Nothing outside the crate populates it. |
| `greentic-designer-sdk` trust store | Trust-on-first-use, anchored to nothing. `verify.rs:62-74` says so in a log line. |
| `gtc` install | No checksum, no signature. Only checks that `manifest.cbor` exists inside the archive. |

The SDK states the blocker directly: `trust_store.rs:7` — the root of trust is "org-blocked", and
`root_verifier.rs:51` returns `"production root key not yet provisioned (org-blocked)"`.

did:web answers exactly this question and needs no new PKI, no key ceremony beyond one root, no
keys embedded in binaries, and no TUF adoption. The trust anchor is WebPKI plus DNS control —
infrastructure we already run and every client already trusts.

## What this slice delivers

A new crate, `greentic-trust`: given a signed `describe`, a `PublisherCert`, and a trusted DID,
decide whether the artifact is authentic — or say precisely why not.

Pure library. One HTTP GET, no global state, no filesystem, no deploy, and **no dependency on the
org-blocked root key** (the whole chain tests against a fixture root).

## Decisions

These were settled during design. Each has a live alternative that was rejected; recording why
matters more than recording what.

### D1 — Publish one root key, not N publisher keys

`store-server` mints a **distinct Ed25519 keypair per publisher** — `publisher_keys` has a unique
index on `(publisher_id) WHERE revoked_at IS NULL`. There is no platform-wide signing key anywhere
in the codebase.

The runner's trust list is **flat**: `trusted_signers() -> Vec<VerifyingKey>`, verified with
`trusted.iter().any(|key| key.verify_strict(...).is_ok())`. No key id, no publisher id, no
namespace binding. Any trusted key may sign any component in any namespace.

So publishing N publisher keys via did:web reproduces today's flat allowlist with extra steps: we
gain discovery and no attribution. **Rejected.**

Instead: did:web publishes **one root key per environment**. The root signs a `PublisherCert`
vouching for each publisher key. Publisher keys rotate freely without touching the document.

```
did:web:trust.greentic.cloud/.well-known/did.json
└── root key (Ed25519, stable, rotates ~never)
         │ signs
         ▼
    PublisherCert { publisherPublicKey, rootSignature, keyId, notAfter }
         │ vouches for
         ▼
    publisher key (N, rotates freely)
         │ signs
         ▼
    describe.json inside the .gtxpack
```

This is already half-built: `PublisherCert` exists at
`greentic-designer-sdk/crates/greentic-extension-sdk-contract/src/publisher_cert.rs` with
`{publisherPublicKey, rootSignature, keyId?, notAfter?}` and a `verify(&root) -> VerifyingKey`.
It has never been issued by anything — no migration, no handler, no OpenAPI schema mints one.

Note this vindicates the original "certificate" framing: a `PublisherCert` *is* a certificate — a
root signature over a subject key with an expiry. What it is not is X.509.

### D2 — One root per environment

`greentic.cloud` runs three environments. A shared root would mean **a leaked research key can sign
artifacts that production clients trust** — and research is the environment with the loosest access.

| Environment | DID | Root custody |
|---|---|---|
| research | `did:web:trust.research.greentic.cloud` | Secret manager |
| staging | `did:web:trust.staging.greentic.cloud` | Secret manager |
| production | `did:web:trust.greentic.cloud` | Offline ceremony (S2) |

Clients are configured with which DID to trust. That value is a **URL, not a secret** — it belongs
in ordinary config, which is the entire point of the design.

### D3 — Root key stays offline (production)

A cert vouches for a publisher's *key*, not for each artifact, so certs are issued at publisher
onboarding and key rotation — on the order of months. The root therefore never needs to be online,
and `store-server` never holds it. It stores finished certs and embeds them at publish time.

Rejected: KMS-with-online-issuance. It removes the manual step, but any caller holding
store-server's KMS credentials can mint certs, which puts the blast radius back on store-server —
the exact property this design exists to avoid.

### D4 — The document is static, on an origin that serves no artifacts

If the DID document and the artifacts share a host, whoever owns that host serves a malicious
artifact **and** a matching key, and verification passes. That is a complete break.
`store-server` is where `.gtxpack` files live, so it is disqualified as a host by construction.

Static also decouples availability: a live document endpoint would couple every customer's install
path to a service's uptime.

S1 does not host anything — it only consumes. Hosting is S2.

### D5 — This crate, not `greentic-types`

Reuse-first points at `greentic-types`, but its release train is gated: the consumer graph caps it
below `1.2.0-0`. Landing S1 there drags it behind an unrelated blocker. A standalone crate releases
on its own cadence.

Dependency direction is one-way: `runner → greentic-trust`, `sdk → greentic-trust`,
`store-server → greentic-trust`.

**`PublisherCert` is re-authored here, not moved — and the SDK's copy stays untouched in S1.**
A move would require the SDK to depend on `greentic-trust`, which cannot happen until the crate is
published; S1 would be unable to land without breaking the SDK. So S1 owns the canonical type from
the start, and the SDK's copy becomes vestigial: **nothing issues certs today**, so that copy is
exercised only by its own unit tests and is dead in every deployment. S5 deletes it and re-points
the SDK. The duplication is one slice long and one of the two sides is provably unreachable.

## Architecture

Six units, each with one purpose and testable alone.

| Unit | Purpose | Depends on |
|---|---|---|
| `did` | Parse `did:web:*` → URL. Pure, no I/O. | — |
| `document` | Parse a DID document → key set. Enforces the did:web binding. | `did` |
| `resolver` | `RootResolver` trait + HTTP implementation with a TTL cache. | `did`, `document` |
| `cert` | Verify a `PublisherCert` — root signature and expiry. | — |
| `chain` | Entry point: (describe, cert, DID) → verified key or error. | all |
| `error` | One enum; every failure distinguishable. | — |

### `JwksCache` is a pattern to mirror, not a dependency

`greentic-designer-admin/src/auth/oidc/jwks_cache.rs` is the closest existing thing —
host-keyed TTL cache with a forced refresh and single retry on kid-miss. It cannot be reused as a
dependency: it lives in an application's `src/`, not a shared crate, and its key type is
`jsonwebtoken`'s EC JWK, while we need OKP/Ed25519. We mirror the shape and fix two things it gets
wrong (below). Longer term `greentic-trust` could replace it.

### This crate will reject tenant-manager's own DID documents

`document` enforces the did:web binding: the document's `id` must equal the DID that was resolved.
TM violates this for alias hosts — `discovery.rs:44` uses the tenant's primary domain for `id` and
`controller` while `discovery.rs:68` loads the key by request host, so
`GET https://login.acme.com/.well-known/did.json` returns `id: did:web:id.acme.com`. It is
untested because every fixture seeds exactly one primary domain.

This is not a conflict. The crate is right, TM has a bug, and S1 is unaffected because our
documents are static files that TM does not produce. It is recorded here so nobody "fixes" the
crate to accommodate it.

## Wire format

`store-server` already injects a `signature` object into `describe.json` at publish
(`handlers/extensions/publish.rs:167`). The cert rides in the same object. S1 defines the shape;
S3 populates it.

```json
"signature": {
  "algorithm": "ed25519",
  "publicKey": "<publisher public key, base64>",
  "value": "<signature over JCS(describe minus signature)>",
  "certificate": {
    "publisherPublicKey": "<must equal publicKey above>",
    "rootSignature": "<root signature over the cert body>",
    "keyId": "<publisher_keys.id>",
    "notAfter": "2027-01-01T00:00:00Z"
  }
}
```

Signed bytes are the describe minus its `signature` member, JCS/RFC-8785 canonicalized
(`serde_jcs::to_vec`) — unchanged from what store-server and the runner already do on both sides.

### What `rootSignature` signs

The root signs the **cert body**: the `certificate` object minus its own `rootSignature` member,
JCS-canonicalized, with a domain-separation prefix.

```
signed_bytes = b"greentic-publisher-cert-v1\x00" || serde_jcs::to_vec({
    "publisherPublicKey": "...",
    "keyId": "...",
    "notAfter": "..."
})
```

Three points, each load-bearing:

- **The prefix is domain separation.** Without it, a root signature is just a signature over some
  canonical JSON, and the same root key signing anything else JSON-shaped could be replayed as a
  cert. The prefix and the `\x00` terminator make cert bytes unmistakable for any other message
  this root will ever sign.
- **`keyId` and `notAfter` are inside the signed bytes.** If `notAfter` sat outside, an attacker
  could extend any cert's life by editing one field.
- **`keyId` and `notAfter` are required in this profile.** The existing `PublisherCert` types them
  as `Option` (`keyId?`, `notAfter?`). S1 rejects a cert missing either — a cert with no expiry is
  a permanent grant, which is exactly what revocation-by-expiry depends on not existing. The type
  moves as-is for compatibility; the *verifier* is what enforces presence.

### This replaces the current cert scheme, and that is free

`PublisherCert::verify` today signs the **raw 32-byte publisher key and nothing else**:

```rust
root.verify_strict(publisher_key.as_bytes(), &signature)
```

So `keyId` and `notAfter` sit outside the signed bytes and can be edited at will — the exact attack
the "expiry is signed" requirement above exists to stop. The doc comment even concedes it:
*"`not_after` is not enforced here; expiry is the caller's responsibility."* No caller enforces it,
because no caller exists.

That is what makes the change free: **no `PublisherCert` has ever been issued.** Nothing in
`store-server` mints one — no migration, no handler, no OpenAPI schema. There are no certs in the
wild to break, so S1 changes the signed-bytes format outright rather than versioning around it.
The `v1` in the domain-separation prefix starts here.

## Verification order

Ordered for security, not for cost. Every step fails closed.

1. Parse the signature block. Absent → reject.
2. Resolve the trusted DID → root key set (cached).
3. Verify `rootSignature` over the cert body against a key in the document's `assertionMethod`.
4. Check `notAfter` is strictly after `now`.
5. **Check `certificate.publisherPublicKey == signature.publicKey`.**
6. Verify `signature.value` over `JCS(describe − signature)` using that key.

### Step 5 carries the whole chain

Without it an attacker attaches publisher A's genuine cert to an artifact signed with their own
key: step 3 passes (the cert is real), step 6 passes (the signature matches the attacker's key),
and the artifact verifies.

This is not hypothetical — it is the hole in the SDK today. `verify.rs:41-46` takes the key from
`describe.signature.public_key`, verifies the signature against that self-asserted key, and then
applies the trust anchor. Under `Normal`, the first install of an unknown extension id trusts an
attacker-supplied key unconditionally.

### Time is a parameter

`verify(..., now: chrono::DateTime<Utc>)`. Never `SystemTime::now()` internally. This makes expiry
testable without waiting, and keeps the crate usable from WASM and Cloudflare Workers, which have no
ambient clock. The tenant-manager platform plan takes a caller-supplied `now` for the same reason.

`chrono`, not `time` — it is what `publisher_cert.rs` already uses and what the workspace already
carries.

### Expiry is strict at the boundary

Valid iff `now < notAfter`. At exactly `notAfter` the cert is **expired**.

This changes the existing behaviour. `publisher_cert.rs` computes `is_expired` as `now > expiry`,
and `cert_expiry_boundary_is_inclusive` asserts that a cert exactly at `notAfter` is still valid.
The difference is one second of a months-long window and nothing depends on it, so it goes the
fail-closed way. That test is rewritten as part of the move rather than left contradicting the spec.

### There is no `Skipped` variant

`greentic-component/crates/greentic-component-store/src/verify.rs:70` defines
`enum VerifiedSignature { Skipped }` — one variant, so "verified" and "never checked" are the same
type. `greentic-trust` must not offer that door: the verifier reports pass, or why it failed.
Policy — whether unsigned is tolerable — belongs to the caller.

No `bool` returns and no `Option` for any security decision.

## Errors

One enum. Every failure distinguishable, every variant carrying what a reader needs to act.

```
DidParse { input }
NotWebMethod { method }
InsecureScheme { url }
Fetch { source }
HttpStatus { code }
DocumentParse { source }
BindingMismatch { expected, found }
NoAssertionKeys { did }
UnsupportedAlgorithm { alg }
SignatureBlockMissing
CertMissing
CertMissingExpiry
CertMissingKeyId
CertSignatureInvalid
CertExpired { not_after, now }
CertKeyMismatch { cert_key, signing_key }
DescribeSignatureInvalid
```

## Caching

- **Keyed by the full DID string**, not by host. `JwksCache` keys by `issuer.host_str()`, so two
  issuers on one host collide.
- **TTL default 600s**, configurable. Revocation runs through cert expiry, not the document, so the
  document only changes on root rotation. The TTL exists for the root-compromise case.
- **Errors are never cached.** A transient outage must not lock verification out for a TTL.
- **Single-flight.** `JwksCache` has none, so a burst of misses stampedes the issuer.

The `RootResolver` trait is what makes offline verification possible later: S5 supplies an
implementation backed by a pin, with no network. S1 provides the seam without owning the pin format.

## Testing

Every security invariant gets one test, and every test gets a mutation that must turn it red. A
test whose invariant survives its own mutation is not a test.

| Invariant | Test | Mutation that must fail it |
|---|---|---|
| Cert binds to the signing key | Publisher A's valid cert on an artifact signed by an attacker key | Delete the step-5 check |
| did:web binding | Document returns `id: did:web:evil.com` while resolving `trust.greentic.cloud` | Skip `doc.id == resolved_did` |
| Environment isolation | Cert signed by root-R verified against root-P | Accept any root |
| Expiry | `notAfter` in the past, and exactly at `now` | `>` → `>=`, or drop the check |
| Expiry is mandatory | Cert with `notAfter` absent | Treat a missing expiry as "never expires" |
| Expiry is signed | Cert with `notAfter` edited after issuance | Move `notAfter` outside the signed bytes |
| Domain separation | A root signature over non-cert JSON replayed as a cert | Drop the `greentic-publisher-cert-v1\x00` prefix |
| HTTPS required | DID resolving to `http://` | Allow http without the dev flag |
| Fail closed | Valid document with an empty `assertionMethod` | — must reject, not "no constraints" |

**Environment isolation** is the test that proves D2 is real rather than decorative. If root-R can
sign something production accepts, the three-root split is theatre.

**Fail closed** looks trivial and is a classic trap. `trusted.iter().any(...)` over an empty list
returns `false`, which is accidentally correct — but a document that parses successfully with zero
keys reads naturally as "unconstrained". Reject explicitly.

### URL derivation table

```
did:web:example.com          → https://example.com/.well-known/did.json
did:web:example.com:a:b      → https://example.com/a/b/did.json
did:web:example.com%3A8443   → https://example.com:8443/.well-known/did.json
did:key:z6Mk…                → reject (not the web method)
did:web:                     → reject
did:web:h:..:x               → reject (traversal)
```

Percent-encoding and traversal are the attack surface here, so they are table entries rather than
prose.

### Running the mutation checks

Assert `git diff` is non-empty before concluding "the test survived". A mutation that lands on a
line `cargo fmt` reflows can become a no-op, and a no-op reads exactly like a passing test.

Fixtures move from the SDK — `FixtureRootVerifier` already exists — so the full chain tests
end-to-end with no ceremony, no DNS, and no network.

## Out of scope for S1

Named to prevent scope drift, each with its own spec:

| Slice | Contents | Depends on |
|---|---|---|
| S2 — root provisioning | Ceremony runbook, three roots, three `did.json` published to R2, DNS | — (ops) |
| S3 — store-server issuance | Store `PublisherCert`, embed in describe at publish | S1, S2 |
| S4 — runner verification | Replace the flat allowlist with cert → root → did:web | S1, S2 |
| S5 — SDK re-anchor | TOFU pin becomes root-anchored; offline `RootResolver` | S1, S2 |

Also out of scope, deliberately: the tenant-manager alias-host bug (its own fix, in its own repo),
and unwinding store-server's custody of publisher private keys (real debt, unrelated to this
chain).

## What this does not buy

did:web gives discovery, not compromise resilience. No threshold keys, no offline root beyond our
own ceremony, no transparency log. A rogue CA, DNS hijack, or registrar compromise means an
attacker serves their own document, and we have neither CT monitoring nor pinning to catch it.
This is not TUF and not Sigstore, and it should not be sold internally as if it were.

What it is: a step from *no trust root at all* to *a trust root anchored in WebPKI and DNS*, using
infrastructure we already run. It forecloses nothing — a TUF or Sigstore root can be anchored the
same way later.

## Open question for Maarten

D3 assumes we can run an offline ceremony for the production root: generate the key on an
air-gapped machine, keep it on hardware, and convene to sign certs at publisher onboarding. That
needs a named owner and a runbook, and it is what `root_verifier.rs:51` means by "org-blocked".

S1 does not wait on this. The fixture root exercises the entire chain. But S2 through S5 cannot
ship to production without it, so the decision wants starting now rather than when S1 lands.

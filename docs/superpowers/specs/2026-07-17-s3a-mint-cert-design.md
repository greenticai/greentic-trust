# S3a — publisher certificate minting (`mint-cert`)

**Date:** 2026-07-17
**Status:** Design, approved for planning
**Epic:** did:web trust root. S1 (verification library) and S2 (ceremony CLI: gen-root / build-doc / verify-doc) are merged.
**Scope:** the `greentic-trust` half of S3 — graduate `mint_cert` into the always-compiled `ceremony` module and add a `mint-cert` CLI subcommand. The store-server half (embedding the cert into describe.json at publish) is **S3b**, a separate slice in the greentic-store-server (greentic-biz) repo that consumes this cert format.

## Problem

The chain S1 verifies ends: a root-signed `PublisherCert` vouches for a publisher's key, which signs the describe. S2 produced the root and the DID document; nothing yet produces the **cert**. `mint_cert` exists but is test-only (`cert::fixtures`, `#[cfg(any(test, feature = "testing"))]`) and uses `.expect()`, so it cannot mint a real cert in a ceremony. S3a makes cert minting a real, always-compiled operation and exposes it as a CLI subcommand, completing the ceremony toolkit: **gen-root, build-doc, verify-doc, mint-cert**.

A minted cert is the input S3b (store-server) stores at publisher onboarding and embeds into `signature.certificate` at publish. This slice does not touch store-server; it produces the artifact store-server will consume.

## The custody decision this sits under (epic-level, recorded here)

The recon confirmed store-server holds every publisher's private key and signs describes server-side (`auth/signing.rs:27` `sign_for_publisher`; `publisher_keys.private_key_enc`, AES-256-GCM under one non-rotatable `SIGNING_KEY_ENCRYPTION_KEY`). Two custody models were on the table:

- **A — store keeps signing; the cert is a root anchor over the store-held key.** Store-server's signing is unchanged; a cert minted offline over the publisher's *public* key is stored at onboarding and embedded at publish. The runner verifies cert → root → did:web instead of a flat env-var allowlist. Real improvement — trust becomes anchored and attributable, and store-server cannot mint a *new* trusted publisher without the offline root — but store-server compromise can still sign as any *existing* publisher.
- **B — publishers sign client-side; store-server never holds a key.** The full custody unwind. Correct end-state, but spans store-server + SDK + gtdx + onboarding and needs Maarten sign-off.

**Decision: A now, B later.** B is a separate future epic. S3a is custody-agnostic regardless — `mint-cert` signs whatever public key it is given; who holds the corresponding private key is S3b/B's concern, not this tool's.

## Decisions

### D1 — `mint_cert` graduates to `ceremony` as `Result`, and S1's tests do not change

`mint_cert` moves from `cert::fixtures` into the always-compiled `ceremony` module and returns `Result<PublisherCert, TrustError>` — propagating `PublisherCert::signed_bytes()`'s error with `?` instead of `.expect()`, because it is now a production path (the CLI and, later, S3b's tests call it).

The graduation does **not** ripple through S1's ~dozen merged test call sites. `cert::fixtures::mint_cert` stays, as a thin **infallible test-only wrapper** that delegates to the fallible version:

```rust
// cert::fixtures (still #[cfg(any(test, feature = "testing"))])
#[must_use]
pub fn mint_cert(root: &SigningKey, publisher: &VerifyingKey, key_id: &str, not_after: &str) -> PublisherCert {
    crate::ceremony::mint_cert(root, publisher, key_id, not_after)
        .expect("fixture cert body canonicalizes")
}
```

`.expect()` is permitted here because `fixtures` is test-gated. Every existing caller (`chain.rs` ×9, `cert.rs`) keeps calling `fixtures::mint_cert` and keeps getting an infallible `PublisherCert` — untouched.

This is the correction to the earlier assumption (carried since S2) that graduating `mint_cert` forces a `Result` change through S1's tests. It only would if the tests called the graduated version directly; shielding them behind the infallible wrapper avoids all of that churn while giving production the `Result` it needs.

### D2 — the root private seed enters via stdin, never a flag

`mint-cert` is the one subcommand that touches the root private key. A `--root-private <seed>` flag would leak the secret into `ps` output and shell history. So the root seed is read from **stdin**, mirroring `gen-root`'s secret-to-stdout discipline:

```
wrangler secret get GREENTIC_TRUST_ROOT | greentic-trust mint-cert \
  --publisher-key <x-b64url> --key-id pk_acme_1 --not-after 2027-01-01T00:00:00Z \
  > cert.json
```

Root seed on stdin (secret, pipeable). Everything else — the publisher public key, the key id, the expiry — is non-secret and travels as a flag. The `PublisherCert` JSON goes to stdout.

The seed is the raw 32-byte Ed25519 seed, base64 `STANDARD` — exactly what `gen-root` emits, so `gen-root`'s output pipes straight into `mint-cert` in tests and demos.

## Architecture

| Unit | Change |
|---|---|
| `ceremony::mint_cert` (new, from `cert::fixtures`) | `mint_cert(root: &SigningKey, publisher: &VerifyingKey, key_id: &str, not_after: &str) -> Result<PublisherCert, TrustError>`. Always compiled. Propagates `signed_bytes()` via `?`. |
| `cert::fixtures::mint_cert` (kept) | Infallible test-only wrapper delegating to `ceremony::mint_cert(...).expect(...)`. S1 callers unchanged. |
| `src/main.rs` | New `mint-cert` subcommand: seed from stdin, `--publisher-key` / `--key-id` / `--not-after` flags, `PublisherCert` JSON to stdout. |
| `docs/runbooks/root-ceremony.md` | A "mint a publisher cert" section between generate and publish. |

`ceremony::mint_cert` reuses `PublisherCert`'s public surface from S1: the struct fields, `signed_bytes()` (which prepends the `CERT_DOMAIN_V1` domain prefix and JCS-canonicalizes the body), and the `STANDARD` base64 engine. Co-locating minting with verification in one crate is the anti-drift guarantee — the same argument S1 used to re-author `PublisherCert` here and S2 used for `build_document`.

### `mint-cert` handler shape

```rust
// read the root seed from stdin (secret), reconstruct the root SigningKey
// decode --publisher-key (JWK x, base64url, 32 bytes) into a VerifyingKey
// cert = ceremony::mint_cert(&root, &publisher, &key_id, &not_after)?
// println!("{}", serde_json::to_string_pretty(&cert)?)
```

The root seed is base64 `STANDARD`, 32 bytes → `SigningKey::from_bytes`. The publisher key is base64url, 32 bytes → `VerifyingKey::from_bytes` (the `decode_public` helper S2 already added). A malformed seed, a short key, or a bad flag produces a named `CliError` and a non-zero exit — never a panic.

## Testing

Every behaviour that matters has a test, and each carries the mutation that must turn it red.

| Invariant | Test | Mutation that must fail it |
|---|---|---|
| **Anti-drift mint↔verify** | `ceremony::mint_cert(root, pub, id, na)` → `PublisherCert::verify(&[root.verifying_key()], now)` returns `pub` | any drift in the signed bytes (domain prefix, JCS body, field set) → verify returns `CertSignatureInvalid` |
| Graduated fn is fallible, wrapper still infallible | `ceremony::mint_cert` returns `Result`; `fixtures::mint_cert` returns `PublisherCert`; a pre-existing S1 test still compiles and passes unchanged | — (compile-level; S1 suite stays green) |
| CLI end-to-end | `gen-root` → pipe seed into `mint-cert` → the emitted cert `verify`s against the root | key-id or not-after mis-encoded → verify fails |
| Seed via stdin, not a flag | an `assert_cmd` test pipes the seed on **stdin** (no `--root-private` flag anywhere) and `mint-cert` succeeds | change the handler to read the seed from a `--root-private` flag instead of stdin → the stdin-piping test fails, because the piped seed is now ignored and no seed is supplied |
| Bad root seed fails closed | stdin is not base64, or not 32 bytes → non-zero exit, named error | — |
| Expiry is inside the signed bytes | mint a cert, edit its `not_after`, `verify` → `CertSignatureInvalid` | (already guaranteed by S1; this proves the CLI path does not bypass it) |

The anti-drift row is the star, and the reason `mint_cert` lives in this crate: the bytes it signs are the bytes `PublisherCert::verify` checks. If they diverge, the round-trip is red — not a store-server that ships unverifiable certs.

Mutation-check protocol is S1/S2's: stage the file first so `git diff --stat` has a baseline (an untracked file's diff is always empty). Register a module / add a subcommand before writing its failing test, so "watch it fail" sees a real compiler error, not `0 filtered out`.

## What S3b (store-server) will consume — the interface this slice fixes

S3a fixes the cert format S3b depends on, so recording it here:

- A `PublisherCert` is the JSON `{ publisherPublicKey, rootSignature, keyId, notAfter }` (S1's `cert.rs` struct, `#[serde(deny_unknown_fields)]`).
- It is minted offline at publisher onboarding, over the publisher's **public** key (`publisher_keys.public_key`).
- S3b stores it (a new `publisher_keys`-adjacent column or table) and embeds it verbatim into the `signature.certificate` field at publish (schema-safe: `$defs/signature` has no `additionalProperties: false` in v1 or v2).
- Store-server keeps signing the describe with its store-held key (custody model A). The cert vouches for that same `signature.publicKey`; the runner (S4) checks cert.publisherPublicKey == signature.publicKey, cert → root, root ∈ did:web.

None of that is built here. S3a produces the cert; S3b is its own spec.

## Out of scope for S3a

- Store-server storage/embedding of the cert (S3b).
- The custody unwind — publishers signing client-side (model B, a separate epic).
- Runner verification of the embedded cert (S4).
- The production ceremony itself (needs the named owner — still TBD → Maarten — and real root custody).

## What this does not buy

`mint-cert` makes issuing a cert a real, repeatable, verifiable operation. It does not decide who holds the publisher's private key, and under custody model A it does not remove store-server as a signing oracle — it only anchors the keys store-server already holds to a root, so the runner can stop trusting a flat allowlist. Unwinding the custody is model B, later.

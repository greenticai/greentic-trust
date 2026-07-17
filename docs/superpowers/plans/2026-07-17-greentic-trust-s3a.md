# greentic-trust S3a Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Graduate `mint_cert` into the always-compiled `ceremony` module (returning `Result`) and add a `mint-cert` CLI subcommand that mints a root-signed `PublisherCert` from a root seed on stdin and a publisher public key.

**Architecture:** `mint_cert` moves from the test-only `cert::fixtures` into `ceremony` as a production `Result`-returning function; `cert::fixtures` keeps an infallible test-only wrapper delegating to it, so S1's merged tests are untouched. The `mint-cert` subcommand reads the root private seed from stdin (never a flag) and emits the cert to stdout. The star test parses what it mints back through `PublisherCert::verify` — the anti-drift guarantee that mint and verify agree on the signed-bytes format.

**Tech Stack:** Rust 1.95.0, `ed25519-dalek` 2.1, `clap` 4 (`cli` feature), `chrono`, `base64`, `assert_cmd`/`predicates` (binary tests).

**Spec:** `docs/superpowers/specs/2026-07-17-s3a-mint-cert-design.md`

## Global Constraints

- Rust **1.95.0**, pinned via `rust-toolchain.toml`. `#![forbid(unsafe_code)]` (present via lints).
- **No `unwrap()` / `expect()` / `panic!()` in production paths.** Tests and `#[cfg(any(test, feature = "testing"))]` code may. `ceremony::mint_cert` is a production path — it propagates errors with `?`, no `.expect()`. `cert::fixtures::mint_cert` is test-gated and may `.expect()`.
- **No `bool`/`Option` for a security decision.** Every verification result is `Result<T, TrustError>`.
- **`ceremony` is always compiled** — it defines the mint side of the wire format the lib verifies.
- **The library stays free of CLI dependencies.** `clap`/`tokio`/the binary's `rand` live behind the `cli` feature only. `cargo build` (no features) must not pull `clap`.
- **Base64:** the root seed and the cert's `publisherPublicKey`/`rootSignature` are `STANDARD`. JWK `x` (the `--publisher-key` input) is `URL_SAFE_NO_PAD`. Do not swap them.
- **The root seed enters `mint-cert` via stdin, never a flag** (a flag leaks the secret into `ps`/shell history). It is the raw 32-byte Ed25519 seed, base64 STANDARD — exactly `gen-root`'s output.
- **`TrustError` is the complete crate-wide enum. This work adds no new variants.**
- English only. Conventional Commits. **Do NOT add a `Co-Authored-By` trailer** — this repo follows the no-AI-attribution norm (admin/designer/greentic-start). Commit messages end at the body.
- `cargo clippy --all-targets --all-features -- -D warnings` and `cargo fmt --all -- --check` must pass. `bash ci/local_check.sh` is the gate.
- **Build/CI note:** the `/home/bima-pangestu/projects` partition intermittently fills. If cargo fails with `ENOSPC`, export `CARGO_TARGET_DIR=/tmp/claude-1000/-home-bima-pangestu-projects-Works-greentic/fd761df2-293e-4263-8440-a39246ced99d/scratchpad/gt-target-s3` and `CARGO_PROFILE_DEV_DEBUG=line-tables-only` and retry. Do not delete other repos' `target/` dirs.

## Protocols carried from S1/S2 (apply to every task)

- **Register/add before writing the failing test.** A subcommand or function referenced by a test must exist as a declaration before `cargo test` runs, or the test filters to zero and prints `ok` — a check that cannot fail. The failure you must see is a real compiler error.
- **Mutation checks: stage the file first.** `git add <file>` before applying a mutation — `git diff --stat` over an unstaged-identical or untracked file is always empty, so the "must be non-empty" guard passes vacuously. Stage → mutate → confirm diff non-empty → run test → confirm RED → `git checkout <file>` → confirm green. Report real output.

---

### Task 1: Graduate `mint_cert` into `ceremony` (returning `Result`)

**Files:**
- Modify: `src/ceremony.rs` (add `mint_cert`, imports, module-doc note)
- Modify: `src/cert.rs` (turn `fixtures::mint_cert` into a delegating wrapper; trim now-unused imports)

**Interfaces:**
- Consumes: `crate::cert::PublisherCert` (public struct with fields `publisher_public_key`, `root_signature`, `key_id: Option<String>`, `not_after: Option<String>`), `PublisherCert::signed_bytes(&self) -> Result<Vec<u8>, TrustError>`, `PublisherCert::verify(&self, roots: &[VerifyingKey], now: chrono::DateTime<Utc>) -> Result<VerifyingKey, TrustError>`, `ed25519_dalek::{SigningKey, VerifyingKey, Signer}`.
- Produces: `greentic_trust::ceremony::mint_cert(root: &SigningKey, publisher: &VerifyingKey, key_id: &str, not_after: &str) -> Result<PublisherCert, TrustError>`.

- [ ] **Step 1: Write the failing star test**

Add to the `#[cfg(test)] mod tests` in `src/ceremony.rs` (it already imports `super::*`, `DidWeb`, `TrustDocument`, base64 engines, `StdRng`/`SeedableRng`, and has `seeded_root(seed: u8)`):

```rust
    fn at(rfc3339: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(rfc3339)
            .expect("valid timestamp")
            .with_timezone(&chrono::Utc)
    }

    #[test]
    fn minted_cert_verifies_against_the_root() {
        // The anti-drift guarantee for the cert path: mint_cert signs the exact
        // bytes PublisherCert::verify reconstructs. If they diverge, this is red.
        let root = seeded_root(5);
        let publisher = seeded_root(6);
        let cert = mint_cert(&root, &publisher.verifying_key(), "pk_test_1", "2030-01-01T00:00:00Z")
            .expect("mints");

        let recovered = cert
            .verify(&[root.verifying_key()], at("2026-07-17T00:00:00Z"))
            .expect("verifies against the root");
        assert_eq!(recovered.as_bytes(), publisher.verifying_key().as_bytes());
    }

    #[test]
    fn minted_cert_rejected_by_a_different_root() {
        let root = seeded_root(7);
        let other = seeded_root(8);
        let publisher = seeded_root(9);
        let cert = mint_cert(&root, &publisher.verifying_key(), "pk_test_1", "2030-01-01T00:00:00Z")
            .expect("mints");

        let error = cert
            .verify(&[other.verifying_key()], at("2026-07-17T00:00:00Z"))
            .expect_err("a cert signed by root must not verify against a different root");
        assert!(matches!(error, TrustError::CertSignatureInvalid));
    }
```

`TrustError` is already in scope in the test module via `use super::*;` (the module imports `crate::error::TrustError`), so reference it unqualified — NOT `greentic_trust::TrustError`, which does not resolve inside the crate. `mint_cert` and `at` likewise come into scope through `use super::*;` once they exist.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --lib ceremony::tests::minted_cert 2>&1 | tail -5`
Expected: FAIL — `cannot find function mint_cert in this scope`. A real compiler error, not `0 filtered out`.

- [ ] **Step 3: Add `mint_cert` to `ceremony`**

In `src/ceremony.rs`, extend the imports (currently `use base64::engine::general_purpose::URL_SAFE_NO_PAD;`, `use base64::Engine as _;`, `use ed25519_dalek::{SigningKey, VerifyingKey};`, `use serde_json::json;`, `use crate::did::DidWeb;`, `use crate::error::TrustError;`) to add:

```rust
use base64::engine::general_purpose::STANDARD as B64;
```
and change the ed25519 import to include `Signer`:
```rust
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
```
and add:
```rust
use crate::cert::PublisherCert;
```

Then add the function (after `build_document`):

```rust
/// Mint a `PublisherCert`: the root signs its attestation over the publisher's
/// key, bound to a key id and an expiry.
///
/// This is the *mint* side of the format [`PublisherCert::verify`] checks — it
/// signs exactly [`PublisherCert::signed_bytes`], which prepends the
/// domain-separation prefix and JCS-canonicalizes the body. Co-locating mint and
/// verify in one crate is what keeps them from drifting.
///
/// # Errors
/// [`TrustError`] if the cert body cannot be canonicalized (`signed_bytes`).
pub fn mint_cert(
    root: &SigningKey,
    publisher: &VerifyingKey,
    key_id: &str,
    not_after: &str,
) -> Result<PublisherCert, TrustError> {
    let mut cert = PublisherCert {
        publisher_public_key: B64.encode(publisher.as_bytes()),
        root_signature: String::new(),
        key_id: Some(key_id.to_owned()),
        not_after: Some(not_after.to_owned()),
    };
    let signed = cert.signed_bytes()?;
    cert.root_signature = B64.encode(root.sign(&signed).to_bytes());
    Ok(cert)
}
```

Also update the module doc at the top of `src/ceremony.rs`: the S2-era note says `mint_cert` has NOT graduated. Replace that paragraph with:

```rust
//! `mint_cert` (the cert *mint*), `generate_root`, and `build_document` all
//! live here as the always-compiled mint side of the wire format the rest of
//! the crate verifies.
```

- [ ] **Step 4: Turn `fixtures::mint_cert` into a delegating wrapper**

In `src/cert.rs`, the `#[cfg(any(test, feature = "testing"))] pub mod fixtures` currently defines `mint_cert` by hand with `.expect()`. Replace the whole `mint_cert` fn body so it delegates to the graduated version:

```rust
    /// Mint a cert the way the ceremony and S3's issuer do. Test-only wrapper —
    /// the real, fallible implementation is `crate::ceremony::mint_cert`.
    #[must_use]
    pub fn mint_cert(
        root: &SigningKey,
        publisher: &VerifyingKey,
        key_id: &str,
        not_after: &str,
    ) -> PublisherCert {
        crate::ceremony::mint_cert(root, publisher, key_id, not_after)
            .expect("fixture cert body canonicalizes")
    }
```

The `fixtures` module's imports were `use super::{PublisherCert, B64}; use base64::Engine as _; use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};`. After delegation `mint_cert` no longer uses `B64`, `base64::Engine`, or `Signer` directly (only the signature types and the return type). Trim to what remains used:

```rust
    use super::PublisherCert;
    use ed25519_dalek::{SigningKey, VerifyingKey};
```

(Keep `root_keypair`, which uses `SigningKey`. If clippy reports any of these still unused, remove it; if it reports one is needed, keep it — let `-D warnings` be the arbiter, and report what you kept.)

- [ ] **Step 5: Run the tests to verify they pass, including the untouched S1 suite**

Run: `cargo test --lib --all-features 2>&1 | tail -5`
Expected: PASS — the two new `ceremony` tests plus every pre-existing test. The S1 `chain.rs`/`cert.rs` tests call `fixtures::mint_cert` (still infallible) and must be green without any edit to them. Confirm the total count went up by exactly 2 from S2's 60.

- [ ] **Step 6: Mutation check — the star test discriminates a signed-bytes drift**

Follow the staging protocol. Mutation: in `ceremony::mint_cert`, sign the raw publisher key instead of the canonical signed bytes (this is the pre-S1 broken scheme — `keyId`/`notAfter` unsigned):

```rust
    let signed = publisher.as_bytes().to_vec();   // was: cert.signed_bytes()?
```

```bash
git add src/ceremony.rs src/cert.rs
# apply the mutation
git diff --stat            # MUST be non-empty
cargo test --lib ceremony::tests::minted_cert
git checkout src/ceremony.rs src/cert.rs
cargo test --lib ceremony::tests::minted_cert
```

Expected: `minted_cert_verifies_against_the_root` FAILS under the mutation (verify reconstructs `signed_bytes` with the domain prefix, which the mutated signature does not cover → `CertSignatureInvalid`), and passes after restore.

- [ ] **Step 7: Lints**

Run: `cargo fmt --all -- --check && cargo clippy --lib --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 8: Commit**

```bash
git add src/ceremony.rs src/cert.rs
git commit -m "feat: graduate mint_cert into the ceremony module as a Result"
```

---

### Task 2: `mint-cert` CLI subcommand

**Files:**
- Modify: `src/main.rs` (new `Command::MintCert`, `run_mint_cert`, generalize `decode_public`, a seed decoder)
- Modify: `tests/cli.rs` (end-to-end mint→verify, stdin-not-flag, bad-seed)

**Interfaces:**
- Consumes: `greentic_trust::ceremony::mint_cert`, `greentic_trust::PublisherCert` (re-exported at the crate root), `ed25519_dalek::SigningKey`.
- Produces: the `mint-cert` subcommand on the binary.

- [ ] **Step 1: Add the subcommand variant (so the failing test compiles against a real command)**

In `src/main.rs`, add to the `Command` enum (after `VerifyDoc`):

```rust
    /// Mint a publisher certificate. The root private seed is read from stdin
    /// (base64, the raw 32-byte Ed25519 seed — exactly `gen-root`'s output).
    MintCert {
        /// The publisher public key to certify (JWK x, base64url).
        #[arg(long)]
        publisher_key: String,
        /// A stable identifier for the publisher key this cert vouches for.
        #[arg(long)]
        key_id: String,
        /// RFC3339 expiry, e.g. 2027-01-01T00:00:00Z.
        #[arg(long)]
        not_after: String,
    },
```

Add its dispatch arm in `run()`:

```rust
        Command::MintCert {
            publisher_key,
            key_id,
            not_after,
        } => run_mint_cert(&publisher_key, &key_id, &not_after),
```

- [ ] **Step 2: Write the failing tests**

Append to `tests/cli.rs` (which already has `bin()`, `fresh_root()` returning `(private_b64, x_b64url)`, and imports `STANDARD`/`URL_SAFE_NO_PAD`/`ed25519_dalek`):

```rust
#[test]
fn mint_cert_reads_seed_from_stdin_and_emits_a_cert_that_verifies() {
    use chrono::Utc;
    use greentic_trust::PublisherCert;

    let (root_seed, root_x) = fresh_root();
    let (_pub_seed, pub_x) = fresh_root();

    let output = bin()
        .args([
            "mint-cert",
            "--publisher-key",
            &pub_x,
            "--key-id",
            "pk_test_1",
            "--not-after",
            "2030-01-01T00:00:00Z",
        ])
        .write_stdin(root_seed)
        .assert()
        .success()
        .get_output()
        .clone();

    let cert: PublisherCert =
        serde_json::from_slice(&output.stdout).expect("stdout is a PublisherCert");

    // Reconstruct the root verifying key from gen-root's public x (base64url).
    let root_bytes: [u8; 32] = URL_SAFE_NO_PAD.decode(&root_x).unwrap().try_into().unwrap();
    let root_pub = ed25519_dalek::VerifyingKey::from_bytes(&root_bytes).unwrap();

    let now = chrono::DateTime::parse_from_rfc3339("2026-07-17T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let certified = cert.verify(&[root_pub], now).expect("cert verifies against the root");

    let pub_bytes: [u8; 32] = URL_SAFE_NO_PAD.decode(&pub_x).unwrap().try_into().unwrap();
    assert_eq!(certified.as_bytes(), &pub_bytes);
}

#[test]
fn mint_cert_rejects_a_non_base64_seed_on_stdin() {
    let (_seed, pub_x) = fresh_root();
    bin()
        .args([
            "mint-cert",
            "--publisher-key",
            &pub_x,
            "--key-id",
            "pk_test_1",
            "--not-after",
            "2030-01-01T00:00:00Z",
        ])
        .write_stdin("not base64 !!!")
        .assert()
        .failure();
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test --features cli --test cli mint_cert 2>&1 | tail -6`
Expected: FAIL — `run_mint_cert` is not defined / no such function.

- [ ] **Step 4: Generalize `decode_public` with a label, and implement `run_mint_cert`**

In `src/main.rs`, change `decode_public` to take a label so its error names the right key:

```rust
/// Decode a JWK `x` (base64url, 32 bytes) into a verifying key. `label` names
/// the key in error messages ("root public key", "publisher key", ...).
fn decode_public(x: &str, label: &str) -> Result<ed25519_dalek::VerifyingKey, CliError> {
    let raw = URL_SAFE_NO_PAD
        .decode(x.trim())
        .map_err(|e| CliError::Decode(format!("{label} is not base64url: {e}")))?;
    let bytes: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
        CliError::Decode(format!("{label} is {} bytes, expected 32", raw.len()))
    })?;
    ed25519_dalek::VerifyingKey::from_bytes(&bytes)
        .map_err(|e| CliError::Decode(format!("{label} is not a valid Ed25519 key: {e}")))
}
```

Update the two existing callers:
- in `run_build_doc`: `.map(|x| decode_public(x))` → `.map(|x| decode_public(x, "root public key"))`
- in `run_verify_doc`: `let expected = decode_public(expected_root)?;` → `let expected = decode_public(expected_root, "expected root key")?;`

Add a seed decoder and the handler (after `run_verify_doc`):

```rust
/// Read the root private seed from stdin and reconstruct the signing key. The
/// seed is the raw 32-byte Ed25519 seed, base64 STANDARD — `gen-root`'s output.
/// Reading from stdin (not a flag) keeps the secret out of `ps`/shell history.
fn read_root_seed() -> Result<ed25519_dalek::SigningKey, CliError> {
    use std::io::Read as _;
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf)?;
    let raw = STANDARD
        .decode(buf.trim())
        .map_err(|e| CliError::Decode(format!("root seed on stdin is not base64: {e}")))?;
    let bytes: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| CliError::Decode(format!("root seed is {} bytes, expected 32", raw.len())))?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&bytes))
}

fn run_mint_cert(publisher_key: &str, key_id: &str, not_after: &str) -> Result<(), CliError> {
    let root = read_root_seed()?;
    let publisher = decode_public(publisher_key, "publisher key")?;
    let cert = greentic_trust::ceremony::mint_cert(&root, &publisher, key_id, not_after)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&cert).map_err(|e| CliError::Decode(e.to_string()))?
    );
    Ok(())
}
```

Add `PublisherCert` to the crate-root import if `run_mint_cert` needs it (it does not — it uses `ceremony::mint_cert` which returns the cert; only the *test* needs `PublisherCert`, and the test imports it locally). No new import in `main.rs` beyond what is already there (`STANDARD`, `URL_SAFE_NO_PAD`, `ed25519_dalek`).

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --features cli --test cli 2>&1 | tail -6`
Expected: PASS — all cli tests, including the two new `mint_cert` ones.

- [ ] **Step 6: Mutation check — the seed really comes from stdin**

Follow the staging protocol. Mutation: make `run_mint_cert` ignore stdin and use a throwaway generated key instead of reading the seed:

```rust
    let root = greentic_trust::ceremony::generate_root(&mut rand::rngs::OsRng);  // was: read_root_seed()?
```

```bash
git add src/main.rs
# apply the mutation
git diff --stat            # MUST be non-empty
cargo test --features cli --test cli mint_cert
git checkout src/main.rs
cargo test --features cli --test cli mint_cert
```

Expected: `mint_cert_reads_seed_from_stdin_and_emits_a_cert_that_verifies` FAILS under the mutation (the cert is signed by a random key, not the root from stdin, so `cert.verify(&[root_pub], …)` returns `CertSignatureInvalid`), and passes after restore. This pins that the seed on stdin is what signs.

- [ ] **Step 7: Full gate + clap-free lib still holds**

Run:
```bash
cargo tree --no-default-features -e normal | grep -qi '^clap\| clap ' && echo "FAIL: clap in lib" || echo "OK: lib clap-free"
bash ci/local_check.sh
```
Expected: `OK: lib clap-free` and `All checks passed.`

- [ ] **Step 8: Commit**

```bash
git add src/main.rs tests/cli.rs
git commit -m "feat: add the mint-cert subcommand (root seed via stdin)"
```

---

### Task 3: Runbook — minting a publisher cert

**Files:**
- Modify: `docs/runbooks/root-ceremony.md`

**Interfaces:** none — documentation.

- [ ] **Step 1: Add the mint-cert section**

In `docs/runbooks/root-ceremony.md`, add a section after "## 1. Generate a root" (and before the build/publish sections), so the ceremony order reads generate-root → mint-publisher-cert → build/publish-doc:

```markdown
## 1b. Mint a publisher certificate

A publisher certificate lets the runner verify that a publisher's signing key is
vouched for by the Greentic root — replacing the flat trusted-signer allowlist.
Mint one at publisher onboarding (and at key rotation), offline, over the
publisher's **public** key:

    wrangler secret get GREENTIC_TRUST_ROOT_RESEARCH | greentic-trust mint-cert \
      --publisher-key <publisher-x-base64url> \
      --key-id pk_acme_1 \
      --not-after 2027-01-01T00:00:00Z \
      > acme.cert.json

The root private seed is read from **stdin**, never a flag, so it stays out of
`ps` output and shell history. Everything else — the publisher's public key, the
key id, the expiry — is non-secret. The `PublisherCert` JSON on stdout is what
store-server stores against the publisher and embeds into `describe.json` at
publish (S3b).

Certs are minted at onboarding/rotation, not per publish, so the root only comes
out for this step and step 1 — never for a routine publish. Pick a `--not-after`
that matches your rotation cadence; an expired cert is refused, so re-mint before
it lapses.
```

- [ ] **Step 2: Verify the doc and the command shape**

Run:
```bash
grep -q "mint-cert" docs/runbooks/root-ceremony.md && echo "runbook has mint-cert"
grep -q "read from \*\*stdin\*\*\|from \*\*stdin\*\*" docs/runbooks/root-ceremony.md && echo "stdin note present"
bash ci/local_check.sh 2>&1 | tail -1
```
Expected: both present, `All checks passed.`

- [ ] **Step 3: Commit**

```bash
git add docs/runbooks/root-ceremony.md
git commit -m "docs: runbook section for minting a publisher cert"
```

---

## Self-Review Notes

**Spec coverage:**

| Spec requirement | Task |
|---|---|
| `mint_cert` graduates to `ceremony`, returns `Result`, propagates via `?` | 1 |
| `fixtures::mint_cert` stays as an infallible test-only wrapper; S1 tests untouched | 1 (step 4, verified step 5) |
| Anti-drift mint↔verify round-trip (the star) | 1 (step 1 test + step 6 mutation) |
| `mint-cert` subcommand: seed via stdin, `--publisher-key`/`--key-id`/`--not-after` flags, cert JSON to stdout | 2 |
| Seed via stdin not a flag, mutation-pinned | 2 (step 2 test + step 6 mutation) |
| Bad root seed fails closed | 2 (`mint_cert_rejects_a_non_base64_seed_on_stdin`) |
| Base64: seed + cert fields STANDARD, publisher `x` URL_SAFE_NO_PAD | 1 (`B64`), 2 (`read_root_seed` STANDARD, `decode_public` URL_SAFE_NO_PAD) |
| Lib stays clap-free | 2 (step 7) |
| No new `TrustError` variants | all |
| Runbook mint-cert section | 3 |

**Deferred / out of scope (recorded):** store-server storing + embedding the cert (S3b, greentic-biz repo); runner verification of the embedded cert (S4); custody model B (publishers signing client-side — a separate epic); the production ceremony itself (needs the named owner, TBD → Maarten).

**Refinement from reading the code:** graduating `mint_cert` does not churn S1's ~dozen test call sites — `cert::fixtures::mint_cert` stays as an infallible wrapper delegating to the fallible `ceremony::mint_cert`, so every existing caller keeps compiling unchanged (corrects the assumption carried since S2 that the graduation forces a `Result` change through S1's tests).

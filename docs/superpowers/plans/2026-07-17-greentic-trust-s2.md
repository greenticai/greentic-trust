# greentic-trust S2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the ceremony tooling to `greentic-trust` — a `cli`-feature-gated binary that generates a root key, builds the `did.json` document S1's verifier accepts, and verifies a published document — plus the ceremony runbook.

**Architecture:** A new always-compiled `ceremony` module holds `generate_root` and `build_document` as pure functions (no I/O), so the document bytes the tool emits are parsed by the same `TrustDocument` the runner uses at runtime — the anti-drift guarantee. A `cli`-feature-gated `[[bin]]` is the only place `clap` and process I/O live; the library keeps zero CLI dependencies.

**Tech Stack:** Rust 1.95.0, `ed25519-dalek` 2.1, `rand_core` 0.6 (RNG trait bound), `clap` 4 (optional, `cli` feature), `serde_json`, `base64`, `assert_cmd` + `predicates` (binary integration tests).

**Spec:** `docs/superpowers/specs/2026-07-17-s2-root-provisioning-design.md`

## Global Constraints

- Rust **1.95.0**, pinned via `rust-toolchain.toml` (already present). Do not edit.
- `#![forbid(unsafe_code)]` at the crate root (already present via `[lints.rust]`).
- **No `unwrap()` / `expect()` / `panic!()` in production paths.** Tests may use them. `unwrap_or` / `unwrap_or_default` are total and permitted.
- **No `bool` return and no `Option` for any security decision.** Every verification result is `Result<T, TrustError>`.
- **The library stays free of CLI dependencies.** `clap`, `tokio`, and the binary's `rand` usage live behind the `cli` feature only. `cargo build` (no features) must not pull `clap` into the graph.
- **`ceremony` is always compiled, not test-gated.** It defines the mint side of the same wire format the lib verifies; co-locating build and parse in one crate is the anti-drift guarantee.
- **Base64 discipline (interop-critical, do not swap):** JWK `x` members are `URL_SAFE_NO_PAD` (RFC 7515/8037). The root private-key seed is `STANDARD`. These agree on most bytes and diverge on a few; a swap breaks interop silently.
- **The root private key is the raw 32-byte Ed25519 seed**, base64 `STANDARD` — the encoding `SigningKey::from_bytes(&[u8; 32])` reconstructs. The tool never encrypts it; sealing is the secret manager's job.
- **`gen-root`: private key to stdout only, human-readable to stderr.** No filesystem writes, no network.
- **`TrustError` is the complete crate-wide enum from S1. This work adds no new variants.**
- English only in source, tests, comments, commit messages. Conventional Commits. `Cargo.lock` committed.
- `cargo clippy --all-targets --all-features -- -D warnings` must pass. `cargo fmt --all -- --check` must pass.
- **Build/CI note:** the `/home/bima-pangestu/projects` partition intermittently fills from other activity. If cargo fails with `ENOSPC`, export `CARGO_TARGET_DIR=/tmp/claude-1000/-home-bima-pangestu-projects-Works-greentic/fd761df2-293e-4263-8440-a39246ced99d/scratchpad/gt-target` and `CARGO_PROFILE_DEV_DEBUG=line-tables-only` and retry. Do not delete other repos' `target/` dirs.

## Protocols carried from S1 (apply to every task)

- **Register the module before writing its tests.** Add `pub mod ceremony;` to `src/lib.rs` as the first action, before the test module compiles — otherwise `cargo test --lib ceremony` filters to zero tests and prints `ok`, a check that cannot fail.
- **Mutation checks: stage the file first.** `git add <file>` before applying a mutation, because `git diff --stat` over an unstaged-identical or untracked file is always empty and the "must be non-empty" guard passes vacuously. Stage → mutate → confirm diff non-empty → run test → confirm RED → `git checkout <file>` → confirm green. Report real output.

---

### Task 1: `ceremony` module — `generate_root` and `build_document`

**Files:**
- Modify: `Cargo.toml` (add `rand_core` dep)
- Modify: `src/lib.rs` (declare + re-export `ceremony`)
- Create: `src/ceremony.rs`
- Modify: `src/cert.rs` (rewire `fixtures::root_keypair` to delegate to `ceremony::generate_root`)

**Interfaces:**
- Consumes: `crate::did::DidWeb` (`as_str`), `crate::error::TrustError`, `ed25519_dalek::{SigningKey, VerifyingKey}`.
- Produces:
  - `greentic_trust::ceremony::generate_root<R: rand_core::CryptoRngCore + ?Sized>(rng: &mut R) -> SigningKey`
  - `greentic_trust::ceremony::build_document(did: &DidWeb, roots: &[VerifyingKey]) -> Result<serde_json::Value, TrustError>`

- [ ] **Step 1: Add the `rand_core` dependency**

`rand_core` is already in the lock transitively via `ed25519-dalek`; adding it as a direct non-optional dep costs nothing and gives `generate_root` a stable trait bound without forcing `rand` on lib consumers.

In `Cargo.toml`, under `[dependencies]`, add after the `moka` line:

```toml
rand_core = "0.6"
```

- [ ] **Step 2: Declare the module (before any test — see protocols)**

In `src/lib.rs`, add `pub mod ceremony;` immediately after `pub mod cert;` (line 9), keeping alphabetical-ish grouping. Do NOT add a `pub use` yet — the round-trip test refers to `ceremony::build_document` by path, and consumers can use the full path.

- [ ] **Step 3: Write the failing tests**

Create `src/ceremony.rs` containing only this test module for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::did::DidWeb;
    use crate::document::TrustDocument;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use base64::Engine as _;
    use rand::rngs::StdRng;
    use rand::SeedableRng as _;

    const DID: &str = "did:web:trust.research.greentic.cloud";

    fn seeded_root(seed: u8) -> ed25519_dalek::SigningKey {
        let mut rng = StdRng::from_seed([seed; 32]);
        generate_root(&mut rng)
    }

    #[test]
    fn built_document_round_trips_through_the_verifier() {
        // The anti-drift guarantee: the bytes build_document emits are parsed by
        // the same TrustDocument the runner uses at runtime. If they diverge,
        // this test is red — not production.
        let root = seeded_root(1);
        let did = DidWeb::parse(DID).expect("parses");

        let doc = build_document(&did, &[root.verifying_key()]).expect("builds");
        let bytes = serde_json::to_vec(&doc).expect("serializes");
        let parsed = TrustDocument::parse(&did, &bytes).expect("verifier accepts it");

        assert_eq!(parsed.assertion_keys().len(), 1);
        assert_eq!(
            parsed.assertion_keys()[0].as_bytes(),
            root.verifying_key().as_bytes()
        );
    }

    #[test]
    fn built_document_id_equals_the_did() {
        let root = seeded_root(2);
        let did = DidWeb::parse(DID).expect("parses");
        let doc = build_document(&did, &[root.verifying_key()]).expect("builds");
        assert_eq!(doc["id"], serde_json::json!(DID));
    }

    #[test]
    fn multi_key_document_carries_every_root() {
        // Used only during a root-rotation overlap: old + new root both valid.
        let a = seeded_root(3);
        let b = seeded_root(4);
        let did = DidWeb::parse(DID).expect("parses");

        let doc = build_document(&did, &[a.verifying_key(), b.verifying_key()]).expect("builds");
        let bytes = serde_json::to_vec(&doc).expect("serializes");
        let parsed = TrustDocument::parse(&did, &bytes).expect("verifier accepts it");

        assert_eq!(parsed.assertion_keys().len(), 2);
        let keys: Vec<_> = parsed.assertion_keys().iter().map(|k| *k.as_bytes()).collect();
        assert!(keys.contains(&a.verifying_key().to_bytes()));
        assert!(keys.contains(&b.verifying_key().to_bytes()));
    }

    #[test]
    fn jwk_x_is_base64url_not_standard() {
        // Interop discipline: JWK x is URL_SAFE_NO_PAD. Pick a key whose two
        // encodings actually differ, so a STANDARD mutation is caught rather
        // than silently agreeing. Search seeds until the encodings diverge.
        let (root, x_url) = (0u8..=255)
            .find_map(|s| {
                let root = seeded_root(s);
                let bytes = root.verifying_key().to_bytes();
                let url = URL_SAFE_NO_PAD.encode(bytes);
                let std = STANDARD.encode(bytes);
                (url != std).then_some((root, url))
            })
            .expect("some key encodes differently under the two alphabets");
        let did = DidWeb::parse(DID).expect("parses");

        let doc = build_document(&did, &[root.verifying_key()]).expect("builds");
        assert_eq!(doc["verificationMethod"][0]["publicKeyJwk"]["x"], serde_json::json!(x_url));
    }

    #[test]
    fn empty_roots_is_rejected() {
        let did = DidWeb::parse(DID).expect("parses");
        let error = build_document(&did, &[]).expect_err("rejects");
        assert!(matches!(error, TrustError::DocumentInvalid { .. }));
    }

    #[test]
    fn generate_root_is_deterministic_for_a_fixed_seed() {
        // Same seed -> same key; different seed -> different key. Asserting an
        // exact hardcoded x would be fragile against StdRng algorithm changes.
        assert_eq!(seeded_root(9).to_bytes(), seeded_root(9).to_bytes());
        assert_ne!(seeded_root(9).to_bytes(), seeded_root(10).to_bytes());
    }
}
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `cargo test --lib ceremony`
Expected: FAIL — `cannot find function build_document` / `generate_root`. Confirm a non-zero test count is attempted, not `0 filtered out`.

- [ ] **Step 5: Implement `ceremony`**

Prepend to `src/ceremony.rs`, above the test module:

```rust
//! Ceremony operations: generate a root key and build the did.json document.
//!
//! Always compiled, because these define the *mint* side of the same wire
//! format the rest of the crate verifies. `build_document` produces exactly the
//! bytes [`crate::document::TrustDocument::parse`] accepts, and a round-trip
//! test pins that — co-locating build and parse in one crate is what keeps them
//! from drifting.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde_json::json;

use crate::did::DidWeb;
use crate::error::TrustError;

/// Generate a root signing key from a caller-supplied RNG.
///
/// The binary passes `OsRng`; tests pass a seeded RNG for determinism. Taking
/// the RNG as a parameter keeps this function free of the `rand` crate, so the
/// library's consumers never pull it in.
#[must_use]
pub fn generate_root<R: rand_core::CryptoRngCore + ?Sized>(rng: &mut R) -> SigningKey {
    SigningKey::generate(rng)
}

/// Build the `did.json` document for `did`, carrying one or more root keys.
///
/// More than one key appears only during a root-rotation overlap, so an old and
/// a new root are both valid while the TTL drains. Each key becomes one
/// `verificationMethod` with id `{did}#root-{n}` (n from 1) and one
/// `assertionMethod` reference — the two members the verifier reads — with a JWK
/// of `kty=OKP, crv=Ed25519, x=URL_SAFE_NO_PAD(pubkey)`.
///
/// # Errors
/// [`TrustError::DocumentInvalid`] if `roots` is empty.
pub fn build_document(did: &DidWeb, roots: &[VerifyingKey]) -> Result<serde_json::Value, TrustError> {
    if roots.is_empty() {
        return Err(TrustError::DocumentInvalid {
            reason: "build_document requires at least one root key".to_owned(),
        });
    }

    let id = did.as_str();
    let mut methods = Vec::with_capacity(roots.len());
    let mut assertions = Vec::with_capacity(roots.len());

    for (index, root) in roots.iter().enumerate() {
        let kid = format!("{id}#root-{}", index + 1);
        methods.push(json!({
            "id": kid,
            "type": "JsonWebKey2020",
            "controller": id,
            "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": URL_SAFE_NO_PAD.encode(root.as_bytes()),
                "use": "sig",
            },
        }));
        assertions.push(json!(kid));
    }

    Ok(json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
        ],
        "id": id,
        "verificationMethod": methods,
        "assertionMethod": assertions,
        "authentication": assertions,
    }))
}
```

- [ ] **Step 6: Rewire `fixtures::root_keypair` to delegate**

`src/cert.rs`'s `fixtures::root_keypair` currently calls `SigningKey::generate(&mut rand::rngs::OsRng)` directly. Point it at `ceremony::generate_root` so there is one keygen definition. This keeps `mint_cert` where it is (it graduates in S3, not now — moving it would force a `Result` signature change through S1's merged tests for no S2 benefit).

In `src/cert.rs`, replace the body of `root_keypair` (inside `pub mod fixtures`):

```rust
    /// Generate a root keypair for tests.
    #[must_use]
    pub fn root_keypair() -> SigningKey {
        crate::ceremony::generate_root(&mut rand::rngs::OsRng)
    }
```

Leave `mint_cert` and the module's other contents untouched. The `use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};` at the top of `fixtures` stays (mint_cert still needs `Signer`, `SigningKey`, `VerifyingKey`).

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cargo test --lib --features testing 2>&1 | tail -5`
Expected: PASS — the 6 new `ceremony` tests plus all pre-existing lib tests. `--features testing` keeps `fixtures` (and its `root_keypair`) compiled.

- [ ] **Step 8: Mutation check — the anti-drift round-trip actually discriminates**

Follow the staging protocol. Mutation: in `build_document`, change the `x` encoder from `URL_SAFE_NO_PAD` to `base64::engine::general_purpose::STANDARD` (add the import).

```bash
git add src/ceremony.rs src/cert.rs Cargo.toml src/lib.rs
# apply the mutation
git diff --stat            # MUST be non-empty
cargo test --lib ceremony
git checkout src/ceremony.rs
cargo test --lib ceremony
```

Expected: `jwk_x_is_base64url_not_standard` FAILS under the mutation (and `built_document_round_trips_through_the_verifier` fails for the chosen key too), and both pass after restore.

- [ ] **Step 9: Mutation check — the binding is real**

Mutation: in `build_document`, replace `"id": id,` (the top-level document id) with `"id": "did:web:evil.example",`.

```bash
git add src/ceremony.rs
# apply the mutation
git diff --stat            # MUST be non-empty
cargo test --lib ceremony
git checkout src/ceremony.rs
cargo test --lib ceremony
```

Expected: `built_document_round_trips_through_the_verifier` and `built_document_id_equals_the_did` FAIL under the mutation (the verifier's binding check rejects a document whose id ≠ the resolved DID), and pass after restore.

- [ ] **Step 10: Verify lints are clean**

Run: `cargo fmt --all -- --check && cargo clippy --lib --all-features -- -D warnings`
Expected: no findings. (The clap-free-lib assertion belongs in Task 2, once `clap` actually exists as an optional dep — asserting it here, before Task 2 adds `clap`, would pass vacuously and prove nothing.)

- [ ] **Step 11: Commit**

```bash
git add Cargo.toml Cargo.lock src/lib.rs src/ceremony.rs src/cert.rs
git commit -m "feat: add ceremony module with generate_root and build_document"
```

---

### Task 2: `cli` feature, binary skeleton, and `gen-root`

**Files:**
- Modify: `Cargo.toml` (`cli` feature, optional `clap`/`tokio`/`rand`, `[[bin]]`, `assert_cmd`/`predicates` dev-deps)
- Create: `src/main.rs`
- Create: `tests/cli.rs`

**Interfaces:**
- Consumes: `greentic_trust::ceremony::generate_root`.
- Produces: the `greentic-trust` binary with a `gen-root` subcommand. Later tasks add `build-doc` and `verify-doc` to the same `Command` enum.

- [ ] **Step 1: Add the `cli` feature, optional deps, bin, and test deps**

In `Cargo.toml`:

Under `[features]`, add:
```toml
cli = ["dep:clap", "dep:tokio", "dep:rand"]
```

Under `[dependencies]`, add:
```toml
clap = { version = "4", features = ["derive"], optional = true }
tokio = { version = "1", features = ["rt-multi-thread"], optional = true }
```

`Runtime::new()` (used by `verify-doc`'s network path) requires `rt-multi-thread`. The IO and timer drivers reqwest needs are already compiled in — `reqwest` (a non-optional lib dependency) pulls `tokio` with `net`+`time`, and Cargo unifies features across the graph.
(Change the existing `rand` line — currently `rand = { version = "0.8", optional = true }` — leave it; it is already optional and is now enabled by both `testing` and `cli`.)

Under `[dev-dependencies]`, add:
```toml
assert_cmd = "2"
predicates = "3"
```

After the `[dependencies]` block (or anywhere top-level), add the bin target:
```toml
[[bin]]
name = "greentic-trust"
path = "src/main.rs"
required-features = ["cli"]
```

- [ ] **Step 2: Write the failing integration test**

Create `tests/cli.rs`:

```rust
//! Integration tests for the `greentic-trust` binary. Compiled only with the
//! `cli` feature (the binary does not exist otherwise).
#![cfg(feature = "cli")]

use assert_cmd::Command;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;

fn bin() -> Command {
    Command::cargo_bin("greentic-trust").expect("binary builds")
}

#[test]
fn gen_root_prints_a_valid_private_seed_to_stdout() {
    let output = bin().arg("gen-root").assert().success().get_output().clone();

    let stdout = String::from_utf8(output.stdout).expect("utf8");
    let seed = STANDARD
        .decode(stdout.trim())
        .expect("stdout is standard base64");
    assert_eq!(seed.len(), 32, "private key is a 32-byte Ed25519 seed");
}

#[test]
fn gen_root_puts_the_public_key_and_warning_on_stderr_not_stdout() {
    let output = bin().arg("gen-root").assert().success().get_output().clone();

    let stdout = String::from_utf8(output.stdout).expect("utf8");
    let stderr = String::from_utf8(output.stderr).expect("utf8");

    // The public JWK x is on stderr and decodes to 32 bytes.
    assert!(stderr.contains("base64url"), "stderr names the public key");
    assert!(stderr.to_lowercase().contains("warning"), "stderr warns about the private key");

    // The private seed (stdout) must not appear on stderr.
    let private = stdout.trim();
    assert!(!stderr.contains(private), "private key must not leak to stderr");

    // And the stderr x must NOT be parseable as the private seed (they differ).
    let seed = STANDARD.decode(private).expect("base64");
    let pub_x = URL_SAFE_NO_PAD.encode(
        ed25519_dalek::SigningKey::from_bytes(&seed.try_into().unwrap())
            .verifying_key()
            .to_bytes(),
    );
    assert!(stderr.contains(&pub_x), "stderr carries the public key derived from the private seed");
}
```

Add `ed25519-dalek` and `base64` are already deps; for the test they resolve via the crate's dependency graph (dev context sees normal deps).

- [ ] **Step 3: Run the test to verify it fails**

Run: `cargo test --features cli --test cli 2>&1 | tail -5`
Expected: FAIL — no `gen-root` subcommand yet (clap errors), or the binary has no such command.

- [ ] **Step 4: Implement `src/main.rs` with `gen-root`**

Create `src/main.rs`:

```rust
//! `greentic-trust` ceremony CLI. Generates a root key, builds the did.json
//! document the verifier accepts, and verifies a published document.
//!
//! Compiled only with `--features cli`; the library carries no CLI dependency.

use std::fmt;
use std::process::ExitCode;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use clap::{Parser, Subcommand};

use greentic_trust::ceremony::generate_root;

#[derive(Parser)]
#[command(name = "greentic-trust", about = "Greentic did:web trust-root ceremony tool")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a root Ed25519 keypair. Private seed to stdout, public JWK to stderr.
    GenRoot,
}

/// A ceremony error, rendered to stderr with a non-zero exit.
enum CliError {
    Trust(greentic_trust::TrustError),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::Trust(e) => write!(f, "{e}"),
        }
    }
}

impl From<greentic_trust::TrustError> for CliError {
    fn from(e: greentic_trust::TrustError) -> Self {
        CliError::Trust(e)
    }
}

fn run() -> Result<(), CliError> {
    match Cli::parse().command {
        Command::GenRoot => run_gen_root(),
    }
}

fn run_gen_root() -> Result<(), CliError> {
    let signing = generate_root(&mut rand::rngs::OsRng);

    // stdout: the secret, alone, so `gen-root | wrangler secret put ...` pipes
    // only the private key.
    println!("{}", STANDARD.encode(signing.to_bytes()));

    // stderr: everything a human needs, none of it captured by the pipe.
    let x = URL_SAFE_NO_PAD.encode(signing.verifying_key().as_bytes());
    eprintln!("public key (JWK x, base64url): {x}");
    eprintln!("suggested kid suffix: #root-1");
    eprintln!(
        "warning: a private key was written to stdout; capture it into your secret \
         manager and clear your scrollback"
    );
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --features cli --test cli 2>&1 | tail -5`
Expected: PASS — both `gen_root_*` tests.

- [ ] **Step 6: Mutation check — the stdout/stderr split is real**

Follow the staging protocol. Mutation: in `run_gen_root`, change the `println!` (stdout) for the private seed to `eprintln!` (stderr).

```bash
git add src/main.rs
# apply the mutation
git diff --stat            # MUST be non-empty
cargo test --features cli --test cli
git checkout src/main.rs
cargo test --features cli --test cli
```

Expected: `gen_root_prints_a_valid_private_seed_to_stdout` fails (stdout empty) and `gen_root_puts_the_public_key_and_warning_on_stderr_not_stdout` fails (private now on stderr), and both pass after restore.

- [ ] **Step 7: Verify the lib stays clap-free now that clap exists**

This is the real gating check for D1 — it means something only now that `clap` is an optional dep behind `cli`.

```bash
cargo build --no-default-features 2>&1 | tail -2
cargo tree --no-default-features -e normal | grep -qi '^clap\| clap ' && echo "FAIL: clap leaked into the lib graph" || echo "OK: lib is clap-free"
```
Expected: the lib builds, and `OK: lib is clap-free` — a default (`cli`-off) build must not pull `clap`.

- [ ] **Step 8: Lints (with the binary in scope)**

Run: `cargo fmt --all -- --check && cargo clippy --all-targets --all-features -- -D warnings`
Expected: clean. `--all-features` builds the binary, so clippy lints it too.

- [ ] **Step 9: Commit**

```bash
git add Cargo.toml Cargo.lock src/main.rs tests/cli.rs
git commit -m "feat: add cli feature and the gen-root subcommand"
```

---

### Task 3: `build-doc` and `verify-doc` subcommands

**Files:**
- Modify: `src/main.rs` (two subcommands + handlers)
- Modify: `tests/cli.rs` (round-trip and mismatch tests)

**Interfaces:**
- Consumes: `greentic_trust::ceremony::build_document`, `greentic_trust::{DidWeb, TrustDocument, HttpResolver, RootResolver}`.
- Produces: `build-doc` and `verify-doc` on the binary.

**Design note:** `verify-doc` takes `--did` (and optional `--file`), not a free `--url`. The S1 resolver derives the document URL from the DID; a free `--url` would either duplicate that or point at a foreign origin the binding check rejects — so it is removed. `--did` alone resolves over the network; `--file` inspects a local document.

- [ ] **Step 1: Write the failing tests**

Append to `tests/cli.rs`:

```rust
use std::io::Write as _;

/// Run gen-root and return (private_seed_b64, public_x_b64url).
fn fresh_root() -> (String, String) {
    let output = bin().arg("gen-root").assert().success().get_output().clone();
    let private = String::from_utf8(output.stdout).unwrap().trim().to_owned();
    let seed: [u8; 32] = STANDARD.decode(&private).unwrap().try_into().unwrap();
    let x = URL_SAFE_NO_PAD.encode(
        ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().to_bytes(),
    );
    (private, x)
}

#[test]
fn build_doc_then_verify_doc_file_accepts_the_matching_root() {
    let did = "did:web:trust.research.greentic.cloud";
    let (_private, x) = fresh_root();

    let built = bin()
        .args(["build-doc", "--did", did, "--root-public", &x])
        .assert()
        .success()
        .get_output()
        .clone();
    let doc = built.stdout;

    let mut file = tempfile::NamedTempFile::new().expect("temp file");
    file.write_all(&doc).expect("write doc");

    bin()
        .args(["verify-doc", "--did", did, "--expected-root", &x, "--file"])
        .arg(file.path())
        .assert()
        .success();
}

#[test]
fn verify_doc_file_rejects_a_wrong_expected_root() {
    let did = "did:web:trust.research.greentic.cloud";
    let (_p1, published_x) = fresh_root();
    let (_p2, other_x) = fresh_root();

    let built = bin()
        .args(["build-doc", "--did", did, "--root-public", &published_x])
        .assert()
        .success()
        .get_output()
        .clone();

    let mut file = tempfile::NamedTempFile::new().expect("temp file");
    file.write_all(&built.stdout).expect("write doc");

    bin()
        .args(["verify-doc", "--did", did, "--expected-root", &other_x, "--file"])
        .arg(file.path())
        .assert()
        .failure();
}

#[test]
fn build_doc_rejects_a_malformed_did() {
    bin()
        .args(["build-doc", "--did", "did:key:z6MkExample", "--root-public", "AAAA"])
        .assert()
        .failure();
}
```

Add `tempfile` to `[dev-dependencies]` in `Cargo.toml`: `tempfile = "3"`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --features cli --test cli 2>&1 | tail -6`
Expected: FAIL — `build-doc` / `verify-doc` are not subcommands yet.

- [ ] **Step 3: Add the subcommands and handlers to `src/main.rs`**

Extend the `Command` enum:

```rust
#[derive(Subcommand)]
enum Command {
    /// Generate a root Ed25519 keypair. Private seed to stdout, public JWK to stderr.
    GenRoot,
    /// Build a did.json document for a DID and one or more root public keys.
    BuildDoc {
        /// The did:web identifier the document is served for.
        #[arg(long)]
        did: String,
        /// A root public key (JWK x, base64url). Repeat for a rotation-overlap doc.
        #[arg(long = "root-public", required = true)]
        root_public: Vec<String>,
    },
    /// Verify a published or local did.json serves the expected root.
    VerifyDoc {
        /// The did:web identifier to resolve (or to bind a --file document against).
        #[arg(long)]
        did: String,
        /// The root public key you expect (JWK x, base64url).
        #[arg(long)]
        expected_root: String,
        /// Read a local document instead of resolving over the network.
        #[arg(long)]
        file: Option<std::path::PathBuf>,
    },
}
```

Add error variants and their `Display`:

```rust
enum CliError {
    Trust(greentic_trust::TrustError),
    Io(std::io::Error),
    Decode(String),
    Mismatch,
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::Trust(e) => write!(f, "{e}"),
            CliError::Io(e) => write!(f, "io: {e}"),
            CliError::Decode(m) => write!(f, "decode: {m}"),
            CliError::Mismatch => write!(f, "the document does not serve the expected root"),
        }
    }
}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        CliError::Io(e)
    }
}
```

Extend `run`:

```rust
fn run() -> Result<(), CliError> {
    match Cli::parse().command {
        Command::GenRoot => run_gen_root(),
        Command::BuildDoc { did, root_public } => run_build_doc(&did, &root_public),
        Command::VerifyDoc { did, expected_root, file } => {
            run_verify_doc(&did, &expected_root, file.as_deref())
        }
    }
}
```

Add the handlers and a shared key decoder:

```rust
use greentic_trust::ceremony::build_document;
use greentic_trust::{DidWeb, HttpResolver, RootResolver, TrustDocument};

/// Decode a JWK `x` (base64url, 32 bytes) into a verifying key.
fn decode_public(x: &str) -> Result<ed25519_dalek::VerifyingKey, CliError> {
    let raw = URL_SAFE_NO_PAD
        .decode(x.trim())
        .map_err(|e| CliError::Decode(format!("root public key is not base64url: {e}")))?;
    let bytes: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| CliError::Decode(format!("root public key is {} bytes, expected 32", raw.len())))?;
    ed25519_dalek::VerifyingKey::from_bytes(&bytes)
        .map_err(|e| CliError::Decode(format!("root public key is not a valid Ed25519 key: {e}")))
}

fn run_build_doc(did: &str, root_public: &[String]) -> Result<(), CliError> {
    let did = DidWeb::parse(did)?;
    let roots = root_public
        .iter()
        .map(|x| decode_public(x))
        .collect::<Result<Vec<_>, _>>()?;
    let doc = build_document(&did, &roots)?;
    println!("{}", serde_json::to_string_pretty(&doc).map_err(|e| CliError::Decode(e.to_string()))?);
    Ok(())
}

fn run_verify_doc(did: &str, expected_root: &str, file: Option<&std::path::Path>) -> Result<(), CliError> {
    let did = DidWeb::parse(did)?;
    let expected = decode_public(expected_root)?;

    let matched = match file {
        Some(path) => {
            let bytes = std::fs::read(path)?;
            let doc = TrustDocument::parse(&did, &bytes)?;
            doc.assertion_keys().iter().any(|k| k.as_bytes() == expected.as_bytes())
        }
        None => {
            let resolver = HttpResolver::new(std::time::Duration::from_secs(600), 4);
            let doc = tokio::runtime::Runtime::new()?.block_on(resolver.resolve(&did))?;
            doc.assertion_keys().iter().any(|k| k.as_bytes() == expected.as_bytes())
        }
    };

    if matched {
        println!("OK: {} serves the expected root", did.as_str());
        Ok(())
    } else {
        Err(CliError::Mismatch)
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --features cli --test cli 2>&1 | tail -6`
Expected: PASS — all `cli` tests (gen-root, build/verify round-trip, mismatch, malformed DID).

- [ ] **Step 5: Mutation check — verify-doc actually enforces the expected root**

Follow the staging protocol. Mutation: in `run_verify_doc`, replace the `.any(...)` predicate for the `file` branch with `true` (accept any document).

```bash
git add src/main.rs
# apply the mutation
git diff --stat            # MUST be non-empty
cargo test --features cli --test cli
git checkout src/main.rs
cargo test --features cli --test cli
```

Expected: `verify_doc_file_rejects_a_wrong_expected_root` FAILS under the mutation (a mismatch is wrongly accepted), and passes after restore.

- [ ] **Step 6: Full gate**

Run: `bash ci/local_check.sh`
Expected: `All checks passed.` (fmt, clippy `-D warnings`, tests under `--all-features` including the binary, doc `-D warnings`).

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml Cargo.lock src/main.rs tests/cli.rs
git commit -m "feat: add build-doc and verify-doc subcommands"
```

---

### Task 4: the ceremony runbook

**Files:**
- Create: `docs/runbooks/root-ceremony.md`
- Modify: `README.md` (link the runbook and the tool)

**Interfaces:** none — documentation.

- [ ] **Step 1: Write the runbook**

Create `docs/runbooks/root-ceremony.md`:

```markdown
# Root ceremony runbook

How to generate, publish, verify, rotate, and revoke a Greentic did:web trust root.
The `greentic-trust` binary (built with `cargo build --features cli`) does the crypto;
this runbook is the human procedure around it.

## Environments

| Environment | DID | Root custody |
|---|---|---|
| research | `did:web:trust.research.greentic.cloud` | secret manager |
| staging | `did:web:trust.staging.greentic.cloud` | secret manager |
| production | `did:web:trust.greentic.cloud` | offline ceremony |

The trusted DID is configured into consumers as a **URL, not a secret** — it belongs in
ordinary config. Only the private root key is secret.

**Production owner: TBD — assign before the first production ceremony.** This is the
"org-blocked" item `root_verifier.rs:51` refers to: the production root does not exist
until someone holds the ceremony on an air-gapped machine.

## 1. Generate a root

research / staging — on a trusted operator machine:

    greentic-trust gen-root | wrangler secret put GREENTIC_TRUST_ROOT_RESEARCH
    # the public JWK x and a suggested kid are printed to stderr — record the x

production — on an **air-gapped** machine:

    greentic-trust gen-root > /dev/shm/root.seed   # stdout is the private seed (base64)
    # transfer the public x (printed to stderr) out; move the sealed seed into hardware/KMS;
    # the private seed never leaves the air-gapped machine in the clear.

The private key is the raw 32-byte Ed25519 seed, base64. `gen-root` never encrypts it —
your secret manager or hardware does the sealing.

## 2. Build the document

    greentic-trust build-doc \
      --did did:web:trust.research.greentic.cloud \
      --root-public <x-from-step-1> \
      > did.json

`build-doc` produces exactly the bytes the runtime verifier accepts. Publishing this to
`https://trust.research.greentic.cloud/.well-known/did.json` completes the resolution.

## 3. Publish (manual — see the token note)

Upload `did.json` to the R2 bucket serving the environment's origin, at the path
`/.well-known/did.json`, and bind `trust.<env>.greentic.cloud` to it (production:
`trust.greentic.cloud`).

**Token note.** The CI `CLOUDFLARE_API_TOKEN` lacks `Workers Routes:Edit` and has no R2
scope — declaring routes in wrangler makes `wrangler deploy` fail *after* upload
(Cloudflare error 10000). This is why every custom domain in the platform, e.g.
`id.research.greentic.cloud`, is bound out-of-band and persists across deploys. Bind the
trust hostname the same way, or use a scoped-up token. The Cloudflare API shapes to script
against, if you do scope one up, are in `greentic-tenant-manager/crates/tenant-core/src/cloudflare_api.rs`
(`ensure_r2_bucket`, `configure_custom_hostname`).

The document must be **static** and on an origin that serves **no artifacts** — never the
store server. A host that serves both the key and the artifacts can substitute both at once.

## 4. Verify the publish

    greentic-trust verify-doc \
      --did did:web:trust.research.greentic.cloud \
      --expected-root <x-from-step-1>

This resolves the live document with the same code the runner uses and confirms it serves
your key. Do not trust a publish you have not verified. To inspect a local file instead,
add `--file did.json`.

## 5. Rotate the root

1. `gen-root` a new root; stash its private key as in step 1.
2. Build a document carrying **both** roots so signatures under either verify during the overlap:

       greentic-trust build-doc --did <did> \
         --root-public <old-x> --root-public <new-x> > did.json

3. Publish (step 3) and verify (step 4, once per key).
4. After the TTL (600s) has drained and consumers hold the new key, rebuild with the new
   root only and republish.

Offline-pinned consumers do not see a rotation until they refetch.

## 6. Revoke a root

Remove the compromised key from the published document and republish. There is no CRL —
the live document is the revocation surface, which is why the TTL is short (600s). Pinned
consumers lag until they refetch, so a rotation of the compromised key should follow.
```

- [ ] **Step 2: Link it from the README**

In `README.md`, under the `## Design` section (or add a `## Ceremony` section before it), add:

```markdown
## Ceremony

Generating and publishing a root is documented in
[`docs/runbooks/root-ceremony.md`](docs/runbooks/root-ceremony.md). The tool:

    cargo build --features cli
    greentic-trust gen-root         # generate a root keypair
    greentic-trust build-doc ...    # build the did.json
    greentic-trust verify-doc ...   # confirm a publish
```

- [ ] **Step 3: Verify the docs build and links resolve**

Run:
```bash
test -f docs/runbooks/root-ceremony.md && echo "runbook present"
grep -q "root-ceremony.md" README.md && echo "README links the runbook"
bash ci/local_check.sh 2>&1 | tail -1
```
Expected: both present, `All checks passed.`

- [ ] **Step 4: Commit**

```bash
git add docs/runbooks/root-ceremony.md README.md
git commit -m "docs: add the root ceremony runbook"
```

---

## Self-Review Notes

**Spec coverage:**

| Spec requirement | Task |
|---|---|
| `ceremony` module, always compiled, `generate_root` + `build_document` | 1 |
| Anti-drift round-trip through `TrustDocument::parse` | 1 (step 3 test + step 8/9 mutations) |
| `fixtures` kept as delegating shim; nothing breaks | 1 (step 6) |
| Base64 discipline (JWK x = URL_SAFE_NO_PAD) | 1 (`jwk_x_is_base64url_not_standard` + step 8) |
| Multi-key document for rotation overlap | 1 (`multi_key_document_carries_every_root`) |
| `cli` feature, lib stays clap-free | 2 (step 1 + step 10 of Task 1's clap-free check; Task 2 introduces the feature) |
| `gen-root`, private→stdout / public→stderr, raw seed base64 STANDARD | 2 |
| `build-doc` (repeatable `--root-public`) | 3 |
| `verify-doc` (`--did` resolves, `--file` local), fail-closed exit code | 3 |
| Runbook: per-env, publish, verify, rotate, revoke, token landmine, prod owner TBD | 4 |
| No new `TrustError` variants | all (only existing variants used) |
| Every security invariant has a mutation check | 1 (steps 8,9), 2 (step 6), 3 (step 5) |

**Deliberately deferred (recorded, not lost):** `mint_cert` graduation to always-compiled (S3, when store-server has a production caller — moving it now forces a `Result` signature change through S1's merged tests for no S2 benefit); CI automation of R2/DNS (blocked on token scope); the production ceremony itself (needs the named owner).

**Design refinement from reading the code:** `verify-doc` uses `--did` to drive the S1 resolver rather than the spec's `--url`, because a free `--url` either duplicates the DID-derived URL or points at a foreign origin the binding check rejects. Recorded here and in Task 3's design note.

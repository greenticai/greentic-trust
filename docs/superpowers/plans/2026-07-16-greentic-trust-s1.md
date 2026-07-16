# greentic-trust S1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `greentic-trust`, a pure library that decides whether a signed Greentic `describe` chains to a trusted root key published at a `did:web` URL — or says precisely why not.

**Architecture:** Six modules with one-way dependencies. `did` parses `did:web:*` into a URL. `document` parses the fetched DID document and enforces that its `id` matches the DID we asked for. `cert` verifies a `PublisherCert` — a root signature over a publisher key, with a signed expiry. `resolver` fetches and caches documents behind a trait so callers can supply an offline implementation later. `chain` runs the six-step verification in order. `error` gives every failure its own variant.

**Tech Stack:** Rust 1.95.0, `ed25519-dalek` 2.1, `serde_jcs` 0.1 (RFC 8785 canonicalization), `chrono` 0.4, `moka` 0.12 (cache), `reqwest` 0.12, `wiremock` 0.6 (tests).

**Spec:** `docs/superpowers/specs/2026-07-16-did-web-trust-root-design.md`

## Global Constraints

- Rust **1.95.0**, pinned via `rust-toolchain.toml`. Do not edit the pin per-repo.
- `#![forbid(unsafe_code)]` at the crate root.
- **No `unwrap()` / `expect()` / `panic!()` in production paths.** Tests may use them.
- **No `bool` return and no `Option` for any security decision.** Every verification result is `Result<T, TrustError>`.
- **No `Skipped`-style variant anywhere.** The verifier reports pass or why it failed; "unsigned is tolerable" is the caller's policy, not this crate's.
- English only in source, tests, comments, commit messages.
- Conventional Commits (`feat:`, `fix:`, `test:`, `docs:`, `chore:`).
- `Cargo.lock` is committed; CI uses `--locked`.
- `cargo clippy --all-targets --all-features -- -D warnings` must pass.
- Base64: **`STANDARD`** for cert/signature fields (matches store-server and the runner). **`URL_SAFE_NO_PAD`** for JWK `x` members (RFC 7515 §2 / RFC 8037). Mixing these silently breaks interop — the two encodings agree on most bytes and diverge on a few.
- Time is always a caller-supplied `chrono::DateTime<Utc>` parameter. Never call `Utc::now()` inside the crate.

---

### Task 1: Repo skeleton, error enum, and `did` parsing

**Files:**
- Create: `Cargo.toml`
- Create: `rust-toolchain.toml`
- Create: `src/lib.rs`
- Create: `src/error.rs`
- Create: `src/did.rs`

**Interfaces:**
- Consumes: nothing (first task).
- Produces:
  - `greentic_trust::error::TrustError` — the crate-wide error enum, complete. Every later task uses its variants and adds none.
  - `greentic_trust::did::DidWeb` with `DidWeb::parse(&str) -> Result<DidWeb, TrustError>`, `DidWeb::as_str(&self) -> &str`, `DidWeb::document_url(&self) -> &str`.

- [ ] **Step 1: Create the toolchain pin**

Create `rust-toolchain.toml`:

```toml
# Canonical toolchain for Greentic Rust repos.
# Do not edit per-repo.

[toolchain]
channel = "1.95.0"
components = ["clippy", "rustfmt"]
```

- [ ] **Step 2: Create `Cargo.toml`**

```toml
[package]
name = "greentic-trust"
version = "0.1.0"
edition = "2021"
rust-version = "1.95"
license = "Apache-2.0"
description = "did:web trust root and publisher certificate verification for Greentic"
repository = "https://github.com/greenticai/greentic-trust"

[features]
default = []
# Exposes fixture helpers (root keypair generation, cert minting) to downstream crates.
testing = ["dep:rand"]

[dependencies]
base64 = "0.22"
chrono = { version = "0.4", default-features = false, features = ["serde", "clock"] }
ed25519-dalek = { version = "2.1", features = ["rand_core"] }
moka = { version = "0.12", features = ["future"] }
rand = { version = "0.8", optional = true }
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls"] }
serde = { version = "1", features = ["derive"] }
serde_jcs = "0.1"
serde_json = "1"
thiserror = "2"

[dev-dependencies]
rand = "0.8"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
wiremock = "0.6"

[lints.rust]
unsafe_code = "forbid"

[lints.clippy]
all = { level = "deny", priority = -1 }
pedantic = { level = "warn", priority = -1 }
```

- [ ] **Step 3: Create `src/error.rs` with the complete error enum**

```rust
//! Crate-wide error type.
//!
//! Every failure mode gets its own variant carrying what a reader needs to act.
//! There is deliberately no "skipped" or "not checked" variant: a caller that
//! wants to tolerate unsigned artifacts expresses that in its own policy, so
//! that "verified" and "never checked" can never collapse into one value here.

use thiserror::Error;

/// Any failure while resolving a trust root or verifying a chain.
#[derive(Debug, Error)]
pub enum TrustError {
    #[error("not a did:web identifier: {input}")]
    NotWebMethod { input: String },

    #[error("malformed did:web identifier {input}: {reason}")]
    DidParse { input: String, reason: String },

    #[error("refusing to resolve a trust root over a non-HTTPS URL: {url}")]
    InsecureScheme { url: String },

    #[error("fetching the DID document failed: {source}")]
    Fetch {
        #[source]
        source: reqwest::Error,
    },

    #[error("DID document request returned HTTP {code}")]
    HttpStatus { code: u16 },

    #[error("DID document is not valid JSON: {source}")]
    DocumentParse {
        #[source]
        source: serde_json::Error,
    },

    #[error("DID document is malformed: {reason}")]
    DocumentInvalid { reason: String },

    #[error("DID document binding violated: served at {expected} but claims id {found}")]
    BindingMismatch { expected: String, found: String },

    #[error("DID document for {did} publishes no assertionMethod keys")]
    NoAssertionKeys { did: String },

    #[error("unsupported key algorithm: {alg}")]
    UnsupportedAlgorithm { alg: String },

    #[error("describe has no signature block")]
    SignatureBlockMissing,

    #[error("describe signature block has no certificate")]
    CertMissing,

    #[error("publisher certificate has no notAfter")]
    CertMissingExpiry,

    #[error("publisher certificate has no keyId")]
    CertMissingKeyId,

    #[error("publisher certificate is malformed: {reason}")]
    CertInvalid { reason: String },

    #[error("publisher certificate is not signed by any trusted root")]
    CertSignatureInvalid,

    #[error("publisher certificate expired at {not_after} (now {now})")]
    CertExpired {
        not_after: chrono::DateTime<chrono::Utc>,
        now: chrono::DateTime<chrono::Utc>,
    },

    #[error("certificate vouches for key {cert_key} but the describe was signed by {signing_key}")]
    CertKeyMismatch {
        cert_key: String,
        signing_key: String,
    },

    #[error("describe signature does not verify against the certified publisher key")]
    DescribeSignatureInvalid,

    #[error("canonicalizing JSON failed: {source}")]
    Canonicalize {
        #[source]
        source: serde_json::Error,
    },
}
```

- [ ] **Step 4: Create `src/lib.rs`**

```rust
//! did:web trust root and publisher certificate verification for Greentic.
//!
//! Given a signed `describe`, a [`cert::PublisherCert`], and a trusted
//! [`did::DidWeb`], decide whether the artifact is authentic. See
//! `docs/superpowers/specs/2026-07-16-did-web-trust-root-design.md`.

#![forbid(unsafe_code)]

pub mod did;
pub mod error;

pub use did::DidWeb;
pub use error::TrustError;
```

- [ ] **Step 5: Write the failing tests for `did`**

Create `src/did.rs` containing only this test module for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_well_known_url_for_a_bare_host() {
        let did = DidWeb::parse("did:web:example.com").expect("parses");
        assert_eq!(
            did.document_url(),
            "https://example.com/.well-known/did.json"
        );
        assert_eq!(did.as_str(), "did:web:example.com");
    }

    #[test]
    fn derives_a_path_url_for_a_namespaced_did() {
        let did = DidWeb::parse("did:web:example.com:services:store").expect("parses");
        assert_eq!(
            did.document_url(),
            "https://example.com/services/store/did.json"
        );
    }

    #[test]
    fn decodes_a_percent_encoded_port() {
        let did = DidWeb::parse("did:web:example.com%3A8443").expect("parses");
        assert_eq!(
            did.document_url(),
            "https://example.com:8443/.well-known/did.json"
        );
    }

    #[test]
    fn rejects_a_non_web_method() {
        let error = DidWeb::parse("did:key:z6MkExample").expect_err("rejects");
        assert!(matches!(error, TrustError::NotWebMethod { .. }));
    }

    #[test]
    fn rejects_an_empty_method_specific_id() {
        let error = DidWeb::parse("did:web:").expect_err("rejects");
        assert!(matches!(error, TrustError::DidParse { .. }));
    }

    #[test]
    fn rejects_path_traversal_segments() {
        let error = DidWeb::parse("did:web:example.com:..:secrets").expect_err("rejects");
        assert!(matches!(error, TrustError::DidParse { .. }));
    }

    #[test]
    fn rejects_an_empty_path_segment() {
        let error = DidWeb::parse("did:web:example.com::store").expect_err("rejects");
        assert!(matches!(error, TrustError::DidParse { .. }));
    }

    #[test]
    fn rejects_a_percent_encoded_path_separator_in_the_host() {
        // %2F would smuggle a path separator into the host and let an attacker
        // point the DID at an origin it does not name.
        let error = DidWeb::parse("did:web:example.com%2Fevil.com").expect_err("rejects");
        assert!(matches!(error, TrustError::DidParse { .. }));
    }
}
```

- [ ] **Step 6: Run the tests to verify they fail**

Run: `cargo test --lib did`
Expected: FAIL — `cannot find type DidWeb in this scope`.

- [ ] **Step 7: Implement `did`**

Prepend to `src/did.rs`, above the test module:

```rust
//! Parsing `did:web:*` identifiers into the URL their document is served from.
//!
//! Pure — no I/O. Per the did:web method, `did:web:example.com` resolves to
//! `https://example.com/.well-known/did.json`, and each extra colon-separated
//! segment becomes a path segment: `did:web:example.com:a:b` resolves to
//! `https://example.com/a/b/did.json`.

use crate::error::TrustError;

const DID_WEB_PREFIX: &str = "did:web:";

/// A parsed `did:web` identifier and the URL its document is served from.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DidWeb {
    raw: String,
    url: String,
}

impl DidWeb {
    /// Parse a `did:web:*` identifier.
    ///
    /// # Errors
    /// [`TrustError::NotWebMethod`] if `input` is not a `did:web` identifier;
    /// [`TrustError::DidParse`] if the host or any path segment is malformed.
    pub fn parse(input: &str) -> Result<Self, TrustError> {
        let rest = input
            .strip_prefix(DID_WEB_PREFIX)
            .ok_or_else(|| TrustError::NotWebMethod {
                input: input.to_owned(),
            })?;

        let mut segments = rest.split(':');
        let Some(host_raw) = segments.next() else {
            return Err(TrustError::DidParse {
                input: input.to_owned(),
                reason: "empty method-specific identifier".to_owned(),
            });
        };
        let host = decode_host(host_raw).map_err(|reason| TrustError::DidParse {
            input: input.to_owned(),
            reason,
        })?;

        let mut path = String::new();
        for segment in segments {
            validate_path_segment(segment).map_err(|reason| TrustError::DidParse {
                input: input.to_owned(),
                reason,
            })?;
            path.push('/');
            path.push_str(segment);
        }

        let url = if path.is_empty() {
            format!("https://{host}/.well-known/did.json")
        } else {
            format!("https://{host}{path}/did.json")
        };

        Ok(Self {
            raw: input.to_owned(),
            url,
        })
    }

    /// The identifier exactly as parsed. This is what a document's `id` must equal.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// The HTTPS URL this identifier's document is served from.
    #[must_use]
    pub fn document_url(&self) -> &str {
        &self.url
    }
}

/// Decode a did:web host.
///
/// `%3A` (a port separator) is the only percent-escape the method defines for
/// the host, so decode exactly that and reject anything else still encoded. A
/// general percent-decoder here would let `%2F` smuggle a path separator into
/// the host and repoint the DID at an origin it does not name.
fn decode_host(raw: &str) -> Result<String, String> {
    if raw.is_empty() {
        return Err("empty host".to_owned());
    }
    let decoded = raw.replace("%3A", ":").replace("%3a", ":");
    if decoded.contains('%') {
        return Err(format!("host has unsupported percent-encoding: {raw}"));
    }
    if decoded.contains('/') {
        return Err(format!("host contains a path separator: {raw}"));
    }
    Ok(decoded)
}

fn validate_path_segment(segment: &str) -> Result<(), String> {
    if segment.is_empty() {
        return Err("empty path segment".to_owned());
    }
    if segment == "." || segment == ".." {
        return Err(format!("path traversal segment: {segment}"));
    }
    if segment.contains('/') || segment.contains('%') {
        return Err(format!("illegal path segment: {segment}"));
    }
    Ok(())
}
```

Add to `src/lib.rs` — it already declares `pub mod did;`, so no change is needed.

- [ ] **Step 8: Run the tests to verify they pass**

Run: `cargo test --lib did`
Expected: PASS — 8 tests.

- [ ] **Step 9: Verify lint and format are clean**

Run: `cargo fmt --all && cargo clippy --all-targets --all-features -- -D warnings`
Expected: no warnings.

- [ ] **Step 10: Commit**

```bash
git add Cargo.toml Cargo.lock rust-toolchain.toml src/lib.rs src/error.rs src/did.rs
git commit -m "feat: parse did:web identifiers into document URLs"
```

---

### Task 2: DID document parsing with binding enforcement

**Files:**
- Create: `src/document.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: `DidWeb::as_str()` and `TrustError` from Task 1.
- Produces:
  - `greentic_trust::document::TrustDocument` with `TrustDocument::parse(did: &DidWeb, bytes: &[u8]) -> Result<TrustDocument, TrustError>` and `TrustDocument::assertion_keys(&self) -> &[ed25519_dalek::VerifyingKey]`.

- [ ] **Step 1: Write the failing tests**

Create `src/document.rs` containing only this test module for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn document_json(id: &str, x_b64url: &str, crv: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": id,
            "verificationMethod": [{
                "id": format!("{id}#root-1"),
                "type": "JsonWebKey2020",
                "controller": id,
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": crv,
                    "x": x_b64url,
                    "use": "sig",
                },
            }],
            "assertionMethod": [format!("{id}#root-1")],
        }))
        .expect("serializes")
    }

    fn a_key() -> (SigningKey, String) {
        let signing = SigningKey::generate(&mut OsRng);
        let x = URL_SAFE_NO_PAD.encode(signing.verifying_key().as_bytes());
        (signing, x)
    }

    #[test]
    fn parses_an_ed25519_assertion_key() {
        let (signing, x) = a_key();
        let did = DidWeb::parse("did:web:trust.greentic.cloud").expect("parses");
        let bytes = document_json("did:web:trust.greentic.cloud", &x, "Ed25519");

        let document = TrustDocument::parse(&did, &bytes).expect("parses");

        assert_eq!(document.assertion_keys().len(), 1);
        assert_eq!(
            document.assertion_keys()[0].as_bytes(),
            signing.verifying_key().as_bytes()
        );
    }

    #[test]
    fn rejects_a_document_whose_id_does_not_match_the_resolved_did() {
        // The did:web binding: a document is only authoritative for the DID
        // whose URL served it. Without this check an attacker who can serve any
        // document at any URL can claim to be the Greentic root.
        let (_signing, x) = a_key();
        let did = DidWeb::parse("did:web:trust.greentic.cloud").expect("parses");
        let bytes = document_json("did:web:evil.example", &x, "Ed25519");

        let error = TrustDocument::parse(&did, &bytes).expect_err("rejects");

        assert!(matches!(
            error,
            TrustError::BindingMismatch { ref expected, ref found }
                if expected == "did:web:trust.greentic.cloud" && found == "did:web:evil.example"
        ));
    }

    #[test]
    fn rejects_a_document_with_no_assertion_keys() {
        let did = DidWeb::parse("did:web:trust.greentic.cloud").expect("parses");
        let bytes = serde_json::to_vec(&serde_json::json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:web:trust.greentic.cloud",
            "verificationMethod": [],
            "assertionMethod": [],
        }))
        .expect("serializes");

        let error = TrustDocument::parse(&did, &bytes).expect_err("rejects");

        assert!(matches!(error, TrustError::NoAssertionKeys { .. }));
    }

    #[test]
    fn rejects_a_non_ed25519_key() {
        // tenant-manager publishes ES256/P-256. A P-256 key must be a loud
        // rejection, not a silently skipped entry that leaves an empty set.
        let did = DidWeb::parse("did:web:trust.greentic.cloud").expect("parses");
        let bytes = serde_json::to_vec(&serde_json::json!({
            "id": "did:web:trust.greentic.cloud",
            "verificationMethod": [{
                "id": "did:web:trust.greentic.cloud#root-1",
                "type": "JsonWebKey2020",
                "controller": "did:web:trust.greentic.cloud",
                "publicKeyJwk": {
                    "kty": "EC", "crv": "P-256", "alg": "ES256",
                    "x": "aaaa", "y": "bbbb",
                },
            }],
            "assertionMethod": ["did:web:trust.greentic.cloud#root-1"],
        }))
        .expect("serializes");

        let error = TrustDocument::parse(&did, &bytes).expect_err("rejects");

        assert!(matches!(error, TrustError::UnsupportedAlgorithm { .. }));
    }

    #[test]
    fn rejects_an_assertion_reference_with_no_verification_method() {
        let did = DidWeb::parse("did:web:trust.greentic.cloud").expect("parses");
        let bytes = serde_json::to_vec(&serde_json::json!({
            "id": "did:web:trust.greentic.cloud",
            "verificationMethod": [],
            "assertionMethod": ["did:web:trust.greentic.cloud#missing"],
        }))
        .expect("serializes");

        let error = TrustDocument::parse(&did, &bytes).expect_err("rejects");

        assert!(matches!(error, TrustError::DocumentInvalid { .. }));
    }

    #[test]
    fn rejects_a_jwk_whose_x_is_not_32_bytes() {
        let did = DidWeb::parse("did:web:trust.greentic.cloud").expect("parses");
        let short = URL_SAFE_NO_PAD.encode([0_u8; 16]);
        let bytes = document_json("did:web:trust.greentic.cloud", &short, "Ed25519");

        let error = TrustDocument::parse(&did, &bytes).expect_err("rejects");

        assert!(matches!(error, TrustError::DocumentInvalid { .. }));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib document`
Expected: FAIL — `cannot find type TrustDocument in this scope`.

- [ ] **Step 3: Implement `document`**

Prepend to `src/document.rs`, above the test module:

```rust
//! Parsing a fetched DID document into the set of keys it authorizes for
//! assertions.
//!
//! The binding check here is the whole security value of did:web: a document is
//! authoritative only for the DID whose URL served it, so its `id` must equal
//! the identifier we resolved. Everything else is shape validation.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::VerifyingKey;
use serde::Deserialize;

use crate::did::DidWeb;
use crate::error::TrustError;

/// A DID document reduced to the keys it authorizes for assertions.
#[derive(Debug, Clone)]
pub struct TrustDocument {
    did: String,
    assertion_keys: Vec<VerifyingKey>,
}

#[derive(Debug, Deserialize)]
struct RawDocument {
    id: String,
    #[serde(default, rename = "verificationMethod")]
    verification_method: Vec<RawVerificationMethod>,
    #[serde(default, rename = "assertionMethod")]
    assertion_method: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawVerificationMethod {
    id: String,
    #[serde(rename = "publicKeyJwk")]
    public_key_jwk: RawJwk,
}

#[derive(Debug, Deserialize)]
struct RawJwk {
    kty: String,
    #[serde(default)]
    crv: String,
    #[serde(default)]
    x: String,
}

impl TrustDocument {
    /// Parse `bytes` as the DID document for `did`.
    ///
    /// # Errors
    /// [`TrustError::BindingMismatch`] if the document's `id` is not `did`;
    /// [`TrustError::NoAssertionKeys`] if it authorizes none;
    /// [`TrustError::UnsupportedAlgorithm`] for a non-Ed25519 key;
    /// [`TrustError::DocumentParse`] / [`TrustError::DocumentInvalid`] on shape errors.
    pub fn parse(did: &DidWeb, bytes: &[u8]) -> Result<Self, TrustError> {
        let raw: RawDocument = serde_json::from_slice(bytes)
            .map_err(|source| TrustError::DocumentParse { source })?;

        if raw.id != did.as_str() {
            return Err(TrustError::BindingMismatch {
                expected: did.as_str().to_owned(),
                found: raw.id,
            });
        }

        let mut assertion_keys = Vec::with_capacity(raw.assertion_method.len());
        for reference in &raw.assertion_method {
            let method = raw
                .verification_method
                .iter()
                .find(|candidate| &candidate.id == reference)
                .ok_or_else(|| TrustError::DocumentInvalid {
                    reason: format!("assertionMethod {reference} has no verificationMethod"),
                })?;
            assertion_keys.push(ed25519_key_from_jwk(&method.public_key_jwk)?);
        }

        if assertion_keys.is_empty() {
            return Err(TrustError::NoAssertionKeys {
                did: did.as_str().to_owned(),
            });
        }

        Ok(Self {
            did: raw.id,
            assertion_keys,
        })
    }

    /// The identifier this document is authoritative for.
    #[must_use]
    pub fn did(&self) -> &str {
        &self.did
    }

    /// The keys authorized to make assertions — i.e. to sign publisher certs.
    #[must_use]
    pub fn assertion_keys(&self) -> &[VerifyingKey] {
        &self.assertion_keys
    }
}

/// Decode an Ed25519 public key from a JWK.
///
/// JWK `x` is base64url **unpadded** (RFC 7515 §2, RFC 8037), unlike the
/// standard-base64 used for cert and signature fields elsewhere in Greentic.
fn ed25519_key_from_jwk(jwk: &RawJwk) -> Result<VerifyingKey, TrustError> {
    if jwk.kty != "OKP" || jwk.crv != "Ed25519" {
        return Err(TrustError::UnsupportedAlgorithm {
            alg: format!("kty={} crv={}", jwk.kty, jwk.crv),
        });
    }
    let raw = URL_SAFE_NO_PAD
        .decode(&jwk.x)
        .map_err(|e| TrustError::DocumentInvalid {
            reason: format!("jwk x is not base64url: {e}"),
        })?;
    let bytes: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| TrustError::DocumentInvalid {
            reason: format!("jwk x is {} bytes, expected 32", raw.len()),
        })?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| TrustError::DocumentInvalid {
        reason: format!("jwk x is not a valid Ed25519 key: {e}"),
    })
}
```

- [ ] **Step 4: Register the module**

In `src/lib.rs`, add `pub mod document;` after `pub mod did;`, and add `pub use document::TrustDocument;` after the existing `pub use` lines.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --lib document`
Expected: PASS — 6 tests.

- [ ] **Step 6: Verify the binding check actually discriminates**

Comment out the `if raw.id != did.as_str()` block in `src/document.rs`, then:

```bash
git diff --stat            # MUST be non-empty — a mutation that cargo fmt reflowed into a no-op reads exactly like a passing test
cargo test --lib document
```

Expected: `rejects_a_document_whose_id_does_not_match_the_resolved_did` FAILS. Then restore the block with `git checkout src/document.rs` and re-run to confirm PASS.

- [ ] **Step 7: Commit**

```bash
git add src/document.rs src/lib.rs
git commit -m "feat: parse DID documents and enforce the did:web binding"
```

---

### Task 3: Publisher certificate verification

**Files:**
- Create: `src/cert.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: `TrustError` from Task 1.
- Produces:
  - `greentic_trust::cert::PublisherCert` — `serde` (de)serializable struct with public fields `publisher_public_key: String`, `root_signature: String`, `key_id: Option<String>`, `not_after: Option<String>` (JSON names `publisherPublicKey`, `rootSignature`, `keyId`, `notAfter`).
  - `PublisherCert::signed_bytes(&self) -> Result<Vec<u8>, TrustError>`
  - `PublisherCert::verify(&self, roots: &[VerifyingKey], now: DateTime<Utc>) -> Result<VerifyingKey, TrustError>`
  - `greentic_trust::cert::CERT_DOMAIN_V1: &[u8]`
  - Feature-gated (`testing`): `greentic_trust::cert::fixtures::{root_keypair, mint_cert}`.

**Background:** the existing `greentic-extension-sdk-contract::PublisherCert` signs only the raw 32-byte publisher key, so `keyId` and `notAfter` are unsigned and editable. No cert has ever been issued by anything, so this task replaces that scheme outright rather than versioning around it. The SDK's copy is left alone — S5 deletes it.

- [ ] **Step 1: Write the failing tests**

Create `src/cert.rs` containing only this test module for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone as _;
    use ed25519_dalek::{Signer as _, SigningKey};
    use rand::rngs::OsRng;

    fn at(rfc3339: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(rfc3339)
            .expect("valid timestamp")
            .with_timezone(&Utc)
    }

    /// Mint a cert the way S2's ceremony and S3's issuer will.
    fn mint(root: &SigningKey, publisher: &VerifyingKey, not_after: &str) -> PublisherCert {
        let mut cert = PublisherCert {
            publisher_public_key: B64.encode(publisher.as_bytes()),
            root_signature: String::new(),
            key_id: Some("pk_test_1".to_owned()),
            not_after: Some(not_after.to_owned()),
        };
        let signed = cert.signed_bytes().expect("builds signed bytes");
        cert.root_signature = B64.encode(root.sign(&signed).to_bytes());
        cert
    }

    fn setup() -> (SigningKey, SigningKey, PublisherCert) {
        let root = SigningKey::generate(&mut OsRng);
        let publisher = SigningKey::generate(&mut OsRng);
        let cert = mint(&root, &publisher.verifying_key(), "2030-01-01T00:00:00Z");
        (root, publisher, cert)
    }

    #[test]
    fn verifies_a_well_formed_cert_and_returns_the_publisher_key() {
        let (root, publisher, cert) = setup();

        let key = cert
            .verify(&[root.verifying_key()], at("2026-07-16T00:00:00Z"))
            .expect("verifies");

        assert_eq!(key.as_bytes(), publisher.verifying_key().as_bytes());
    }

    #[test]
    fn rejects_a_cert_signed_by_a_different_root() {
        // This is the environment-isolation property: a research root must not
        // be able to sign something production accepts.
        let (_root_r, _publisher, cert) = setup();
        let root_p = SigningKey::generate(&mut OsRng);

        let error = cert
            .verify(&[root_p.verifying_key()], at("2026-07-16T00:00:00Z"))
            .expect_err("rejects");

        assert!(matches!(error, TrustError::CertSignatureInvalid));
    }

    #[test]
    fn rejects_a_cert_whose_expiry_was_edited_after_issuance() {
        // notAfter is inside the signed bytes, so extending a cert's life
        // invalidates the root signature rather than succeeding silently.
        let (root, _publisher, mut cert) = setup();
        cert.not_after = Some("2099-01-01T00:00:00Z".to_owned());

        let error = cert
            .verify(&[root.verifying_key()], at("2026-07-16T00:00:00Z"))
            .expect_err("rejects");

        assert!(matches!(error, TrustError::CertSignatureInvalid));
    }

    #[test]
    fn rejects_a_cert_whose_key_id_was_edited_after_issuance() {
        let (root, _publisher, mut cert) = setup();
        cert.key_id = Some("pk_other".to_owned());

        let error = cert
            .verify(&[root.verifying_key()], at("2026-07-16T00:00:00Z"))
            .expect_err("rejects");

        assert!(matches!(error, TrustError::CertSignatureInvalid));
    }

    #[test]
    fn rejects_an_expired_cert() {
        let root = SigningKey::generate(&mut OsRng);
        let publisher = SigningKey::generate(&mut OsRng);
        let cert = mint(&root, &publisher.verifying_key(), "2026-01-01T00:00:00Z");

        let error = cert
            .verify(&[root.verifying_key()], at("2026-07-16T00:00:00Z"))
            .expect_err("rejects");

        assert!(matches!(error, TrustError::CertExpired { .. }));
    }

    #[test]
    fn treats_a_cert_exactly_at_not_after_as_expired() {
        // Valid iff now < notAfter. The boundary goes the fail-closed way.
        let root = SigningKey::generate(&mut OsRng);
        let publisher = SigningKey::generate(&mut OsRng);
        let cert = mint(&root, &publisher.verifying_key(), "2026-07-16T00:00:00Z");

        let error = cert
            .verify(&[root.verifying_key()], at("2026-07-16T00:00:00Z"))
            .expect_err("rejects");

        assert!(matches!(error, TrustError::CertExpired { .. }));
    }

    #[test]
    fn rejects_a_cert_with_no_expiry() {
        // A cert with no notAfter is a permanent grant, and revocation in this
        // design is expiry.
        let (root, _publisher, mut cert) = setup();
        cert.not_after = None;

        let error = cert
            .verify(&[root.verifying_key()], at("2026-07-16T00:00:00Z"))
            .expect_err("rejects");

        assert!(matches!(error, TrustError::CertMissingExpiry));
    }

    #[test]
    fn rejects_a_cert_with_no_key_id() {
        let (root, _publisher, mut cert) = setup();
        cert.key_id = None;

        let error = cert
            .verify(&[root.verifying_key()], at("2026-07-16T00:00:00Z"))
            .expect_err("rejects");

        assert!(matches!(error, TrustError::CertMissingKeyId));
    }

    #[test]
    fn rejects_a_root_signature_that_omits_the_domain_prefix() {
        // Without domain separation, any root signature over canonical JSON
        // could be replayed as a cert.
        let root = SigningKey::generate(&mut OsRng);
        let publisher = SigningKey::generate(&mut OsRng);
        let mut cert = PublisherCert {
            publisher_public_key: B64.encode(publisher.verifying_key().as_bytes()),
            root_signature: String::new(),
            key_id: Some("pk_test_1".to_owned()),
            not_after: Some("2030-01-01T00:00:00Z".to_owned()),
        };
        let undomained = serde_jcs::to_vec(&serde_json::json!({
            "publisherPublicKey": cert.publisher_public_key,
            "keyId": "pk_test_1",
            "notAfter": "2030-01-01T00:00:00Z",
        }))
        .expect("canonicalizes");
        cert.root_signature = B64.encode(root.sign(&undomained).to_bytes());

        let error = cert
            .verify(&[root.verifying_key()], at("2026-07-16T00:00:00Z"))
            .expect_err("rejects");

        assert!(matches!(error, TrustError::CertSignatureInvalid));
    }

    #[test]
    fn rejects_an_empty_root_set() {
        let (_root, _publisher, cert) = setup();

        let error = cert
            .verify(&[], at("2026-07-16T00:00:00Z"))
            .expect_err("rejects");

        assert!(matches!(error, TrustError::CertSignatureInvalid));
    }

    #[test]
    fn rejects_a_malformed_expiry_rather_than_treating_it_as_absent() {
        let root = SigningKey::generate(&mut OsRng);
        let publisher = SigningKey::generate(&mut OsRng);
        let cert = mint(&root, &publisher.verifying_key(), "not-a-date");

        let error = cert
            .verify(&[root.verifying_key()], at("2026-07-16T00:00:00Z"))
            .expect_err("rejects");

        assert!(matches!(error, TrustError::CertInvalid { .. }));
    }

    #[test]
    fn signed_bytes_start_with_the_domain_prefix() {
        let (_root, _publisher, cert) = setup();
        let bytes = cert.signed_bytes().expect("builds");
        assert!(bytes.starts_with(CERT_DOMAIN_V1));
    }

    #[test]
    fn round_trips_through_json_with_camel_case_names() {
        let (_root, _publisher, cert) = setup();
        let json = serde_json::to_value(&cert).expect("serializes");
        assert!(json.get("publisherPublicKey").is_some());
        assert!(json.get("rootSignature").is_some());
        assert!(json.get("keyId").is_some());
        assert!(json.get("notAfter").is_some());

        let back: PublisherCert = serde_json::from_value(json).expect("deserializes");
        assert_eq!(back, cert);
    }
}
```

`DateTime::parse_from_rfc3339` and `.with_timezone` are inherent, so no `chrono::TimeZone` import is needed here. `B64`, `DateTime`, `Utc` and `VerifyingKey` all arrive through `use super::*`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib cert`
Expected: FAIL — `cannot find type PublisherCert in this scope`.

- [ ] **Step 3: Implement `cert`**

Prepend to `src/cert.rs`, above the test module:

```rust
//! Publisher certificates: a root signature over a publisher's Ed25519 key,
//! bound to a key id and an expiry.
//!
//! ## What the root signs
//!
//! ```text
//! greentic-publisher-cert-v1\x00 || JCS({publisherPublicKey, keyId, notAfter})
//! ```
//!
//! The prefix is domain separation: without it a root signature is merely a
//! signature over some canonical JSON, and anything else JSON-shaped this root
//! ever signs could be replayed as a cert. `keyId` and `notAfter` are inside the
//! signed bytes so neither can be edited after issuance — an unsigned expiry is
//! an expiry an attacker can extend.
//!
//! This replaces the scheme in `greentic-extension-sdk-contract`, which signs
//! only the raw publisher key and leaves both fields unsigned. Nothing has ever
//! issued a cert, so there is nothing in the wild to keep compatible with.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::TrustError;

/// Domain-separation prefix for v1 publisher-certificate signatures.
pub const CERT_DOMAIN_V1: &[u8] = b"greentic-publisher-cert-v1\x00";

/// A root-signed attestation binding a publisher's Ed25519 key to an expiry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublisherCert {
    /// Standard-base64 of the publisher's 32-byte Ed25519 public key.
    #[serde(rename = "publisherPublicKey")]
    pub publisher_public_key: String,
    /// Standard-base64 of the root's 64-byte signature over [`Self::signed_bytes`].
    #[serde(rename = "rootSignature")]
    pub root_signature: String,
    /// Identifier of the publisher key this cert vouches for. Required by
    /// [`Self::verify`]; `Option` only so a malformed cert deserializes and is
    /// rejected with a precise error rather than a serde message.
    #[serde(rename = "keyId", default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// RFC3339 expiry. Required by [`Self::verify`]; see [`Self::key_id`].
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
}

impl PublisherCert {
    /// The exact bytes the root signs.
    ///
    /// # Errors
    /// [`TrustError::CertMissingKeyId`] or [`TrustError::CertMissingExpiry`] if
    /// either required field is absent; [`TrustError::Canonicalize`] if JCS fails.
    pub fn signed_bytes(&self) -> Result<Vec<u8>, TrustError> {
        let key_id = self.key_id.as_deref().ok_or(TrustError::CertMissingKeyId)?;
        let not_after = self
            .not_after
            .as_deref()
            .ok_or(TrustError::CertMissingExpiry)?;

        let body = serde_json::json!({
            "publisherPublicKey": self.publisher_public_key,
            "keyId": key_id,
            "notAfter": not_after,
        });
        let canonical =
            serde_jcs::to_vec(&body).map_err(|source| TrustError::Canonicalize { source })?;

        let mut out = Vec::with_capacity(CERT_DOMAIN_V1.len() + canonical.len());
        out.extend_from_slice(CERT_DOMAIN_V1);
        out.extend_from_slice(&canonical);
        Ok(out)
    }

    /// Verify this cert chains to one of `roots` and has not expired at `now`.
    ///
    /// Returns the publisher key the root vouched for.
    ///
    /// The signature is checked **before** the expiry is enforced. Both fields
    /// are inside the signed bytes, so a tampered `notAfter` fails as a bad
    /// signature; enforcing expiry first would report a misleading error for
    /// what is really a forgery.
    ///
    /// An empty `roots` trusts nobody and fails closed.
    ///
    /// # Errors
    /// [`TrustError::CertSignatureInvalid`] if no root validates;
    /// [`TrustError::CertExpired`] if `now >= notAfter`;
    /// [`TrustError::CertInvalid`] on any decode or timestamp failure;
    /// [`TrustError::CertMissingKeyId`] / [`TrustError::CertMissingExpiry`].
    pub fn verify(
        &self,
        roots: &[VerifyingKey],
        now: DateTime<Utc>,
    ) -> Result<VerifyingKey, TrustError> {
        let signed = self.signed_bytes()?;

        let publisher_key = decode_publisher_key(&self.publisher_public_key)?;
        let signature = decode_signature(&self.root_signature)?;

        // `verify_strict` rejects small-order components, matching the runner's
        // existing store-pull check. An empty `roots` makes `any` false, which
        // is the fail-closed answer.
        if !roots
            .iter()
            .any(|root| root.verify_strict(&signed, &signature).is_ok())
        {
            return Err(TrustError::CertSignatureInvalid);
        }

        let not_after = self
            .not_after
            .as_deref()
            .ok_or(TrustError::CertMissingExpiry)?;
        let expiry = DateTime::parse_from_rfc3339(not_after)
            .map_err(|e| TrustError::CertInvalid {
                reason: format!("notAfter is not RFC3339: {e}"),
            })?
            .with_timezone(&Utc);

        if now >= expiry {
            return Err(TrustError::CertExpired {
                not_after: expiry,
                now,
            });
        }

        Ok(publisher_key)
    }
}

fn decode_publisher_key(encoded: &str) -> Result<VerifyingKey, TrustError> {
    let raw = B64.decode(encoded).map_err(|e| TrustError::CertInvalid {
        reason: format!("publisherPublicKey is not base64: {e}"),
    })?;
    let bytes: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| TrustError::CertInvalid {
            reason: format!("publisherPublicKey is {} bytes, expected 32", raw.len()),
        })?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| TrustError::CertInvalid {
        reason: format!("publisherPublicKey is not a valid Ed25519 key: {e}"),
    })
}

fn decode_signature(encoded: &str) -> Result<Signature, TrustError> {
    let raw = B64.decode(encoded).map_err(|e| TrustError::CertInvalid {
        reason: format!("rootSignature is not base64: {e}"),
    })?;
    let bytes: [u8; 64] = raw
        .as_slice()
        .try_into()
        .map_err(|_| TrustError::CertInvalid {
            reason: format!("rootSignature is {} bytes, expected 64", raw.len()),
        })?;
    Ok(Signature::from_bytes(&bytes))
}

/// Fixture helpers for downstream crates' tests. Never compiled into a
/// production build unless the `testing` feature is explicitly enabled.
#[cfg(any(test, feature = "testing"))]
pub mod fixtures {
    use super::{B64, PublisherCert};
    use base64::Engine as _;
    use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};

    /// Generate a root keypair for tests.
    #[must_use]
    pub fn root_keypair() -> SigningKey {
        SigningKey::generate(&mut rand::rngs::OsRng)
    }

    /// Mint a cert the way S2's ceremony and S3's issuer will.
    ///
    /// # Panics
    /// Panics if the cert body cannot be canonicalized. Test-only.
    #[must_use]
    pub fn mint_cert(
        root: &SigningKey,
        publisher: &VerifyingKey,
        key_id: &str,
        not_after: &str,
    ) -> PublisherCert {
        let mut cert = PublisherCert {
            publisher_public_key: B64.encode(publisher.as_bytes()),
            root_signature: String::new(),
            key_id: Some(key_id.to_owned()),
            not_after: Some(not_after.to_owned()),
        };
        let signed = cert
            .signed_bytes()
            .expect("fixture cert body canonicalizes");
        cert.root_signature = B64.encode(root.sign(&signed).to_bytes());
        cert
    }
}
```

- [ ] **Step 4: Register the module**

In `src/lib.rs`, add `pub mod cert;` after `pub mod did;`, and `pub use cert::PublisherCert;` to the `pub use` block.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --lib cert && cargo clippy --all-targets --all-features -- -D warnings`
Expected: PASS — 13 tests, no clippy warnings. Delete any import clippy reports as unused.

- [ ] **Step 6: Verify the domain prefix actually discriminates**

Change `CERT_DOMAIN_V1` to `b""`, then:

```bash
git diff --stat            # MUST be non-empty
cargo test --lib cert
```

Expected: `rejects_a_root_signature_that_omits_the_domain_prefix` FAILS. Restore with `git checkout src/cert.rs` and re-run to confirm PASS.

- [ ] **Step 7: Verify the expiry boundary actually discriminates**

Change `if now >= expiry` to `if now > expiry`, then:

```bash
git diff --stat            # MUST be non-empty
cargo test --lib cert
```

Expected: `treats_a_cert_exactly_at_not_after_as_expired` FAILS. Restore and re-run to confirm PASS.

- [ ] **Step 8: Commit**

```bash
git add src/cert.rs src/lib.rs
git commit -m "feat: verify publisher certificates with signed expiry and domain separation"
```

---

### Task 4: Root resolver with TTL cache

**Files:**
- Create: `src/resolver.rs`
- Modify: `src/lib.rs`
- Modify: `Cargo.toml` (add `async-trait`)

**Interfaces:**
- Consumes: `DidWeb` (Task 1), `TrustDocument` (Task 2), `TrustError` (Task 1).
- Produces:
  - `greentic_trust::resolver::RootResolver` — `#[async_trait] pub trait RootResolver: Send + Sync { async fn resolve(&self, did: &DidWeb) -> Result<Arc<TrustDocument>, TrustError>; }`
  - `greentic_trust::resolver::HttpResolver` with `HttpResolver::new(ttl: Duration, capacity: u64) -> Self` and `HttpResolver::allow_http(self) -> Self` (dev/test only).

- [ ] **Step 1: Add `async-trait` to `Cargo.toml`**

In `[dependencies]`, add: `async-trait = "0.1"`

- [ ] **Step 2: Write the failing tests**

Create `src/resolver.rs` containing only this test module for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn document_body(did: &str) -> serde_json::Value {
        let signing = SigningKey::generate(&mut OsRng);
        let x = URL_SAFE_NO_PAD.encode(signing.verifying_key().as_bytes());
        serde_json::json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": did,
            "verificationMethod": [{
                "id": format!("{did}#root-1"),
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": x, "use": "sig" },
            }],
            "assertionMethod": [format!("{did}#root-1")],
        })
    }

    /// Build a DidWeb pointing at the mock server, and the matching resolver.
    /// The mock serves plain HTTP, so the resolver must allow it explicitly.
    fn did_for(server: &MockServer) -> DidWeb {
        let authority = server
            .uri()
            .trim_start_matches("http://")
            .replace(':', "%3A");
        DidWeb::parse(&format!("did:web:{authority}")).expect("parses")
    }

    #[tokio::test]
    async fn fetches_and_caches_a_document() {
        let server = MockServer::start().await;
        let did = did_for(&server);
        Mock::given(method("GET"))
            .and(path("/.well-known/did.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(document_body(did.as_str())))
            .expect(1) // second resolve must be served from cache
            .mount(&server)
            .await;

        let resolver = HttpResolver::new(Duration::from_secs(600), 16).allow_http();

        let first = resolver.resolve(&did).await.expect("resolves");
        let second = resolver.resolve(&did).await.expect("resolves");

        assert!(Arc::ptr_eq(&first, &second));
    }

    #[tokio::test]
    async fn does_not_cache_failures() {
        // A transient outage must not lock verification out for a whole TTL.
        let server = MockServer::start().await;
        let did = did_for(&server);
        Mock::given(method("GET"))
            .and(path("/.well-known/did.json"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/.well-known/did.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(document_body(did.as_str())))
            .mount(&server)
            .await;

        let resolver = HttpResolver::new(Duration::from_secs(600), 16).allow_http();

        let first = resolver.resolve(&did).await;
        assert!(matches!(first, Err(TrustError::HttpStatus { code: 503 })));

        resolver.resolve(&did).await.expect("second attempt succeeds");
    }

    #[tokio::test]
    async fn surfaces_a_non_success_status() {
        let server = MockServer::start().await;
        let did = did_for(&server);
        Mock::given(method("GET"))
            .and(path("/.well-known/did.json"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let resolver = HttpResolver::new(Duration::from_secs(600), 16).allow_http();

        let error = resolver.resolve(&did).await.expect_err("rejects");
        assert!(matches!(error, TrustError::HttpStatus { code: 404 }));
    }

    #[tokio::test]
    async fn refuses_plain_http_by_default() {
        // `DidWeb` always derives an https:// URL, so the guard is reached only
        // via `allow_http`'s rewrite or a caller passing a URL in directly.
        // Exercise it at `fetch_bytes`, which is where the decision lives.
        let resolver = HttpResolver::new(Duration::from_secs(600), 16);

        let error = resolver
            .fetch_bytes("http://trust.greentic.cloud/.well-known/did.json")
            .await
            .expect_err("rejects");

        assert!(matches!(error, TrustError::InsecureScheme { .. }));
    }

    #[tokio::test]
    async fn propagates_the_binding_check() {
        let server = MockServer::start().await;
        let did = did_for(&server);
        Mock::given(method("GET"))
            .and(path("/.well-known/did.json"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(document_body("did:web:evil.example")),
            )
            .mount(&server)
            .await;

        let resolver = HttpResolver::new(Duration::from_secs(600), 16).allow_http();

        let error = resolver.resolve(&did).await.expect_err("rejects");
        assert!(matches!(error, TrustError::BindingMismatch { .. }));
    }
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test --lib resolver`
Expected: FAIL — `cannot find type HttpResolver in this scope`.

- [ ] **Step 4: Implement `resolver`**

Prepend to `src/resolver.rs`, above the test module:

```rust
//! Fetching and caching DID documents.
//!
//! [`RootResolver`] is a trait rather than a concrete type so a caller can
//! supply an offline implementation backed by a pinned document — that is how
//! air-gapped verification works without this crate owning a pin format.
//!
//! The cache mirrors `greentic-designer-admin`'s `JwksCache` and fixes two
//! things it gets wrong: it keys on the full DID rather than the host (two
//! issuers on one host would otherwise collide), and it uses `try_get_with`, so
//! concurrent misses collapse into one request instead of stampeding the origin.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use moka::future::Cache;

use crate::did::DidWeb;
use crate::document::TrustDocument;
use crate::error::TrustError;

/// Resolves a [`DidWeb`] to the document it names.
#[async_trait]
pub trait RootResolver: Send + Sync {
    /// Resolve `did` to its document.
    ///
    /// # Errors
    /// Any [`TrustError`] arising from fetching or parsing.
    async fn resolve(&self, did: &DidWeb) -> Result<Arc<TrustDocument>, TrustError>;
}

/// Fetches documents over HTTPS and caches them for a TTL.
#[derive(Debug, Clone)]
pub struct HttpResolver {
    cache: Cache<String, Arc<TrustDocument>>,
    http: reqwest::Client,
    allow_http: bool,
}

impl HttpResolver {
    /// Build a resolver caching up to `capacity` documents for `ttl`.
    #[must_use]
    pub fn new(ttl: Duration, capacity: u64) -> Self {
        Self {
            cache: Cache::builder()
                .max_capacity(capacity)
                .time_to_live(ttl)
                .build(),
            http: reqwest::Client::new(),
            allow_http: false,
        }
    }

    /// Permit plain HTTP. Development and tests only — this removes the only
    /// thing making a fetched root key trustworthy.
    #[must_use]
    pub fn allow_http(mut self) -> Self {
        self.allow_http = true;
        self
    }

    async fn fetch_bytes(&self, url: &str) -> Result<Vec<u8>, TrustError> {
        if !url.starts_with("https://") && !self.allow_http {
            return Err(TrustError::InsecureScheme {
                url: url.to_owned(),
            });
        }
        let response = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|source| TrustError::Fetch { source })?;

        let status = response.status();
        if !status.is_success() {
            return Err(TrustError::HttpStatus {
                code: status.as_u16(),
            });
        }
        response
            .bytes()
            .await
            .map(|body| body.to_vec())
            .map_err(|source| TrustError::Fetch { source })
    }
}

#[async_trait]
impl RootResolver for HttpResolver {
    async fn resolve(&self, did: &DidWeb) -> Result<Arc<TrustDocument>, TrustError> {
        // Keyed on the full DID, not the host: `did:web:h:a` and `did:web:h:b`
        // are different roots served from the same host.
        let key = did.as_str().to_owned();

        // `try_get_with` gives single-flight and, crucially, does not cache the
        // error — a failed fetch is retried on the next call rather than pinned
        // for a TTL.
        self.cache
            .try_get_with(key, async {
                let url = if self.allow_http {
                    did.document_url().replacen("https://", "http://", 1)
                } else {
                    did.document_url().to_owned()
                };
                let bytes = self.fetch_bytes(&url).await?;
                TrustDocument::parse(did, &bytes).map(Arc::new)
            })
            .await
            .map_err(|shared| match Arc::try_unwrap(shared) {
                Ok(error) => error,
                Err(shared) => TrustError::DocumentInvalid {
                    reason: shared.to_string(),
                },
            })
    }
}
```

Note on the `map_err`: `moka`'s `try_get_with` returns `Arc<E>` because one initializer's error is shared with every caller that coalesced onto it. `Arc::try_unwrap` recovers the owned error in the common single-caller case and falls back to a string-carrying variant when it is genuinely shared.

- [ ] **Step 5: Register the module**

In `src/lib.rs`, add `pub mod resolver;` and `pub use resolver::{HttpResolver, RootResolver};`.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test --lib resolver`
Expected: PASS — 5 tests.

- [ ] **Step 7: Verify the no-error-caching test actually discriminates**

Replace `try_get_with` with a get-then-insert that caches errors:

```rust
if let Some(hit) = self.cache.get(&key).await {
    return Ok(hit);
}
```
...followed by an unconditional `self.cache.insert(key, value).await` on both paths. Then:

```bash
git diff --stat            # MUST be non-empty
cargo test --lib resolver
```

Expected: `does_not_cache_failures` FAILS. Restore with `git checkout src/resolver.rs` and re-run to confirm PASS.

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml Cargo.lock src/resolver.rs src/lib.rs
git commit -m "feat: resolve did:web documents with a single-flight TTL cache"
```

---

### Task 5: Chain verification

**Files:**
- Create: `src/chain.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: everything from Tasks 1–4.
- Produces:
  - `greentic_trust::chain::verify_describe(describe: &serde_json::Value, trusted_did: &DidWeb, resolver: &dyn RootResolver, now: DateTime<Utc>) -> Result<VerifyingKey, TrustError>`

- [ ] **Step 1: Write the failing tests**

Create `src/chain.rs` containing only this test module for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::fixtures::{mint_cert, root_keypair};
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::{Signer as _, SigningKey};
    use rand::rngs::OsRng;
    use std::sync::Arc;

    const TRUSTED: &str = "did:web:trust.greentic.cloud";

    /// An offline resolver over a fixed document — exactly the shape S5's pin
    /// store will take.
    struct FixedResolver(Arc<TrustDocument>);

    #[async_trait::async_trait]
    impl RootResolver for FixedResolver {
        async fn resolve(&self, _did: &DidWeb) -> Result<Arc<TrustDocument>, TrustError> {
            Ok(Arc::clone(&self.0))
        }
    }

    fn resolver_for(root: &SigningKey) -> FixedResolver {
        let x = URL_SAFE_NO_PAD.encode(root.verifying_key().as_bytes());
        let body = serde_json::json!({
            "id": TRUSTED,
            "verificationMethod": [{
                "id": format!("{TRUSTED}#root-1"),
                "type": "JsonWebKey2020",
                "controller": TRUSTED,
                "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": x },
            }],
            "assertionMethod": [format!("{TRUSTED}#root-1")],
        });
        let did = DidWeb::parse(TRUSTED).expect("parses");
        let bytes = serde_json::to_vec(&body).expect("serializes");
        FixedResolver(Arc::new(
            TrustDocument::parse(&did, &bytes).expect("parses"),
        ))
    }

    fn at(rfc3339: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(rfc3339)
            .expect("valid timestamp")
            .with_timezone(&Utc)
    }

    /// Sign `describe` the way store-server does: JCS over the document minus
    /// its `signature` member, then inject the signature block.
    fn sign_describe(
        publisher: &SigningKey,
        cert: &crate::cert::PublisherCert,
        signing_key_override: Option<&SigningKey>,
    ) -> serde_json::Value {
        let unsigned = serde_json::json!({
            "metadata": { "id": "acme.widget", "version": "1.0.0" },
        });
        let message = serde_jcs::to_vec(&unsigned).expect("canonicalizes");
        let actual = signing_key_override.unwrap_or(publisher);
        let signature = actual.sign(&message);

        let mut describe = unsigned;
        if let Some(object) = describe.as_object_mut() {
            object.insert(
                "signature".to_owned(),
                serde_json::json!({
                    "algorithm": "ed25519",
                    "publicKey": B64.encode(actual.verifying_key().as_bytes()),
                    "value": B64.encode(signature.to_bytes()),
                    "certificate": serde_json::to_value(cert).expect("serializes"),
                }),
            );
        }
        describe
    }

    #[tokio::test]
    async fn verifies_a_well_formed_describe() {
        let root = root_keypair();
        let publisher = SigningKey::generate(&mut OsRng);
        let cert = mint_cert(
            &root,
            &publisher.verifying_key(),
            "pk_1",
            "2030-01-01T00:00:00Z",
        );
        let describe = sign_describe(&publisher, &cert, None);
        let did = DidWeb::parse(TRUSTED).expect("parses");

        let key = verify_describe(
            &describe,
            &did,
            &resolver_for(&root),
            at("2026-07-16T00:00:00Z"),
        )
        .await
        .expect("verifies");

        assert_eq!(key.as_bytes(), publisher.verifying_key().as_bytes());
    }

    #[tokio::test]
    async fn rejects_a_genuine_cert_attached_to_an_attacker_signed_describe() {
        // The attack this whole chain exists to stop: publisher A's real cert
        // is reused, but the describe is signed by the attacker's own key. The
        // cert verifies against the root and the signature verifies against the
        // attacker key — only the cert-to-signing-key bind catches it.
        let root = root_keypair();
        let publisher = SigningKey::generate(&mut OsRng);
        let attacker = SigningKey::generate(&mut OsRng);
        let cert = mint_cert(
            &root,
            &publisher.verifying_key(),
            "pk_1",
            "2030-01-01T00:00:00Z",
        );
        let describe = sign_describe(&publisher, &cert, Some(&attacker));
        let did = DidWeb::parse(TRUSTED).expect("parses");

        let error = verify_describe(
            &describe,
            &did,
            &resolver_for(&root),
            at("2026-07-16T00:00:00Z"),
        )
        .await
        .expect_err("rejects");

        assert!(matches!(error, TrustError::CertKeyMismatch { .. }));
    }

    #[tokio::test]
    async fn rejects_a_describe_with_no_signature_block() {
        let root = root_keypair();
        let describe = serde_json::json!({ "metadata": { "id": "acme.widget" } });
        let did = DidWeb::parse(TRUSTED).expect("parses");

        let error = verify_describe(
            &describe,
            &did,
            &resolver_for(&root),
            at("2026-07-16T00:00:00Z"),
        )
        .await
        .expect_err("rejects");

        assert!(matches!(error, TrustError::SignatureBlockMissing));
    }

    #[tokio::test]
    async fn rejects_a_signature_block_with_no_certificate() {
        let root = root_keypair();
        let publisher = SigningKey::generate(&mut OsRng);
        let describe = serde_json::json!({
            "metadata": { "id": "acme.widget" },
            "signature": {
                "algorithm": "ed25519",
                "publicKey": B64.encode(publisher.verifying_key().as_bytes()),
                "value": B64.encode([0_u8; 64]),
            },
        });
        let did = DidWeb::parse(TRUSTED).expect("parses");

        let error = verify_describe(
            &describe,
            &did,
            &resolver_for(&root),
            at("2026-07-16T00:00:00Z"),
        )
        .await
        .expect_err("rejects");

        assert!(matches!(error, TrustError::CertMissing));
    }

    #[tokio::test]
    async fn rejects_a_tampered_describe_body() {
        let root = root_keypair();
        let publisher = SigningKey::generate(&mut OsRng);
        let cert = mint_cert(
            &root,
            &publisher.verifying_key(),
            "pk_1",
            "2030-01-01T00:00:00Z",
        );
        let mut describe = sign_describe(&publisher, &cert, None);
        if let Some(object) = describe.as_object_mut() {
            object.insert(
                "metadata".to_owned(),
                serde_json::json!({ "id": "evil.widget", "version": "1.0.0" }),
            );
        }
        let did = DidWeb::parse(TRUSTED).expect("parses");

        let error = verify_describe(
            &describe,
            &did,
            &resolver_for(&root),
            at("2026-07-16T00:00:00Z"),
        )
        .await
        .expect_err("rejects");

        assert!(matches!(error, TrustError::DescribeSignatureInvalid));
    }

    #[tokio::test]
    async fn rejects_a_cert_from_another_environments_root() {
        let root_r = root_keypair();
        let root_p = root_keypair();
        let publisher = SigningKey::generate(&mut OsRng);
        let cert = mint_cert(
            &root_r,
            &publisher.verifying_key(),
            "pk_1",
            "2030-01-01T00:00:00Z",
        );
        let describe = sign_describe(&publisher, &cert, None);
        let did = DidWeb::parse(TRUSTED).expect("parses");

        let error = verify_describe(
            &describe,
            &did,
            &resolver_for(&root_p),
            at("2026-07-16T00:00:00Z"),
        )
        .await
        .expect_err("rejects");

        assert!(matches!(error, TrustError::CertSignatureInvalid));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib chain`
Expected: FAIL — `cannot find function verify_describe in this scope`.

- [ ] **Step 3: Implement `chain`**

Prepend to `src/chain.rs`, above the test module:

```rust
//! The verification entry point.
//!
//! Runs the six steps in the order the spec fixes, which is a security order
//! rather than a cost order:
//!
//! 1. Parse the signature block — absent is a rejection, never a skip.
//! 2. Resolve the trusted DID to its root key set.
//! 3. Verify the cert chains to one of those roots.
//! 4. Check the cert has not expired.
//! 5. Check the cert vouches for the key that actually signed.
//! 6. Verify the describe signature with that key.
//!
//! Steps 3–4 live inside [`PublisherCert::verify`]. Step 5 is the one that
//! carries the chain: without it, a genuine cert for one publisher can be
//! attached to an artifact signed by anybody.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};

use crate::cert::PublisherCert;
use crate::did::DidWeb;
use crate::document::TrustDocument;
use crate::error::TrustError;
use crate::resolver::RootResolver;

/// Verify that `describe` was signed by a publisher certified by the root
/// published at `trusted_did`.
///
/// Returns the certified publisher key on success.
///
/// # Errors
/// Any [`TrustError`]. Every failure is distinguishable; none is a silent pass.
pub async fn verify_describe(
    describe: &serde_json::Value,
    trusted_did: &DidWeb,
    resolver: &dyn RootResolver,
    now: DateTime<Utc>,
) -> Result<VerifyingKey, TrustError> {
    // 1. Signature block.
    let signature_object = describe
        .get("signature")
        .ok_or(TrustError::SignatureBlockMissing)?;

    let algorithm = signature_object
        .get("algorithm")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("ed25519");
    if !algorithm.eq_ignore_ascii_case("ed25519") {
        return Err(TrustError::UnsupportedAlgorithm {
            alg: algorithm.to_owned(),
        });
    }

    let signing_key_b64 = signature_object
        .get("publicKey")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| TrustError::CertInvalid {
            reason: "signature.publicKey missing or not a string".to_owned(),
        })?;
    let signature_b64 = signature_object
        .get("value")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| TrustError::CertInvalid {
            reason: "signature.value missing or not a string".to_owned(),
        })?;

    let cert_value = signature_object
        .get("certificate")
        .ok_or(TrustError::CertMissing)?;
    let cert: PublisherCert =
        serde_json::from_value(cert_value.clone()).map_err(|e| TrustError::CertInvalid {
            reason: format!("certificate is malformed: {e}"),
        })?;

    // 2. Resolve the root key set.
    let document: std::sync::Arc<TrustDocument> = resolver.resolve(trusted_did).await?;

    // 3 + 4. Cert chains to a root, and has not expired.
    let certified_key = cert.verify(document.assertion_keys(), now)?;

    // 5. The cert must vouch for the key that actually signed this describe.
    //    Comparing decoded key bytes, not the base64 text, so an equivalent
    //    re-encoding cannot slip past.
    let signing_key = decode_signing_key(signing_key_b64)?;
    if certified_key.as_bytes() != signing_key.as_bytes() {
        return Err(TrustError::CertKeyMismatch {
            cert_key: B64.encode(certified_key.as_bytes()),
            signing_key: B64.encode(signing_key.as_bytes()),
        });
    }

    // 6. The describe signature itself.
    //    Signed bytes are the describe minus `signature`, JCS-canonicalized —
    //    identical to what store-server signs and what the runner reconstructs.
    let mut unsigned = describe.clone();
    unsigned
        .as_object_mut()
        .ok_or_else(|| TrustError::CertInvalid {
            reason: "describe is not a JSON object".to_owned(),
        })?
        .remove("signature");
    let message =
        serde_jcs::to_vec(&unsigned).map_err(|source| TrustError::Canonicalize { source })?;

    let signature = decode_signature(signature_b64)?;
    certified_key
        .verify_strict(&message, &signature)
        .map_err(|_| TrustError::DescribeSignatureInvalid)?;

    Ok(certified_key)
}

fn decode_signing_key(encoded: &str) -> Result<VerifyingKey, TrustError> {
    let raw = B64
        .decode(encoded.trim())
        .map_err(|e| TrustError::CertInvalid {
            reason: format!("signature.publicKey is not base64: {e}"),
        })?;
    let bytes: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| TrustError::CertInvalid {
            reason: format!("signature.publicKey is {} bytes, expected 32", raw.len()),
        })?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| TrustError::CertInvalid {
        reason: format!("signature.publicKey is not a valid Ed25519 key: {e}"),
    })
}

fn decode_signature(encoded: &str) -> Result<Signature, TrustError> {
    let raw = B64
        .decode(encoded.trim())
        .map_err(|e| TrustError::CertInvalid {
            reason: format!("signature.value is not base64: {e}"),
        })?;
    let bytes: [u8; 64] = raw
        .as_slice()
        .try_into()
        .map_err(|_| TrustError::CertInvalid {
            reason: format!("signature.value is {} bytes, expected 64", raw.len()),
        })?;
    Ok(Signature::from_bytes(&bytes))
}
```

- [ ] **Step 4: Register the module and add `async-trait` to dev use**

In `src/lib.rs`, add `pub mod chain;` and `pub use chain::verify_describe;`.

- [ ] **Step 5: Run the whole suite**

Run: `cargo test --all-targets --all-features`
Expected: PASS — all tests across the five modules.

- [ ] **Step 6: Verify step 5 actually discriminates**

This is the single most important check in the plan. Comment out the `if certified_key.as_bytes() != signing_key.as_bytes()` block, and change the step-6 verification to use `signing_key` instead of `certified_key`:

```rust
signing_key
    .verify_strict(&message, &signature)
    .map_err(|_| TrustError::DescribeSignatureInvalid)?;
```

(Both edits are needed: leaving step 6 on `certified_key` would make the attack fail at step 6 for the wrong reason, which would mask that step 5 is gone.)

```bash
git diff --stat            # MUST be non-empty
cargo test --lib chain
```

Expected: `rejects_a_genuine_cert_attached_to_an_attacker_signed_describe` FAILS. Restore with `git checkout src/chain.rs` and re-run to confirm PASS.

- [ ] **Step 7: Verify lint and format**

Run: `cargo fmt --all -- --check && cargo clippy --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 8: Commit**

```bash
git add src/chain.rs src/lib.rs
git commit -m "feat: verify a describe chains to a did:web trust root"
```

---

### Task 6: Local CI script and README

**Files:**
- Create: `ci/local_check.sh`
- Create: `README.md`

**Interfaces:**
- Consumes: the finished crate.
- Produces: `bash ci/local_check.sh` as the canonical local gate, matching every other Greentic Rust repo.

- [ ] **Step 1: Create `ci/local_check.sh`**

```bash
#!/usr/bin/env bash
set -euo pipefail

# Canonical local CI gate for greentic-trust.
#   bash ci/local_check.sh

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

echo "==> cargo fmt"
cargo fmt --all -- --check

echo "==> cargo clippy"
cargo clippy --all-targets --all-features --locked -- -D warnings

echo "==> cargo test"
cargo test --all-targets --all-features --locked

echo "==> cargo doc"
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features --locked

echo "All checks passed."
```

- [ ] **Step 2: Make it executable and run it**

```bash
chmod +x ci/local_check.sh
bash ci/local_check.sh
```

Expected: `All checks passed.`

- [ ] **Step 3: Create `README.md`**

```markdown
# greentic-trust

did:web trust root and publisher certificate verification for Greentic.

Given a signed `describe`, a `PublisherCert`, and a trusted `did:web` identifier,
decide whether the artifact is authentic — or say precisely why not.

## The chain

```
did:web:trust.greentic.cloud/.well-known/did.json
└── root key (Ed25519, published as a static document)
         │ signs
         ▼
    PublisherCert { publisherPublicKey, rootSignature, keyId, notAfter }
         │ vouches for
         ▼
    publisher key
         │ signs
         ▼
    describe.json inside the .gtxpack
```

## Usage

```rust
use std::time::Duration;
use chrono::Utc;
use greentic_trust::{DidWeb, HttpResolver, verify_describe};

let did = DidWeb::parse("did:web:trust.greentic.cloud")?;
let resolver = HttpResolver::new(Duration::from_secs(600), 16);
let publisher_key = verify_describe(&describe, &did, &resolver, Utc::now()).await?;
```

The trusted DID is a **URL, not a secret** — it belongs in ordinary config.

## Environments

Each environment has its own root. A leaked research key must not be able to
sign something production accepts.

| Environment | DID |
|---|---|
| research | `did:web:trust.research.greentic.cloud` |
| staging | `did:web:trust.staging.greentic.cloud` |
| production | `did:web:trust.greentic.cloud` |

## Verify

```bash
bash ci/local_check.sh
```

## Design

`docs/superpowers/specs/2026-07-16-did-web-trust-root-design.md`
```

- [ ] **Step 4: Commit**

```bash
git add ci/local_check.sh README.md
git commit -m "chore: add local CI gate and README"
```

---

## Self-Review Notes

**Spec coverage:**

| Spec requirement | Task |
|---|---|
| `did` module — parse, URL derivation | 1 |
| `error` — one enum, every failure distinguishable, no `Skipped` | 1 |
| `document` — parse, binding enforcement, Ed25519 JWK | 2 |
| Reject non-Ed25519 (TM's P-256) loudly | 2 |
| `cert` — domain separation, signed `keyId`/`notAfter`, strict boundary | 3 |
| Required `keyId` and `notAfter` | 3 |
| `resolver` — trait, HTTPS, full-DID key, no error caching, single-flight | 4 |
| `chain` — six-step order, step-5 bind | 5 |
| Time as a parameter | 3, 5 |
| Every invariant has a mutation check | 2 (step 6), 3 (steps 6–7), 4 (step 7), 5 (step 6) |
| `bash ci/local_check.sh` | 6 |

**Deliberately not covered here** (spec's "out of scope for S1"): hosting the document (S2), store-server issuance (S3), runner wiring (S4), SDK re-anchor and pin store (S5), and the tenant-manager alias-host bug.

**Known gap carried forward:** the spec's environment-isolation invariant is tested at the `cert` and `chain` levels (a root-R cert rejected against root-P), which is the property that matters. Testing it against three *live* documents belongs to S2, which is what publishes them.

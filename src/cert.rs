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

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
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
        let canonical = serde_jcs::to_vec(&body).map_err(|source| TrustError::Canonicalize {
            source: Arc::new(source),
        })?;

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
    use super::{PublisherCert, B64};
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

#[cfg(test)]
mod tests {
    use super::fixtures::mint_cert;
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};
    use rand::rngs::OsRng;

    fn at(rfc3339: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(rfc3339)
            .expect("valid timestamp")
            .with_timezone(&Utc)
    }

    /// Mint via the same `fixtures::mint_cert` that S2's ceremony, S3's issuer,
    /// and Task 5's tests use. One definition of "how a cert is made": if the
    /// fixture drifts from `signed_bytes`, these tests are what catches it.
    fn mint(root: &SigningKey, publisher: &VerifyingKey, not_after: &str) -> PublisherCert {
        mint_cert(root, publisher, "pk_test_1", not_after)
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
        assert_eq!(CERT_DOMAIN_V1, b"greentic-publisher-cert-v1\x00");
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

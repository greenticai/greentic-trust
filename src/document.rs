//! Parsing a fetched DID document into the set of keys it authorizes for
//! assertions.
//!
//! The binding check here is the whole security value of did:web: a document is
//! authoritative only for the DID whose URL served it, so its `id` must equal
//! the identifier we resolved. Everything else is shape validation.

use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
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
        let raw: RawDocument =
            serde_json::from_slice(bytes).map_err(|source| TrustError::DocumentParse {
                source: Arc::new(source),
            })?;

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

#[cfg(test)]
mod tests {
    use super::*;
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

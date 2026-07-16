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
//! Steps 3–4 live inside [`PublisherCert::verify`]. The invariant that must
//! never be relaxed is step 6: it verifies against `certified_key`, the key
//! the cert vouches for, never against the describe's self-asserted
//! `signature.publicKey`. That is what closes the hole Greentic's SDK has —
//! the SDK verifies against the self-asserted key, so a genuine cert for one
//! publisher can be attached to an artifact signed by anybody. Step 5 is
//! defense in depth: it catches the very same substitution one step earlier
//! and turns it into a precise [`TrustError::CertKeyMismatch`] naming both
//! keys, instead of letting it fall through to a generic
//! [`TrustError::DescribeSignatureInvalid`] out of step 6. The redundancy
//! between them is deliberate, not accidental — each is independently
//! sufficient to catch the attack.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
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
    // 0. `describe` must be a JSON object before anything else can be read
    //    from or removed out of it.
    describe
        .as_object()
        .ok_or_else(|| TrustError::DescribeInvalid {
            reason: "describe is not a JSON object".to_owned(),
        })?;

    // 1. Signature block.
    let signature_object = describe
        .get("signature")
        .ok_or(TrustError::SignatureBlockMissing)?;

    let algorithm = match signature_object.get("algorithm") {
        None => "ed25519".to_owned(),
        Some(value) => value
            .as_str()
            .ok_or_else(|| TrustError::UnsupportedAlgorithm {
                alg: value.to_string(),
            })?
            .to_owned(),
    };
    if !algorithm.eq_ignore_ascii_case("ed25519") {
        return Err(TrustError::UnsupportedAlgorithm { alg: algorithm });
    }

    let signing_key_b64 = signature_object
        .get("publicKey")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| TrustError::DescribeInvalid {
            reason: "signature.publicKey missing or not a string".to_owned(),
        })?;
    let signature_b64 = signature_object
        .get("value")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| TrustError::DescribeInvalid {
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
    //    `describe` was already proven to be a JSON object in step 0, so this
    //    clone is always `Value::Object` too.
    let mut unsigned = describe.clone();
    if let Some(object) = unsigned.as_object_mut() {
        object.remove("signature");
    }
    let message = serde_jcs::to_vec(&unsigned).map_err(|source| TrustError::Canonicalize {
        source: std::sync::Arc::new(source),
    })?;

    let signature = decode_signature(signature_b64)?;
    certified_key
        .verify_strict(&message, &signature)
        .map_err(|_| TrustError::DescribeSignatureInvalid)?;

    Ok(certified_key)
}

fn decode_signing_key(encoded: &str) -> Result<VerifyingKey, TrustError> {
    let raw = B64
        .decode(encoded.trim())
        .map_err(|e| TrustError::DescribeInvalid {
            reason: format!("signature.publicKey is not base64: {e}"),
        })?;
    let bytes: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| TrustError::DescribeInvalid {
            reason: format!("signature.publicKey is {} bytes, expected 32", raw.len()),
        })?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| TrustError::DescribeInvalid {
        reason: format!("signature.publicKey is not a valid Ed25519 key: {e}"),
    })
}

fn decode_signature(encoded: &str) -> Result<Signature, TrustError> {
    let raw = B64
        .decode(encoded.trim())
        .map_err(|e| TrustError::DescribeInvalid {
            reason: format!("signature.value is not base64: {e}"),
        })?;
    let bytes: [u8; 64] = raw
        .as_slice()
        .try_into()
        .map_err(|_| TrustError::DescribeInvalid {
            reason: format!("signature.value is {} bytes, expected 64", raw.len()),
        })?;
    Ok(Signature::from_bytes(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::fixtures::{mint_cert, root_keypair};
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

    #[tokio::test]
    async fn rejects_an_expired_cert_using_the_caller_supplied_now() {
        // The cert expires 2030-01-01. Passing a `now` from *after* that date
        // can only happen because `now` is threaded in by the caller, never
        // read off the wall clock inside the crate — a real `Utc::now()` call
        // here could not produce a future timestamp. This is what pins step
        // 4's expiry delegation and the "no Utc::now() inside the crate"
        // constraint at this layer.
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

        let error = verify_describe(
            &describe,
            &did,
            &resolver_for(&root),
            at("2031-01-01T00:00:00Z"),
        )
        .await
        .expect_err("rejects");

        assert!(matches!(error, TrustError::CertExpired { .. }));
    }

    #[tokio::test]
    async fn rejects_a_non_string_algorithm() {
        let root = root_keypair();
        let publisher = SigningKey::generate(&mut OsRng);
        let cert = mint_cert(
            &root,
            &publisher.verifying_key(),
            "pk_1",
            "2030-01-01T00:00:00Z",
        );
        let describe = serde_json::json!({
            "metadata": { "id": "acme.widget", "version": "1.0.0" },
            "signature": {
                "algorithm": 42,
                "publicKey": B64.encode(publisher.verifying_key().as_bytes()),
                "value": B64.encode([0_u8; 64]),
                "certificate": serde_json::to_value(&cert).expect("serializes"),
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

        assert!(matches!(error, TrustError::UnsupportedAlgorithm { .. }));
    }

    #[tokio::test]
    async fn rejects_a_non_object_describe() {
        let root = root_keypair();
        let describe = serde_json::json!(["not", "an", "object"]);
        let did = DidWeb::parse(TRUSTED).expect("parses");

        let error = verify_describe(
            &describe,
            &did,
            &resolver_for(&root),
            at("2026-07-16T00:00:00Z"),
        )
        .await
        .expect_err("rejects");

        assert!(matches!(error, TrustError::DescribeInvalid { .. }));
    }
}

//! Ceremony operations: generate a root key and build the did.json document.
//!
//! Always compiled, because these define the *mint* side of the same wire
//! format the rest of the crate verifies. `build_document` produces exactly the
//! bytes [`crate::document::TrustDocument::parse`] accepts, and a round-trip
//! test pins that — co-locating build and parse in one crate is what keeps them
//! from drifting.
//!
//! `mint_cert` (the cert *mint*), `generate_root`, and `build_document` all
//! live here as the always-compiled mint side of the wire format the rest of
//! the crate verifies.

use base64::engine::general_purpose::STANDARD as B64;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use serde_json::json;

use crate::cert::PublisherCert;
use crate::did::DidWeb;
use crate::document::ServiceEntry;
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

/// Build the `did.json` document for `did`, carrying one or more root keys and
/// an optional set of service entries.
///
/// More than one key appears only during a root-rotation overlap, so an old and
/// a new root are both valid while the TTL drains. Each key becomes one
/// `verificationMethod` with id `{did}#root-{n}` (n from 1) and one
/// `assertionMethod` reference — the two members the verifier reads — with a JWK
/// of `kty=OKP, crv=Ed25519, x=URL_SAFE_NO_PAD(pubkey)`.
///
/// `services` is emitted as a `service` key only when non-empty, so existing
/// documents that carry no services are byte-identical to what the old
/// zero-service signature produced.
///
/// # Errors
/// [`TrustError::DocumentInvalid`] if `roots` is empty.
pub fn build_document(
    did: &DidWeb,
    roots: &[VerifyingKey],
    services: &[ServiceEntry],
) -> Result<serde_json::Value, TrustError> {
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

    // Only `assertionMethod`: a root key exists to sign publisher certs, which
    // is an assertion. It is deliberately NOT in `authentication` — that
    // relationship proves control *as the DID subject*, a capability a signing
    // root has no business advertising to a third-party did:web resolver.
    let mut doc = json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
        ],
        "id": id,
        "verificationMethod": methods,
        "assertionMethod": assertions,
    });

    // Emit `service` only when non-empty so existing zero-service documents
    // remain byte-identical.
    if !services.is_empty() {
        let service_array: Vec<serde_json::Value> = services
            .iter()
            .map(|s| {
                json!({
                    "id": s.id,
                    "type": s.service_type,
                    "serviceEndpoint": s.service_endpoint,
                })
            })
            .collect();
        doc["service"] = json!(service_array);
    }

    Ok(doc)
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did::DidWeb;
    use crate::document::TrustDocument;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
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

        let doc = build_document(&did, &[root.verifying_key()], &[]).expect("builds");
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
        let doc = build_document(&did, &[root.verifying_key()], &[]).expect("builds");
        assert_eq!(doc["id"], serde_json::json!(DID));
    }

    #[test]
    fn multi_key_document_carries_every_root() {
        // Used only during a root-rotation overlap: old + new root both valid.
        let a = seeded_root(3);
        let b = seeded_root(4);
        let did = DidWeb::parse(DID).expect("parses");

        let doc =
            build_document(&did, &[a.verifying_key(), b.verifying_key()], &[]).expect("builds");
        let bytes = serde_json::to_vec(&doc).expect("serializes");
        let parsed = TrustDocument::parse(&did, &bytes).expect("verifier accepts it");

        assert_eq!(parsed.assertion_keys().len(), 2);
        let keys: Vec<_> = parsed
            .assertion_keys()
            .iter()
            .map(|k| *k.as_bytes())
            .collect();
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

        let doc = build_document(&did, &[root.verifying_key()], &[]).expect("builds");
        assert_eq!(
            doc["verificationMethod"][0]["publicKeyJwk"]["x"],
            serde_json::json!(x_url)
        );
    }

    #[test]
    fn empty_roots_is_rejected() {
        let did = DidWeb::parse(DID).expect("parses");
        let error = build_document(&did, &[], &[]).expect_err("rejects");
        assert!(matches!(error, TrustError::DocumentInvalid { .. }));
    }

    #[test]
    fn generate_root_is_deterministic_for_a_fixed_seed() {
        // Same seed -> same key; different seed -> different key. Asserting an
        // exact hardcoded x would be fragile against StdRng algorithm changes.
        assert_eq!(seeded_root(9).to_bytes(), seeded_root(9).to_bytes());
        assert_ne!(seeded_root(9).to_bytes(), seeded_root(10).to_bytes());
    }

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
        let cert = mint_cert(
            &root,
            &publisher.verifying_key(),
            "pk_test_1",
            "2030-01-01T00:00:00Z",
        )
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
        let cert = mint_cert(
            &root,
            &publisher.verifying_key(),
            "pk_test_1",
            "2030-01-01T00:00:00Z",
        )
        .expect("mints");

        let error = cert
            .verify(&[other.verifying_key()], at("2026-07-17T00:00:00Z"))
            .expect_err("a cert signed by root must not verify against a different root");
        assert!(matches!(error, TrustError::CertSignatureInvalid));
    }

    #[test]
    fn build_document_with_no_services_emits_no_service_key() {
        // Byte-compat: existing documents that carried no services must be
        // identical to what the old zero-argument build_document produced.
        let root = seeded_root(20);
        let did = DidWeb::parse(DID).expect("parses");
        let doc = build_document(&did, &[root.verifying_key()], &[]).expect("builds");
        assert!(
            doc.get("service").is_none(),
            "empty services must not emit a service key"
        );
    }

    #[test]
    fn build_document_with_services_round_trips_through_the_verifier() {
        let root = seeded_root(21);
        let did = DidWeb::parse(DID).expect("parses");
        let services = vec![ServiceEntry {
            id: format!("{DID}#updates"),
            service_type: "GreenticUpdateEndpoint".to_owned(),
            service_endpoint: "https://updates.greentic.cloud".to_owned(),
        }];

        let doc = build_document(&did, &[root.verifying_key()], &services).expect("builds");
        let bytes = serde_json::to_vec(&doc).expect("serializes");
        let parsed = TrustDocument::parse(&did, &bytes).expect("verifier accepts it");

        assert_eq!(parsed.assertion_keys().len(), 1);
        assert_eq!(parsed.services().len(), 1);
        assert_eq!(parsed.services()[0].id, format!("{DID}#updates"));
        assert_eq!(parsed.services()[0].service_type, "GreenticUpdateEndpoint");
        assert_eq!(
            parsed.services()[0].service_endpoint,
            "https://updates.greentic.cloud"
        );
    }
}

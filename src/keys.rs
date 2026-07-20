//! Key utility functions: Greentic key id derivation and SPKI PEM export.
//!
//! The key id is the canonical address of a public key across Greentic's signing
//! subsystems — the same derivation used by `greentic-distributor-client` and
//! `packc`. Keeping it in `greentic-trust` means the trust chain (DID document
//! root key -> key id -> trust-root.json pin) can be built without pulling in
//! the full distributor or pack crate.
//!
//! The SPKI PEM export produces the `-----BEGIN PUBLIC KEY-----` format
//! `trust-root.json` stores keys in, round-tripping through the same
//! `from_public_key_pem` that the trust-root loader uses.

use ed25519_dalek::pkcs8::spki::EncodePublicKey;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

/// Derive a Greentic key id from an Ed25519 public key.
///
/// The derivation is `hex(sha256(raw_32_byte_public_key)[..16])` — the first 16
/// bytes of the SHA-256 digest, lowercase hex-encoded, yielding a 32-character
/// hex string. This matches the canonical derivation in
/// `greentic-distributor-client::signing::key_id_for_verifying_key` and is
/// stable across all Greentic signing subsystems.
#[must_use]
pub fn greentic_key_id(key: &VerifyingKey) -> String {
    let digest = Sha256::digest(key.to_bytes());
    hex::encode(&digest[..16])
}

/// Export an Ed25519 public key as an SPKI PEM string
/// (`-----BEGIN PUBLIC KEY-----`).
///
/// This is the format `trust-root.json` stores pinned keys in and the format
/// `greentic-distributor-client` accepts via `key_id_for_public_key_pem`. Using
/// ed25519-dalek's PKCS#8/SPKI support directly avoids hand-rolling DER
/// encoding.
///
/// # Errors
/// Returns an error string if SPKI encoding fails (should not happen for a
/// valid `VerifyingKey`, but the underlying API is fallible).
pub fn spki_pem(key: &VerifyingKey) -> Result<String, String> {
    key.to_public_key_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
        .map_err(|e| format!("SPKI PEM encoding failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::pkcs8::spki::DecodePublicKey;
    use ed25519_dalek::SigningKey;

    /// Deterministic key from a fixed seed, matching the convention in
    /// `greentic-distributor-client`'s tests.
    fn key_from_seed(seed: u8) -> VerifyingKey {
        SigningKey::from_bytes(&[seed; 32]).verifying_key()
    }

    #[test]
    fn key_id_is_32_lowercase_hex_chars() {
        let id = greentic_key_id(&key_from_seed(1));
        assert_eq!(id.len(), 32, "key id must be 32 hex characters");
        assert!(
            id.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "key id must be lowercase hex: {id}"
        );
    }

    #[test]
    fn key_id_matches_known_derivation_vector() {
        // A FROZEN vector, deliberately not re-derived here.
        //
        // Re-computing the expectation with the same algorithm the function uses
        // only proves the code agrees with itself: change the implementation and
        // the expectation changes with it, silently. This key id must agree with
        // `greentic-distributor-client`'s canonical derivation
        // (`hex::encode(&digest[..16])` in its `signing` module), because the
        // verifier matches a DSSE signature's `keyid` against the trust root by
        // exact string equality — a divergence here does not fail loudly, it
        // just stops every signature from ever matching.
        //
        // Vector: Ed25519 key from seed [1; 32]. Cross-checked against an
        // independent SHA-256 implementation outside this crate.
        let vk = key_from_seed(1);
        assert_eq!(
            hex::encode(vk.to_bytes()),
            "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
            "seed [1; 32] no longer produces the public key this vector was cut from"
        );
        assert_eq!(greentic_key_id(&vk), "34750f98bd59fcfc946da45aaabe933b");
    }

    #[test]
    fn different_keys_produce_different_key_ids() {
        assert_ne!(
            greentic_key_id(&key_from_seed(1)),
            greentic_key_id(&key_from_seed(2))
        );
    }

    #[test]
    fn spki_pem_round_trips_back_to_the_same_key() {
        let vk = key_from_seed(42);
        let pem = spki_pem(&vk).expect("encodes");
        let recovered = VerifyingKey::from_public_key_pem(&pem).expect("decodes");
        assert_eq!(vk.to_bytes(), recovered.to_bytes());
    }

    #[test]
    fn spki_pem_output_starts_with_the_standard_header() {
        let pem = spki_pem(&key_from_seed(1)).expect("encodes");
        assert!(
            pem.starts_with("-----BEGIN PUBLIC KEY-----"),
            "must be SPKI PEM, got: {pem}"
        );
    }

    #[test]
    fn spki_pem_parses_with_the_same_code_path_the_trust_root_loader_uses() {
        // The trust-root loader in greentic-distributor-client uses
        // `VerifyingKey::from_public_key_pem`. This test pins that our export
        // is accepted by that exact code path.
        let vk = key_from_seed(99);
        let pem = spki_pem(&vk).expect("encodes");
        let decoded = VerifyingKey::from_public_key_pem(&pem)
            .expect("from_public_key_pem must accept our export");
        assert_eq!(vk.to_bytes(), decoded.to_bytes());
    }

    #[test]
    fn key_id_of_pem_round_trip_matches_direct_key_id() {
        // The deployer will derive a key id from the PEM stored in
        // trust-root.json. That must produce the same key id as computing it
        // directly from the VerifyingKey.
        let vk = key_from_seed(77);
        let pem = spki_pem(&vk).expect("encodes");
        let recovered = VerifyingKey::from_public_key_pem(&pem).expect("decodes");
        assert_eq!(greentic_key_id(&vk), greentic_key_id(&recovered));
    }
}

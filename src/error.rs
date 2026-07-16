//! Crate-wide error type.
//!
//! Every failure mode gets its own variant carrying what a reader needs to act.
//! There is deliberately no "skipped" or "not checked" variant: a caller that
//! wants to tolerate unsigned artifacts expresses that in its own policy, so
//! that "verified" and "never checked" can never collapse into one value here.

use std::sync::Arc;

use thiserror::Error;

/// Any failure while resolving a trust root or verifying a chain.
#[derive(Debug, Clone, Error)]
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
        source: Arc<reqwest::Error>,
    },

    #[error("DID document request returned HTTP {code}")]
    HttpStatus { code: u16 },

    #[error("DID document is not valid JSON: {source}")]
    DocumentParse {
        #[source]
        source: Arc<serde_json::Error>,
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
        source: Arc<serde_json::Error>,
    },
}

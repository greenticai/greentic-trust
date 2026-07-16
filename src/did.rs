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

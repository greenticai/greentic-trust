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

        let (host_raw, path_raw) = match rest.split_once(':') {
            Some((host, path)) => (host, Some(path)),
            None => (rest, None),
        };
        let host = decode_host(host_raw).map_err(|reason| TrustError::DidParse {
            input: input.to_owned(),
            reason,
        })?;

        let mut path = String::new();
        if let Some(path_raw) = path_raw {
            for segment in path_raw.split(':') {
                validate_path_segment(segment).map_err(|reason| TrustError::DidParse {
                    input: input.to_owned(),
                    reason,
                })?;
                path.push('/');
                path.push_str(segment);
            }
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
///
/// The decoded host is later `format!`-concatenated into a URL string and
/// parsed by `url`, so the parser's reading of that string can diverge from
/// what this function intended unless every character is constrained up
/// front. In particular `@` (userinfo separator), `#` (fragment start), and
/// `?` (query start) must never reach the URL unescaped: an attacker-chosen
/// suffix after one of those would be read by `url` as something other than
/// host, silently repointing the request. `decode_host` therefore validates
/// the decoded host against a registered-name/IP charset — ASCII
/// alphanumerics, `.`, and `-` — plus an optional single `:port` suffix where
/// `port` is one or more ASCII digits.
fn decode_host(raw: &str) -> Result<String, String> {
    if raw.is_empty() {
        return Err("empty host".to_owned());
    }
    let decoded = raw.replace("%3A", ":").replace("%3a", ":");
    if decoded.contains('%') {
        return Err(format!("host has unsupported percent-encoding: {raw}"));
    }

    let (name, port) = match decoded.split_once(':') {
        Some((name, port)) => (name, Some(port)),
        None => (decoded.as_str(), None),
    };
    if name.is_empty() {
        return Err(format!("host has an empty name: {raw}"));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err(format!("host contains illegal characters: {raw}"));
    }
    if let Some(port) = port {
        if port.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
            return Err(format!("host has an invalid port: {raw}"));
        }
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

    #[test]
    fn rejects_userinfo_in_the_host() {
        // The decoded host is `format!`-concatenated into a URL string and
        // later parsed by `url`. Without a charset check, `@` is read by the
        // parser as the userinfo separator, so
        // `did:web:trust.greentic.cloud@127.0.0.1%3A45095` builds
        // `https://trust.greentic.cloud@127.0.0.1:45095/...` — a request to
        // 127.0.0.1, not trust.greentic.cloud.
        let error =
            DidWeb::parse("did:web:trust.greentic.cloud@127.0.0.1%3A45095").expect_err("rejects");
        assert!(matches!(error, TrustError::DidParse { .. }));
    }

    #[test]
    fn rejects_a_fragment_in_the_host() {
        // `#` starts a URL fragment; unfiltered, the path after it is
        // swallowed into the fragment and never sent to the server.
        let error = DidWeb::parse("did:web:example.com#frag").expect_err("rejects");
        assert!(matches!(error, TrustError::DidParse { .. }));
    }

    #[test]
    fn rejects_a_query_in_the_host() {
        // `?` starts a URL query string, letting a suffix ride along into the
        // request unexpectedly.
        let error = DidWeb::parse("did:web:example.com?x=1").expect_err("rejects");
        assert!(matches!(error, TrustError::DidParse { .. }));
    }

    #[test]
    fn rejects_a_trailing_colon() {
        // `did:web:example.com:` splits into host "example.com" and one path
        // segment "" (everything after the first colon), which
        // validate_path_segment already rejects as empty. This pins that
        // behaviour permanently rather than relying on it as an accident of
        // how `split_once` happens to divide the string.
        let error = DidWeb::parse("did:web:example.com:").expect_err("rejects");
        assert!(matches!(error, TrustError::DidParse { .. }));
    }

    #[test]
    fn rejects_a_bare_percent_encoded_colon_with_no_port() {
        // Decodes to "example.com:" with an empty port, which used to yield
        // "https://example.com:/..." — a URL with a syntactically present but
        // empty port.
        let error = DidWeb::parse("did:web:example.com%3A").expect_err("rejects");
        assert!(matches!(error, TrustError::DidParse { .. }));
    }

    #[test]
    fn rejects_a_double_port() {
        // Decodes to "example.com:8443:9": two colons is not a valid
        // registered-name[:port] and must not be silently truncated to the
        // first port by whatever happens to consume it downstream.
        let error = DidWeb::parse("did:web:example.com%3A8443%3A9").expect_err("rejects");
        assert!(matches!(error, TrustError::DidParse { .. }));
    }
}

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

    /// Permit plain HTTP.
    ///
    /// Gated behind `test`/`testing`: HTTPS is the only thing making a fetched
    /// root key trustworthy, so a production build must not even have this
    /// method to call. The field stays unconditional and simply remains `false`
    /// forever in a production build.
    #[cfg(any(test, feature = "testing"))]
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
                Err(shared) => reconstruct_shared_error(&shared),
            })
    }
}

/// Recover a concrete [`TrustError`] from a still-shared `Arc`.
///
/// `moka`'s `try_get_with` retains an internal clone of the error `Arc` for
/// the lifetime of its waiter bookkeeping, so `Arc::try_unwrap` never
/// succeeds in practice — even for the single-caller case this crate targets.
/// Every variant this resolver can actually produce carries only `Copy` or
/// `String` fields except the two that wrap a foreign, non-`Clone` error
/// (`Fetch`'s `reqwest::Error`, `DocumentParse`'s `serde_json::Error`); those
/// fall back to a string-carrying `DocumentInvalid` that preserves the
/// message without needing ownership.
fn reconstruct_shared_error(error: &TrustError) -> TrustError {
    match error {
        TrustError::InsecureScheme { url } => TrustError::InsecureScheme { url: url.clone() },
        TrustError::HttpStatus { code } => TrustError::HttpStatus { code: *code },
        TrustError::DocumentInvalid { reason } => TrustError::DocumentInvalid {
            reason: reason.clone(),
        },
        TrustError::BindingMismatch { expected, found } => TrustError::BindingMismatch {
            expected: expected.clone(),
            found: found.clone(),
        },
        TrustError::NoAssertionKeys { did } => TrustError::NoAssertionKeys { did: did.clone() },
        TrustError::UnsupportedAlgorithm { alg } => {
            TrustError::UnsupportedAlgorithm { alg: alg.clone() }
        }
        other => TrustError::DocumentInvalid {
            reason: other.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
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

    /// Build a `DidWeb` pointing at the mock server, and the matching resolver.
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

        let resolver = HttpResolver::new(Duration::from_mins(10), 16).allow_http();

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

        let resolver = HttpResolver::new(Duration::from_mins(10), 16).allow_http();

        let first = resolver.resolve(&did).await;
        assert!(matches!(first, Err(TrustError::HttpStatus { code: 503 })));

        resolver
            .resolve(&did)
            .await
            .expect("second attempt succeeds");
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

        let resolver = HttpResolver::new(Duration::from_mins(10), 16).allow_http();

        let error = resolver.resolve(&did).await.expect_err("rejects");
        assert!(matches!(error, TrustError::HttpStatus { code: 404 }));
    }

    #[tokio::test]
    async fn refuses_plain_http_by_default() {
        // `DidWeb` always derives an https:// URL, so the guard is reached only
        // via `allow_http`'s rewrite or a caller passing a URL in directly.
        // Exercise it at `fetch_bytes`, which is where the decision lives.
        let resolver = HttpResolver::new(Duration::from_mins(10), 16);

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
                ResponseTemplate::new(200).set_body_json(document_body("did:web:evil.example")),
            )
            .mount(&server)
            .await;

        let resolver = HttpResolver::new(Duration::from_mins(10), 16).allow_http();

        let error = resolver.resolve(&did).await.expect_err("rejects");
        assert!(matches!(error, TrustError::BindingMismatch { .. }));
    }
}

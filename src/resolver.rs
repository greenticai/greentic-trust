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

/// Default total request timeout: long enough for a slow-but-legitimate
/// origin to serve a small static JSON document, short enough that a
/// slow-loris origin cannot park `verify_describe` indefinitely — including
/// every caller queued behind it by the single-flight cache.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Default TCP+TLS connect timeout. A live, correctly-routed origin completes
/// a handshake in well under a second; this only needs to be long enough to
/// absorb ordinary network jitter, not to wait out a black-holed host.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Fetches documents over HTTPS and caches them for a TTL.
#[derive(Debug, Clone)]
pub struct HttpResolver {
    cache: Cache<String, Arc<TrustDocument>>,
    http: reqwest::Client,
    allow_http: bool,
    timeout: Duration,
    connect_timeout: Duration,
}

/// Build the underlying `reqwest::Client`.
///
/// `https_only` is set from `!allow_http`, and redirects are always disabled:
/// a did:web document lives at one static origin, so a 3xx response is never
/// legitimate. Both properties must be enforced on the `Client` itself, not
/// just on the initial URL string — a redirect hop is invisible to a check
/// that only inspects the URL passed in.
fn build_client(
    allow_http: bool,
    timeout: Duration,
    connect_timeout: Duration,
) -> Result<reqwest::Client, TrustError> {
    reqwest::Client::builder()
        .https_only(!allow_http)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .connect_timeout(connect_timeout)
        .build()
        .map_err(|source| TrustError::ClientBuild {
            source: Arc::new(source),
        })
}

impl HttpResolver {
    /// Build a resolver caching up to `capacity` documents for `ttl`, using
    /// the default timeouts (10s total, 5s to connect). Use
    /// [`Self::with_timeout`] to override the total timeout.
    ///
    /// # Errors
    /// [`TrustError::ClientBuild`] if the underlying HTTP client cannot be
    /// constructed (TLS backend initialization failure). Not expected in
    /// practice for this crate's configuration, but `reqwest` types this as
    /// fallible and a production path must not paper over that with `unwrap`.
    pub fn new(ttl: Duration, capacity: u64) -> Result<Self, TrustError> {
        Ok(Self {
            cache: Cache::builder()
                .max_capacity(capacity)
                .time_to_live(ttl)
                .build(),
            http: build_client(false, DEFAULT_TIMEOUT, DEFAULT_CONNECT_TIMEOUT)?,
            allow_http: false,
            timeout: DEFAULT_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
        })
    }

    /// Rebuild with a caller-chosen total request timeout. The connect
    /// timeout stays at the default.
    ///
    /// Returns `Result`, not `Self`: this rebuilds the underlying client (see
    /// [`Self::allow_http`]'s doc comment for why a timeout change needs a
    /// rebuild rather than a field flip), and that rebuild is exactly the
    /// fallible `ClientBuilder::build()` call [`Self::new`] must not unwrap.
    /// A `-> Self` signature here would force swallowing that failure,
    /// reintroducing the silently-wrong-client problem the HTTPS/redirect fix
    /// exists to close.
    ///
    /// # Errors
    /// [`TrustError::ClientBuild`], see [`Self::new`].
    pub fn with_timeout(mut self, timeout: Duration) -> Result<Self, TrustError> {
        self.timeout = timeout;
        self.http = build_client(self.allow_http, self.timeout, self.connect_timeout)?;
        Ok(self)
    }

    /// Permit plain HTTP.
    ///
    /// Gated behind `test`/`testing`: HTTPS is the only thing making a fetched
    /// root key trustworthy, so a production build must not even have this
    /// method to call. The field stays unconditional and simply remains `false`
    /// forever in a production build.
    ///
    /// Rebuilds the underlying client with `https_only(false)` — flipping just
    /// the field without rebuilding would leave the still-`https_only(true)`
    /// client refusing the very plain-HTTP requests this method exists to
    /// allow.
    ///
    /// # Errors
    /// [`TrustError::ClientBuild`], see [`Self::new`].
    #[cfg(any(test, feature = "testing"))]
    pub fn allow_http(mut self) -> Result<Self, TrustError> {
        self.allow_http = true;
        self.http = build_client(true, self.timeout, self.connect_timeout)?;
        Ok(self)
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
            .map_err(|source| TrustError::Fetch {
                source: Arc::new(source),
            })?;

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
            .map_err(|source| TrustError::Fetch {
                source: Arc::new(source),
            })
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
            .map_err(|shared| (*shared).clone())
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

    /// Like [`did_for`], but namespaced under a path segment, so two DIDs can
    /// share the mock server's host while resolving to different documents.
    fn did_for_path(server: &MockServer, segment: &str) -> DidWeb {
        let authority = server
            .uri()
            .trim_start_matches("http://")
            .replace(':', "%3A");
        DidWeb::parse(&format!("did:web:{authority}:{segment}")).expect("parses")
    }

    /// Like [`document_body`], but signed with a caller-supplied key instead of
    /// a freshly generated, unrecoverable one, so a test can assert the
    /// resolved document carries exactly that key back.
    fn document_body_for_key(
        did: &str,
        verifying: &ed25519_dalek::VerifyingKey,
    ) -> serde_json::Value {
        let x = URL_SAFE_NO_PAD.encode(verifying.as_bytes());
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

        let resolver = HttpResolver::new(Duration::from_mins(10), 16)
            .expect("client builds")
            .allow_http()
            .expect("client builds");

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

        let resolver = HttpResolver::new(Duration::from_mins(10), 16)
            .expect("client builds")
            .allow_http()
            .expect("client builds");

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

        let resolver = HttpResolver::new(Duration::from_mins(10), 16)
            .expect("client builds")
            .allow_http()
            .expect("client builds");

        let error = resolver.resolve(&did).await.expect_err("rejects");
        assert!(matches!(error, TrustError::HttpStatus { code: 404 }));
    }

    #[tokio::test]
    async fn refuses_plain_http_by_default() {
        // `DidWeb` always derives an https:// URL, so the guard is reached only
        // via `allow_http`'s rewrite or a caller passing a URL in directly.
        // Exercise it at `fetch_bytes`, which is where the decision lives.
        let resolver = HttpResolver::new(Duration::from_mins(10), 16).expect("client builds");

        let error = resolver
            .fetch_bytes("http://trust.greentic.cloud/.well-known/did.json")
            .await
            .expect_err("rejects");

        assert!(matches!(error, TrustError::InsecureScheme { .. }));
    }

    #[tokio::test]
    async fn surfaces_a_connection_failure_as_fetch() {
        // Nothing listens on this port, so the request fails at the transport
        // layer rather than with an HTTP status — this must surface as
        // `TrustError::Fetch`, not get flattened into `DocumentInvalid`.
        let did = DidWeb::parse("did:web:127.0.0.1%3A1").expect("parses");
        let resolver = HttpResolver::new(Duration::from_mins(10), 16)
            .expect("client builds")
            .allow_http()
            .expect("client builds");

        let error = resolver.resolve(&did).await.expect_err("rejects");
        assert!(matches!(error, TrustError::Fetch { .. }));
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

        let resolver = HttpResolver::new(Duration::from_mins(10), 16)
            .expect("client builds")
            .allow_http()
            .expect("client builds");

        let error = resolver.resolve(&did).await.expect_err("rejects");
        assert!(matches!(error, TrustError::BindingMismatch { .. }));
    }

    #[tokio::test]
    async fn two_dids_on_one_host_do_not_collide() {
        // `did:web:h:a` and `did:web:h:b` are different trust roots served
        // from the same host. A host-keyed cache (the `JwksCache` bug this
        // resolver exists to avoid) would let the second resolve return the
        // first DID's document — a trust root substitution.
        let server = MockServer::start().await;
        let did_a = did_for_path(&server, "a");
        let did_b = did_for_path(&server, "b");

        let key_a = SigningKey::generate(&mut OsRng);
        let key_b = SigningKey::generate(&mut OsRng);

        Mock::given(method("GET"))
            .and(path("/a/did.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(document_body_for_key(
                    did_a.as_str(),
                    &key_a.verifying_key(),
                )),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/b/did.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(document_body_for_key(
                    did_b.as_str(),
                    &key_b.verifying_key(),
                )),
            )
            .mount(&server)
            .await;

        let resolver = HttpResolver::new(Duration::from_mins(10), 16)
            .expect("client builds")
            .allow_http()
            .expect("client builds");

        let doc_a = resolver.resolve(&did_a).await.expect("resolves a");
        let doc_b = resolver.resolve(&did_b).await.expect("resolves b");

        let returned_a = doc_a.assertion_keys()[0].to_bytes();
        let returned_b = doc_b.assertion_keys()[0].to_bytes();

        assert_ne!(returned_a, returned_b);
        assert_eq!(returned_a, key_a.verifying_key().to_bytes());
        assert_eq!(returned_b, key_b.verifying_key().to_bytes());
    }

    #[tokio::test]
    async fn concurrent_misses_collapse_into_one_request() {
        // A burst of concurrent cache misses for the same DID must coalesce
        // into a single origin request via `try_get_with`'s single-flight,
        // rather than stampeding the origin the way an uncoordinated
        // get-then-insert cache would.
        let server = MockServer::start().await;
        let did = did_for(&server);
        Mock::given(method("GET"))
            .and(path("/.well-known/did.json"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(document_body(did.as_str()))
                    .set_delay(Duration::from_millis(100)),
            )
            .expect(1)
            .mount(&server)
            .await;

        let resolver = HttpResolver::new(Duration::from_mins(10), 16)
            .expect("client builds")
            .allow_http()
            .expect("client builds");

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let resolver = resolver.clone();
                let did = did.clone();
                tokio::spawn(async move { resolver.resolve(&did).await })
            })
            .collect();

        let mut results = Vec::with_capacity(handles.len());
        for handle in handles {
            results.push(handle.await.expect("task panicked").expect("resolves"));
        }

        let first = &results[0];
        for document in &results[1..] {
            assert!(Arc::ptr_eq(first, document));
        }
    }

    #[tokio::test]
    async fn refuses_to_follow_a_redirect_to_another_origin() {
        // A malicious or compromised intermediary 302s the well-known request
        // to a second origin serving a document that *claims* the first
        // origin's DID. `document.rs`'s binding check cannot catch this: it
        // validates what the document claims, not where the bytes came from.
        // Provenance is HTTPS-to-the-named-origin, and a redirect must never
        // be followed across origins.
        let victim = MockServer::start().await;
        let attacker = MockServer::start().await;
        let did = did_for(&victim);

        Mock::given(method("GET"))
            .and(path("/.well-known/did.json"))
            .respond_with(ResponseTemplate::new(302).insert_header(
                "Location",
                format!("{}/.well-known/did.json", attacker.uri()),
            ))
            .mount(&victim)
            .await;
        // The attacker's document claims the victim's DID, so if the redirect
        // were followed the binding check alone would not catch it.
        Mock::given(method("GET"))
            .and(path("/.well-known/did.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(document_body(did.as_str())))
            .mount(&attacker)
            .await;

        let resolver = HttpResolver::new(Duration::from_mins(10), 16)
            .expect("client builds")
            .allow_http()
            .expect("client builds");

        let error = resolver
            .resolve(&did)
            .await
            .expect_err("must not follow the redirect");
        assert!(matches!(error, TrustError::HttpStatus { code: 302 }));
    }

    #[tokio::test]
    async fn gives_up_on_an_origin_slower_than_the_configured_timeout() {
        // Client::new() leaves timeout/connect_timeout unset, so a slow
        // origin would hang verify_describe indefinitely — and every
        // concurrent caller queued behind it by the single-flight cache.
        // with_timeout must make that fail closed instead.
        let server = MockServer::start().await;
        let did = did_for(&server);
        Mock::given(method("GET"))
            .and(path("/.well-known/did.json"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(document_body(did.as_str()))
                    .set_delay(Duration::from_millis(200)),
            )
            .mount(&server)
            .await;

        let resolver = HttpResolver::new(Duration::from_mins(10), 16)
            .expect("client builds")
            .with_timeout(Duration::from_millis(20))
            .expect("client builds")
            .allow_http()
            .expect("client builds");

        let error = resolver
            .resolve(&did)
            .await
            .expect_err("times out before the origin responds");
        assert!(matches!(error, TrustError::Fetch { .. }));
    }
}

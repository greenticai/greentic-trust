# greentic-trust

did:web trust root and publisher certificate verification for Greentic.

Given a signed `describe`, a `PublisherCert`, and a trusted `did:web` identifier,
decide whether the artifact is authentic — or say precisely why not.

## The chain

```
did:web:trust.greentic.cloud/.well-known/did.json
└── root key (Ed25519, published as a static document)
         │ signs
         ▼
    PublisherCert { publisherPublicKey, rootSignature, keyId, notAfter }
         │ vouches for
         ▼
    publisher key
         │ signs
         ▼
    describe.json inside the .gtxpack
```

## Usage

```rust
use std::time::Duration;
use chrono::Utc;
use greentic_trust::{DidWeb, HttpResolver, verify_describe};

let did = DidWeb::parse("did:web:trust.greentic.cloud")?;
let resolver = HttpResolver::new(Duration::from_secs(600), 16);
let publisher_key = verify_describe(&describe, &did, &resolver, Utc::now()).await?;
```

The trusted DID is a **URL, not a secret** — it belongs in ordinary config.

## Environments

Each environment has its own root. A leaked research key must not be able to
sign something production accepts.

| Environment | DID |
|---|---|
| research | `did:web:trust.research.greentic.cloud` |
| staging | `did:web:trust.staging.greentic.cloud` |
| production | `did:web:trust.greentic.cloud` |

## Verify

```bash
bash ci/local_check.sh
```

## Design

`docs/superpowers/specs/2026-07-16-did-web-trust-root-design.md`

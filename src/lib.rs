//! did:web trust root and publisher certificate verification for Greentic.
//!
//! Given a signed `describe`, a [`cert::PublisherCert`], and a trusted
//! [`did::DidWeb`], decide whether the artifact is authentic. See
//! `docs/superpowers/specs/2026-07-16-did-web-trust-root-design.md`.

#![forbid(unsafe_code)]

pub mod did;
pub mod error;

pub use did::DidWeb;
pub use error::TrustError;

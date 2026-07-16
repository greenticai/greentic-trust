//! `greentic-trust` ceremony CLI. Generates a root key, builds the did.json
//! document the verifier accepts, and verifies a published document.
//!
//! Compiled only with `--features cli`; the library carries no CLI dependency.

use std::process::ExitCode;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use clap::{Parser, Subcommand};

use greentic_trust::ceremony::{build_document, generate_root};
use greentic_trust::{DidWeb, HttpResolver, RootResolver, TrustDocument};

#[derive(Parser)]
#[command(
    name = "greentic-trust",
    about = "Greentic did:web trust-root ceremony tool"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a root Ed25519 keypair. Private seed to stdout, public JWK to stderr.
    GenRoot,
    /// Build a did.json document for a DID and one or more root public keys.
    BuildDoc {
        /// The did:web identifier the document is served for.
        #[arg(long)]
        did: String,
        /// A root public key (JWK x, base64url). Repeat for a rotation-overlap doc.
        #[arg(long = "root-public", required = true)]
        root_public: Vec<String>,
    },
    /// Verify a published or local did.json serves the expected root.
    VerifyDoc {
        /// The did:web identifier to resolve (or to bind a --file document against).
        #[arg(long)]
        did: String,
        /// The root public key you expect (JWK x, base64url).
        #[arg(long)]
        expected_root: String,
        /// Read a local document instead of resolving over the network.
        #[arg(long)]
        file: Option<std::path::PathBuf>,
    },
}

/// A ceremony error, rendered to stderr with a non-zero exit.
#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error("{0}")]
    Trust(#[from] greentic_trust::TrustError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("decode: {0}")]
    Decode(String),
    #[error("the document does not serve the expected root")]
    Mismatch,
}

fn run() -> Result<(), CliError> {
    match Cli::parse().command {
        Command::GenRoot => run_gen_root(),
        Command::BuildDoc { did, root_public } => run_build_doc(&did, &root_public),
        Command::VerifyDoc {
            did,
            expected_root,
            file,
        } => run_verify_doc(&did, &expected_root, file.as_deref()),
    }
}

#[allow(clippy::unnecessary_wraps)]
fn run_gen_root() -> Result<(), CliError> {
    let signing = generate_root(&mut rand::rngs::OsRng);

    // stdout: the secret, alone, so `gen-root | wrangler secret put ...` pipes
    // only the private key.
    println!("{}", STANDARD.encode(signing.to_bytes()));

    // stderr: everything a human needs, none of it captured by the pipe.
    let x = URL_SAFE_NO_PAD.encode(signing.verifying_key().as_bytes());
    eprintln!("public key (JWK x, base64url): {x}");
    eprintln!("suggested kid suffix: #root-1");
    eprintln!(
        "warning: a private key was written to stdout; capture it into your secret \
         manager and clear your scrollback"
    );
    Ok(())
}

/// Decode a JWK `x` (base64url, 32 bytes) into a verifying key.
fn decode_public(x: &str) -> Result<ed25519_dalek::VerifyingKey, CliError> {
    let raw = URL_SAFE_NO_PAD
        .decode(x.trim())
        .map_err(|e| CliError::Decode(format!("root public key is not base64url: {e}")))?;
    let bytes: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
        CliError::Decode(format!(
            "root public key is {} bytes, expected 32",
            raw.len()
        ))
    })?;
    ed25519_dalek::VerifyingKey::from_bytes(&bytes)
        .map_err(|e| CliError::Decode(format!("root public key is not a valid Ed25519 key: {e}")))
}

fn run_build_doc(did: &str, root_public: &[String]) -> Result<(), CliError> {
    let did = DidWeb::parse(did)?;
    let roots = root_public
        .iter()
        .map(|x| decode_public(x))
        .collect::<Result<Vec<_>, _>>()?;
    let doc = build_document(&did, &roots)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&doc).map_err(|e| CliError::Decode(e.to_string()))?
    );
    Ok(())
}

fn run_verify_doc(
    did: &str,
    expected_root: &str,
    file: Option<&std::path::Path>,
) -> Result<(), CliError> {
    let did = DidWeb::parse(did)?;
    let expected = decode_public(expected_root)?;

    let matched = if let Some(path) = file {
        let bytes = std::fs::read(path)?;
        let doc = TrustDocument::parse(&did, &bytes)?;
        doc.assertion_keys()
            .iter()
            .any(|k| k.as_bytes() == expected.as_bytes())
    } else {
        let resolver = HttpResolver::new(std::time::Duration::from_mins(10), 4)?;
        let doc = tokio::runtime::Runtime::new()?.block_on(resolver.resolve(&did))?;
        doc.assertion_keys()
            .iter()
            .any(|k| k.as_bytes() == expected.as_bytes())
    };

    if matched {
        println!("OK: {} serves the expected root", did.as_str());
        Ok(())
    } else {
        Err(CliError::Mismatch)
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

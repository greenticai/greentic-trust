//! `greentic-trust` ceremony CLI. Generates a root key, builds the did.json
//! document the verifier accepts, and verifies a published document.
//!
//! Compiled only with `--features cli`; the library carries no CLI dependency.

use std::fmt;
use std::process::ExitCode;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use clap::{Parser, Subcommand};

use greentic_trust::ceremony::generate_root;

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
}

/// A ceremony error, rendered to stderr with a non-zero exit.
enum CliError {
    Trust(greentic_trust::TrustError),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::Trust(e) => write!(f, "{e}"),
        }
    }
}

impl From<greentic_trust::TrustError> for CliError {
    fn from(e: greentic_trust::TrustError) -> Self {
        CliError::Trust(e)
    }
}

fn run() -> Result<(), CliError> {
    match Cli::parse().command {
        Command::GenRoot => run_gen_root(),
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

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

//! Integration tests for the `greentic-trust` binary. Compiled only with the
//! `cli` feature (the binary does not exist otherwise).
#![cfg(feature = "cli")]

use assert_cmd::Command;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;

fn bin() -> Command {
    Command::cargo_bin("greentic-trust").expect("binary builds")
}

#[test]
fn gen_root_prints_a_valid_private_seed_to_stdout() {
    let output = bin()
        .arg("gen-root")
        .assert()
        .success()
        .get_output()
        .clone();

    let stdout = String::from_utf8(output.stdout).expect("utf8");
    let seed = STANDARD
        .decode(stdout.trim())
        .expect("stdout is standard base64");
    assert_eq!(seed.len(), 32, "private key is a 32-byte Ed25519 seed");
}

#[test]
fn gen_root_puts_the_public_key_and_warning_on_stderr_not_stdout() {
    let output = bin()
        .arg("gen-root")
        .assert()
        .success()
        .get_output()
        .clone();

    let stdout = String::from_utf8(output.stdout).expect("utf8");
    let stderr = String::from_utf8(output.stderr).expect("utf8");

    // The public JWK x is on stderr and decodes to 32 bytes.
    assert!(stderr.contains("base64url"), "stderr names the public key");
    assert!(
        stderr.to_lowercase().contains("warning"),
        "stderr warns about the private key"
    );

    // The private seed (stdout) must not appear on stderr.
    let private = stdout.trim();
    assert!(
        !stderr.contains(private),
        "private key must not leak to stderr"
    );

    // And the stderr x must NOT be parseable as the private seed (they differ).
    let seed = STANDARD.decode(private).expect("base64");
    let pub_x = URL_SAFE_NO_PAD.encode(
        ed25519_dalek::SigningKey::from_bytes(&seed.try_into().unwrap())
            .verifying_key()
            .to_bytes(),
    );
    assert!(
        stderr.contains(&pub_x),
        "stderr carries the public key derived from the private seed"
    );
}

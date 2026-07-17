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

use std::io::Write as _;

/// Run gen-root and return (`private_seed_b64`, `public_x_b64url`).
fn fresh_root() -> (String, String) {
    let output = bin()
        .arg("gen-root")
        .assert()
        .success()
        .get_output()
        .clone();
    let private = String::from_utf8(output.stdout).unwrap().trim().to_owned();
    let seed: [u8; 32] = STANDARD.decode(&private).unwrap().try_into().unwrap();
    let x = URL_SAFE_NO_PAD.encode(
        ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes(),
    );
    (private, x)
}

#[test]
fn build_doc_then_verify_doc_file_accepts_the_matching_root() {
    let did = "did:web:trust.research.greentic.cloud";
    let (_private, x) = fresh_root();

    let built = bin()
        .args(["build-doc", "--did", did, "--root-public", &x])
        .assert()
        .success()
        .get_output()
        .clone();
    let doc = built.stdout;

    let mut file = tempfile::NamedTempFile::new().expect("temp file");
    file.write_all(&doc).expect("write doc");

    bin()
        .args(["verify-doc", "--did", did, "--expected-root", &x, "--file"])
        .arg(file.path())
        .assert()
        .success();
}

#[test]
fn verify_doc_file_rejects_a_wrong_expected_root() {
    let did = "did:web:trust.research.greentic.cloud";
    let (_p1, published_x) = fresh_root();
    let (_p2, other_x) = fresh_root();

    let built = bin()
        .args(["build-doc", "--did", did, "--root-public", &published_x])
        .assert()
        .success()
        .get_output()
        .clone();

    let mut file = tempfile::NamedTempFile::new().expect("temp file");
    file.write_all(&built.stdout).expect("write doc");

    bin()
        .args([
            "verify-doc",
            "--did",
            did,
            "--expected-root",
            &other_x,
            "--file",
        ])
        .arg(file.path())
        .assert()
        .failure();
}

#[test]
fn build_doc_rejects_a_malformed_did() {
    bin()
        .args([
            "build-doc",
            "--did",
            "did:key:z6MkExample",
            "--root-public",
            "AAAA",
        ])
        .assert()
        .failure();
}

#[test]
fn mint_cert_reads_seed_from_stdin_and_emits_a_cert_that_verifies() {
    use chrono::Utc;
    use greentic_trust::PublisherCert;

    let (root_seed, root_x) = fresh_root();
    let (_pub_seed, pub_x) = fresh_root();

    let output = bin()
        .args([
            "mint-cert",
            "--publisher-key",
            &pub_x,
            "--key-id",
            "pk_test_1",
            "--not-after",
            "2030-01-01T00:00:00Z",
        ])
        .write_stdin(root_seed)
        .assert()
        .success()
        .get_output()
        .clone();

    let cert: PublisherCert =
        serde_json::from_slice(&output.stdout).expect("stdout is a PublisherCert");

    // Reconstruct the root verifying key from gen-root's public x (base64url).
    let root_bytes: [u8; 32] = URL_SAFE_NO_PAD.decode(&root_x).unwrap().try_into().unwrap();
    let root_pub = ed25519_dalek::VerifyingKey::from_bytes(&root_bytes).unwrap();

    let now = chrono::DateTime::parse_from_rfc3339("2026-07-17T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let certified = cert
        .verify(&[root_pub], now)
        .expect("cert verifies against the root");

    let pub_bytes: [u8; 32] = URL_SAFE_NO_PAD.decode(&pub_x).unwrap().try_into().unwrap();
    assert_eq!(certified.as_bytes(), &pub_bytes);
}

#[test]
fn mint_cert_rejects_a_non_base64_seed_on_stdin() {
    let (_seed, pub_x) = fresh_root();
    bin()
        .args([
            "mint-cert",
            "--publisher-key",
            &pub_x,
            "--key-id",
            "pk_test_1",
            "--not-after",
            "2030-01-01T00:00:00Z",
        ])
        .write_stdin("not base64 !!!")
        .assert()
        .failure();
}

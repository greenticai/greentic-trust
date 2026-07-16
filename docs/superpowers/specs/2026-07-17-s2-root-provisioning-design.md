# S2 — root provisioning: ceremony tooling + runbook

**Date:** 2026-07-17
**Status:** Design, approved for planning
**Epic:** did:web trust root. S1 (the verification library) is merged.
**Scope:** the buildable-now half of S2 — a ceremony CLI and a runbook. The credential-bearing publish is a documented human procedure, not code (see "Why publish is a runbook, not CI").

## Problem

S1 verifies a chain that ends at a root key published at a `did:web` URL. Nothing produces that root or that document yet. S2 provides the machinery to:

1. generate a per-environment Ed25519 root key, air-gapped-friendly,
2. build the exact `did.json` document S1's verifier accepts, and
3. verify a published document serves the expected root —

plus the runbook a human follows to run the ceremony and publish, across the three environments the S1 design fixes.

The three DIDs (from the S1 design, D2):

| Environment | DID | Root custody |
|---|---|---|
| research | `did:web:trust.research.greentic.cloud` | secret manager |
| staging | `did:web:trust.staging.greentic.cloud` | secret manager |
| production | `did:web:trust.greentic.cloud` | offline ceremony (org-blocked) |

## Why publish is a runbook, not CI

The recon settled this, and it is not a preference. The workspace's `CLOUDFLARE_API_TOKEN` (the only Cloudflare deploy credential in CI, in `greentic-tenant-manager/.github/workflows/deploy-research.yml`) **lacks `Workers Routes:Edit` and has no R2 scope**. `greentic-tenant-manager/wrangler.research.toml:12-27` documents that declaring routes in wrangler makes `wrangler deploy` fail *after* upload with Cloudflare error 10000, which is why `id.research.greentic.cloud` was bound **manually, out-of-band, and persists across deploys**. `greentic-edge/wrangler.toml:5-27` records the same limitation.

So automating R2 upload + DNS binding in CI is blocked by permissions we do not hold, regardless of intent. S2's code deliverable is therefore the ceremony tool; the publish is a runbook of manual steps, matching how every custom domain in the platform is bound today. When the token is later scoped up, the runbook's manual steps become a CI job — but that is a separate change, and this design does not pretend to it.

This mirrors the pattern already in the SDK's audit-remediation design: build the machinery now; the production root pubkey + issuance stay org-blocked.

## Decisions

### D1 — one crate, `cli` feature-gated binary

`greentic-trust` stays a single crate. `clap` is an optional dependency behind a `cli` feature; the `[[bin]]` carries `required-features = ["cli"]`. `cargo build` builds the lib with no CLI dependencies; `cargo build --features cli` builds the tool. The lib's consumers — runner, SDK, store-server — never pull `clap` into their graphs.

Rejected: a separate crate in a workspace (turns a clean single-crate repo into a workspace, and forces the ceremony module to be full public API rather than a focused surface). Rejected: a standalone script (loses the anti-drift guarantee below — the document builder would no longer be the code S1's parser is tested against).

### D2 — the `ceremony` module graduates from `fixtures`, always compiled

`cert::fixtures` today (`#[cfg(any(test, feature = "testing"))]`) holds `root_keypair()` and `mint_cert()`. These move to a new always-compiled `ceremony` module, joined by `build_document()`. `fixtures` becomes a `#[cfg(any(test, feature = "testing"))]` re-export shim so existing `fixtures::mint_cert` consumers (S1's own tests, and later S3/S5) keep compiling unchanged.

Always compiled, not test-gated, because `ceremony` defines the **mint side of the same wire format the lib verifies**. One module owns both "how a root document is built" and "how a cert is minted"; the verifier owns "how they are checked". Co-locating mint and verify in one crate is the anti-drift guarantee — the same argument S1 used to re-author `PublisherCert` here rather than importing it.

This does expand the lib's public surface with signing operations (`mint_cert`, root generation). That is intended: S3 (store-server issuing certs) needs exactly this, and a single definition of the signed bytes for both sides is the point.

### D3 — the tool never seals; the secret manager does

`gen-root` emits the private key as the raw 32-byte Ed25519 seed, base64 (`STANDARD`) — the encoding `SigningKey::from_bytes(&[u8; 32])` reconstructs directly, and the same `ed25519:<base64>` shape the runner's `trusted_signers` already parses. Not PKCS#8: that would pull the `pkcs8` feature for no interop gain over the codebase's existing raw-key convention. The tool does not encrypt it. Sealing is the secret manager's job (`wrangler secret put`, a GitHub Actions secret, or air-gapped hardware for prod). A tool that sealed under its own master key would reintroduce the custody problem this whole epic exists to avoid — the same reason the S1 design rejected tenant-manager as a key custodian.

### D4 — private to stdout, human-readable to stderr

`gen-root` writes the private key to **stdout only**, as a single line, so `gen-root | wrangler secret put GREENTIC_TRUST_ROOT` pipes the secret and nothing else. The public JWK `x`, the derived `kid`, and a warning that a private key was printed go to **stderr**, visible on the terminal but absent from the piped stream. The public key is not secret, so stderr is a safe home and keeps stdout clean for the pipe.

No filesystem writes by default and no network — the tool must run on an air-gapped machine.

## Architecture

| Unit | Responsibility | Depends on |
|---|---|---|
| `ceremony` (new; from `fixtures`) | `generate_root(rng)`, `build_document(did, roots)`, `mint_cert` — pure, no I/O | `did`, `cert`, `error` |
| `src/bin/greentic-trust.rs` | clap wrapper; all I/O (stdout/stderr, file read, HTTPS fetch) | `ceremony`, `resolver`, `did` |
| `cert::fixtures` (kept) | `#[cfg(any(test, feature = "testing"))]` re-export of `ceremony` for back-compat | `ceremony` |

The lib gains no CLI dependency. The binary is the only place `clap` and process I/O live.

### `ceremony` interface

```rust
/// Generate a root signing key from a caller-supplied RNG.
/// The binary always passes OsRng; tests pass a seeded RNG for determinism.
pub fn generate_root(rng: impl CryptoRng + RngCore) -> SigningKey;

/// Build the did.json document S1's verifier accepts, carrying one or more
/// root keys (more than one only during a root rotation overlap).
///
/// Each key becomes one verificationMethod entry with id `{did}#root-{n}`
/// (n from 1), and each is referenced once from `assertionMethod`. These are
/// the only two members `TrustDocument::parse` reads. Produces exactly the
/// shape it accepts: kty=OKP, crv=Ed25519, x = URL_SAFE_NO_PAD(pubkey bytes).
///
/// # Errors
/// TrustError if `did` is not a did:web identifier or `roots` is empty.
pub fn build_document(did: &DidWeb, roots: &[VerifyingKey])
    -> Result<serde_json::Value, TrustError>;

// mint_cert moves here unchanged from fixtures.
pub fn mint_cert(root: &SigningKey, publisher: &VerifyingKey, key_id: &str, not_after: &str)
    -> PublisherCert;
```

`build_document` output must round-trip: `TrustDocument::parse(did, &to_vec(build_document(did, &[k])?)?)?.assertion_keys() == [k]`. That round-trip is the anti-drift test, and it is the reason the builder lives beside the parser.

## Subcommands

### `gen-root`

```
greentic-trust gen-root
```
- Generates an Ed25519 keypair with `OsRng`.
- **stdout:** private key, PKCS#8 DER, base64, one line.
- **stderr:** `x` (base64url), the ready-to-use `kid`, and `warning: a private key was written to stdout`.
- No file writes, no network.
- There is deliberately no `--seed` flag: a seed on a production keygen is a footgun. Determinism for tests lives in `generate_root(rng)` at the library level, driven by a seeded RNG in the test only.

### `build-doc`

```
greentic-trust build-doc --did did:web:trust.research.greentic.cloud \
  --root-public <x-b64url> [--root-public <x-b64url> ...]
```
- **stdout:** the `did.json` document.
- `--root-public` is repeatable. Two or more keys produce a multi-key document — used only during a root-rotation overlap so an old and a new root are both valid while the TTL drains. `kid`s are auto-numbered `#root-1`, `#root-2`, …
- Requires: the output parses under `TrustDocument::parse(&did, …)` and its `id` equals `--did`. A malformed DID or a non-32-byte key is a clean error, never a panic.

### `verify-doc`

```
greentic-trust verify-doc --did <did> --expected-root <x-b64url> \
  ( --url https://… | --file <path> )
```
- `--url` resolves through S1's `HttpResolver` (HTTPS-only, redirects disabled — the transport hardened in S1's final review). `--file` reads and parses locally.
- Parses the document, then asserts one of its assertion keys equals `--expected-root`.
- **Exit 0** with `OK: <did> serves the expected root`. **Non-zero** with the expected and found keys named. Never a silent pass.
- This dogfoods the runtime verifier: the operator confirms a publish with the same code the runner uses.

## Error handling

Everything is `Result<_, TrustError>` plus a thin binary-level error that maps `TrustError` to an exit code and a stderr message. No `unwrap`/`expect`/`panic!` on any path the binary can reach with bad input — a malformed DID, a short key, an unreachable URL, a mismatched root all produce a named error and a non-zero exit. `gen-root`'s only failure is RNG, which must surface as an error, not a panic.

## Testing

Every behaviour that matters has a test, and each carries the mutation that must turn it red.

| Invariant | Test | Mutation that must fail it |
|---|---|---|
| **Anti-drift** | `build_document(did, &[k])` → `TrustDocument::parse` → `assertion_keys() == [k]` | emit wrong `x`, or `kty`/`crv` ≠ OKP/Ed25519 → parse rejects |
| Binding | `build_document` for did A produces `id == A` | hardcode a different `id` → `TrustDocument::parse` returns `BindingMismatch` |
| Multi-key rotation | two roots → a two-entry `assertionMethod`, both parse | drop the second key → `assertion_keys().len()` falls to 1 |
| gen-root determinism | `generate_root(seeded_rng)` yields the exact known `x` | — |
| Base64 discipline | the JWK `x` is `URL_SAFE_NO_PAD`, not `STANDARD` | swap to `STANDARD` → round-trip `parse` fails on a key with `+`/`/`/`=` bytes |
| verify-doc match | expected == published → exit 0 | ignore `--expected-root` → a mismatch still exits 0 |
| verify-doc mismatch | expected ≠ published → non-zero exit | — |
| stdout/stderr split | `assert_cmd`: private on stdout, public on stderr, neither leaks | write the private key to stderr too → the test sees it in both streams |

The anti-drift row is the whole reason the builder ships in this crate: the bytes `build-doc` emits are parsed by the same `TrustDocument` the runner uses at runtime. If they diverge, this test is red — not production.

Mutation-check protocol is S1's (documented in the S1 plan's Global Constraints): stage the file first so `git diff --stat` has a baseline, since an untracked file's diff is always empty.

## The runbook

`docs/runbooks/root-ceremony.md`. The human procedure the tool serves.

- **Per-environment generation.** research/staging: run `gen-root` on a trusted machine, pipe the private key into a secret (`wrangler secret put` or a GitHub Actions secret). production: run `gen-root` on an air-gapped machine; the private key never leaves it except as sealed material into hardware/KMS. **Production owner: named in the runbook, currently TBD → Maarten. This is the "org-blocked" item `root_verifier.rs:51` refers to.**
- **Build and publish.** `build-doc` for the environment's DID → `did.json`. Upload to the R2 bucket serving that origin. Bind `trust.<env>.greentic.cloud` (prod: `trust.greentic.cloud`). The runbook states the token landmine explicitly: the CI `CLOUDFLARE_API_TOKEN` cannot do this, so binding is out-of-band, exactly as `id.research.greentic.cloud` is today. Follow `tenant-core/cloudflare_api.rs` (`ensure_r2_bucket`, `configure_custom_hostname`) for the API shapes if scripting it against a scoped-up token.
- **Verify.** `verify-doc --url https://trust.<env>.greentic.cloud/.well-known/did.json --expected-root <x>` — the operator proves the publish is correct with the runtime verifier before trusting it.
- **Root rotation.** `gen-root` a new root → `build-doc` with both old and new `--root-public` → publish the multi-key document → after the S1 TTL (600s) drains and consumers hold the new key, publish again with only the new root. Note: offline-pinned consumers (S5) do not see the change until they refetch.
- **Revocation.** Remove the compromised key from the published document and republish. Propagation is bounded by the TTL; pinned consumers lag until refetch. There is no CRL — the live document is the revocation surface, which is why the TTL is short.

## Out of scope for S2

- CI automation of R2 upload / DNS (blocked on token scope; becomes a job when the token is scoped up).
- Actual root key generation for production (the ceremony itself — needs the named owner and hardware).
- Store-server cert issuance (S3, consumes `ceremony::mint_cert`).
- Runner wiring (S4), SDK re-anchor + offline pin store (S5).

## What this does not buy

The tool makes the ceremony repeatable and the document verifiable; it does not make the production root exist. That still requires a human, an air-gapped machine, and an owner. S2 removes every excuse except the one that was always the real blocker — someone has to hold the ceremony.

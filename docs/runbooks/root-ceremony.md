# Root ceremony runbook

How to generate, publish, verify, rotate, and revoke a Greentic did:web trust root.
The `greentic-trust` binary (built with `cargo build --features cli`) does the crypto;
this runbook is the human procedure around it.

## Environments

| Environment | DID | Root custody |
|---|---|---|
| research | `did:web:trust.research.greentic.cloud` | secret manager |
| staging | `did:web:trust.staging.greentic.cloud` | secret manager |
| production | `did:web:trust.greentic.cloud` | offline ceremony |

The trusted DID is configured into consumers as a **URL, not a secret** — it belongs in
ordinary config. Only the private root key is secret.

**Production owner: TBD — assign before the first production ceremony.** This is the
"org-blocked" item `root_verifier.rs:51` refers to: the production root does not exist
until someone holds the ceremony on an air-gapped machine.

## 1. Generate a root

research / staging — on a trusted operator machine:

    greentic-trust gen-root | wrangler secret put GREENTIC_TRUST_ROOT_RESEARCH
    # the public JWK x and a suggested kid are printed to stderr — record the x

production — on an **air-gapped** machine:

    greentic-trust gen-root > /dev/shm/root.seed   # stdout is the private seed (base64)
    # transfer the public x (printed to stderr) out; move the sealed seed into hardware/KMS;
    # the private seed never leaves the air-gapped machine in the clear.

The private key is the raw 32-byte Ed25519 seed, base64. `gen-root` never encrypts it —
your secret manager or hardware does the sealing.

## 1b. Mint a publisher certificate

A publisher certificate lets the runner verify that a publisher's signing key is
vouched for by the Greentic root — replacing the flat trusted-signer allowlist.
Mint one at publisher onboarding (and at key rotation), offline, over the
publisher's **public** key:

    wrangler secret get GREENTIC_TRUST_ROOT_RESEARCH | greentic-trust mint-cert \
      --publisher-key <publisher-x-base64url> \
      --key-id pk_acme_1 \
      --not-after 2027-01-01T00:00:00Z \
      > acme.cert.json

The root private seed is read from **stdin**, never a flag, so it stays out of
`ps` output and shell history. Everything else — the publisher's public key, the
key id, the expiry — is non-secret. The `PublisherCert` JSON on stdout is what
store-server stores against the publisher and embeds into `describe.json` at
publish (S3b).

Certs are minted at onboarding/rotation, not per publish, so the root only comes
out for this step and step 1 — never for a routine publish. Pick a `--not-after`
that matches your rotation cadence; an expired cert is refused, so re-mint before
it lapses.

## 2. Build the document

    greentic-trust build-doc \
      --did did:web:trust.research.greentic.cloud \
      --root-public <x-from-step-1> \
      > did.json

`build-doc` produces exactly the bytes the runtime verifier accepts. Publishing this to
`https://trust.research.greentic.cloud/.well-known/did.json` completes the resolution.

## 3. Publish (manual — see the token note)

Upload `did.json` to the R2 bucket serving the environment's origin, at the path
`/.well-known/did.json`, and bind `trust.<env>.greentic.cloud` to it (production:
`trust.greentic.cloud`).

**Token note.** The CI `CLOUDFLARE_API_TOKEN` lacks `Workers Routes:Edit` and has no R2
scope — declaring routes in wrangler makes `wrangler deploy` fail *after* upload
(Cloudflare error 10000). This is why every custom domain in the platform, e.g.
`id.research.greentic.cloud`, is bound out-of-band and persists across deploys. Bind the
trust hostname the same way, or use a scoped-up token. The Cloudflare API shapes to script
against, if you do scope one up, are in `greentic-tenant-manager/crates/tenant-core/src/cloudflare_api.rs`
(`ensure_r2_bucket`, `configure_custom_hostname`).

The document must be **static** and on an origin that serves **no artifacts** — never the
store server. A host that serves both the key and the artifacts can substitute both at once.

## 4. Verify the publish

    greentic-trust verify-doc \
      --did did:web:trust.research.greentic.cloud \
      --expected-root <x-from-step-1>

This resolves the live document with the same code the runner uses and confirms it serves
your key. Do not trust a publish you have not verified. To inspect a local file instead,
add `--file did.json`.

## 5. Rotate the root

1. `gen-root` a new root; stash its private key as in step 1.
2. Build a document carrying **both** roots so signatures under either verify during the overlap:

       greentic-trust build-doc --did <did> \
         --root-public <old-x> --root-public <new-x> > did.json

3. Publish (step 3) and verify (step 4, once per key).
4. After the TTL (600s) has drained and consumers hold the new key, rebuild with the new
   root only and republish.

Offline-pinned consumers do not see a rotation until they refetch.

## 6. Revoke a root

Remove the compromised key from the published document and republish. There is no CRL —
the live document is the revocation surface, which is why the TTL is short (600s). Pinned
consumers lag until they refetch, so a rotation of the compromised key should follow.

#!/usr/bin/env bash
set -euo pipefail

# Canonical local CI gate for greentic-trust.
#   bash ci/local_check.sh

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

echo "==> cargo fmt"
cargo fmt --all -- --check

echo "==> cargo clippy"
cargo clippy --all-targets --all-features --locked -- -D warnings

echo "==> cargo test"
cargo test --all-targets --all-features --locked

echo "==> cargo doc"
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features --locked

echo "All checks passed."

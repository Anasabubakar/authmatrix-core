#!/usr/bin/env bash
# Re-records evidence/native-host from the real-host tests. Requires the Rust toolchain.
set -euo pipefail
cd "$(dirname "$0")/.."
root="$PWD"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/stellar-cargo-target}"
cd fixtures/nested-auth
AUTHMATRIX_WRITE_EVIDENCE="$root/evidence/native-host/results.json" \
AUTHMATRIX_RECORDED_AT="$(date -u +%FT%TZ)" \
  cargo test -j2 -- --nocapture 2>&1 | grep -v "Writing test snapshot" | tee "$root/evidence/native-host/cargo-test.txt"

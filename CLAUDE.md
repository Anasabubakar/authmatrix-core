# authmatrix-core: working notes

Commands (repo root): `pnpm install --frozen-lockfile`, `pnpm run typecheck`, `pnpm test`, `pnpm run build`, `pnpm run schema` / `check:schema`, `pnpm run vectors` / `check:vectors`, `pnpm run conformance`.
Rust: `export CARGO_TARGET_DIR=/home/gamp/.cache/stellar-cargo-target` always; use `-j2`. `(cd adapters/rust && cargo build --release -j2 && cargo test -j2)`; `(cd fixtures/nested-auth && cargo test -j2)`; wasm only via `stellar contract build` in `fixtures/nested-auth`.
Evidence: `pnpm run evidence:native` (rewrites evidence/native-host), `pnpm run evidence:testnet` (network, needs funded alias `authmatrix-source` in ~/.config/stellar and evidence/testnet/deployment.json).
Constraints: SDK pinned at 17.2.1 (xdr is immutable classes, read as properties); scripts run with `node --experimental-strip-types` (no enums or parameter properties); never commit S... keys; no mainnet; no pushes or GitHub repos; a missing Rust adapter fails tests.
Commit rules: granular, explicit `git add` paths, no AI co-author trailers.
Unfinished: contract-account (C...) signers and delegated-signing host evidence; npm publish; GitHub publishing and a CI run; independent maintainer review.

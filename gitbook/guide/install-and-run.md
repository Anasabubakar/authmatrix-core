# Install and run

Published to npm as `@anas.abubakar/authmatrix-core`. From a clone (Node >= 22, pnpm 11, Rust stable; the stellar CLI 28.1.0 only to rebuild the wasm):

```bash
git clone <this repo> && cd authmatrix-core
pnpm install --frozen-lockfile
export CARGO_TARGET_DIR=$HOME/.cache/stellar-cargo-target
(cd adapters/rust && cargo build --release -j2 && cargo test -j2)   # Rust adapter + its own tests
pnpm test                                                           # 113 tests; fails if the Rust adapter is missing
pnpm run conformance                                                # both adapters, byte-for-byte
(cd fixtures/nested-auth && cargo test -j2)                         # real-host tests over the committed vectors
```

Re-recording evidence (rewrites files; the testnet step needs network and a funded alias):

```bash
pnpm run evidence:native
pnpm run evidence:testnet
```

Packaging for the inspector: `pnpm run build && pnpm pack` produces `anas.abubakar-authmatrix-core-0.1.1.tgz` containing `dist/`, the JSON Schemas, the vectors and the evidence summaries.

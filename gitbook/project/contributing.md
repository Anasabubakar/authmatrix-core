# Contributing

Thanks for looking. This is a small protocol-testing project; honesty about what is verified matters more than breadth.

## Setup

Node >= 22 (CI uses 24), pnpm 11, Rust stable with the `stellar` CLI 28.1.0 for contracts.

```bash
pnpm install --frozen-lockfile
export CARGO_TARGET_DIR=$HOME/.cache/stellar-cargo-target     # shared target, keeps disk use low
(cd adapters/rust && cargo build --release -j2 && cargo test -j2)
(cd fixtures/nested-auth && cargo test -j2)
pnpm run typecheck && pnpm test && pnpm run check:schema && pnpm run check:vectors
```

Build fixture contracts only with `stellar contract build` (plain `cargo build` for wasm is rejected by the SDK).

## Rules

- Do not invent cryptography. Signing and hashing come from the SDK, `ed25519-dalek` or `sha2`.
- Expected values in tests come from the spec, RFCs or recorded host output, never from the implementation under test.
- Changing a vector or a canonical rule is a format change: bump `formatVersion`, regenerate with `pnpm vectors`, re-run both adapters and the host tests, and re-record evidence.
- Evidence files are recordings. Do not hand-edit them. Re-record with `pnpm run evidence:native` / `pnpm run evidence:testnet` and commit the new output with its environment.
- Never commit secret keys (`S...`). Test keys are derived from public phrases and protect nothing.
- Network tests are opt-in and separate from CI.
- Commits: one logical change each, conventional prefixes, no co-author trailers crediting tools.

# Changelog

## 0.1.0 (unreleased)

- Vector format `authmatrix-vectors` 1.0.0, adapter protocol `authmatrix-adapter/1`, evidence format 1.0.0, with JSON Schemas generated from zod.
- Four vectors (ADDRESS_V2 and legacy ADDRESS nested relay, a synthetic token-operations tree, a historical-labelled public-passphrase legacy entry) and 27 mutation vectors across seven fields, each with a re-signed positive control.
- TypeScript adapter (stellar-sdk 17.2.1 helpers) and Rust adapter (stellar-xdr =28.0.1, sha2, ed25519-dalek) plus a conformance runner; both agree byte-for-byte.
- RFC 8032 Ed25519 vectors as an independent signing source.
- Nested-call fixture contracts (soroban-sdk =28.0.0) with real-host tests via `set_auths` (protocol 28 host).
- Recorded testnet (protocol 29) `simulateTransaction` enforce-mode results: originals accepted, mutations refused by account authentication, controls accepted.
- Reviewed SEP-41 (v0.5.2) and Stellar Asset Contract argument mappings; unknown values stay raw.

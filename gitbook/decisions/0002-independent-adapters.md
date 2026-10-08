# ADR 0002: Independence of the two adapters

Status: accepted, 2026-10-07.

## Decision

The second adapter is written in Rust on `stellar-xdr` =28.0.1, `sha2` =0.10.9 and `ed25519-dalek` =2.2.0. The first is TypeScript on `@stellar/stellar-sdk` 17.2.1 using its official helpers. A second TypeScript or Python wrapper around the same SDK was rejected: it would share the xdr classes, the hashing and the signing code, so agreement would prove only that one library agrees with itself.

## What independence does and does not give

Gives: different language, XDR codec, hash and ed25519 implementation, strkey implementation, and entry-assembly code. A bug in any of those is caught by disagreement.

Does not give: independence of the XDR *definition*. Both codebases derive from the upstream `stellar-xdr` `.x` files. A mistake in the protocol definition would be shared; the real host runs cover that.

## Protocol

A line-oriented JSON protocol (`authmatrix-adapter/1`, in `SPEC.md`) keeps adapters free of shared code. Adding a third adapter (Go, Python) means implementing six operations and being added to `scripts/conformance.ts`.

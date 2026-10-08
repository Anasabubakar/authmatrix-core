# authmatrix-core

Soroban authorization entries changed in Protocol 27. This repo checks that two independent implementations compute the same signature payload for the same entry, and that the real Soroban host agrees.

AuthMatrix core is a language-neutral, versioned set of **authorization vectors** (with single-field **mutation vectors**), **two independent adapters** (TypeScript on `@stellar/stellar-sdk` 17.2.1, Rust on `stellar-xdr`), a **conformance runner**, a pair of **nested fixture contracts**, and **recorded host evidence** (offline with the Soroban host, and live on Stellar testnet). The browser UI that consumes it is a separate repo, `authmatrix-inspector`.

Background: CAP-71 (Protocol 27) added `SOROBAN_CREDENTIALS_ADDRESS_V2` and `..._ADDRESS_WITH_DELEGATES`, whose signature payload is `ENVELOPE_TYPE_SOROBAN_AUTHORIZATION_WITH_ADDRESS` (binds the signer's address). The legacy `ADDRESS` payload is still valid. See the SDK's [Protocol 27 migration page](https://stellar.github.io/js-stellar-sdk/migration/protocol-27-soroban-auth/). Testnet reported Protocol 29 when the evidence here was recorded.

## What it demonstrates (all of this was run)

- **Canonical bytes agree.** `pnpm run conformance` drives 4 vectors and 27 mutations through both adapters: 372 checks pass and the adapters agree on 74 operation results byte-for-byte (preimage XDR, SHA-256 payload hash, signature, unsigned and signed entry XDR).
- **Mutations invalidate the signature.** Changing recipient, amount, network, nonce, expiry, function or contract id changes the payload hash, and the original ed25519 signature no longer verifies.
- **The real host agrees.** The original entries are accepted and the mutated entries refused, with each refusal attributed to account authentication, and each mutated call re-signed and accepted as a positive control:
  - offline, `soroban-sdk` testutils `set_auths` (protocol 28 host): 34 recorded cases, `evidence/native-host/`;
  - live, testnet `simulateTransaction` with `authMode: "enforce"` (protocol 29): 28 recorded cases, raw RPC requests and responses in `evidence/testnet/`.
- **The signing primitive is checked against a standard.** RFC 8032 section 7.1 vectors are verified in both adapters, in the SDK and in OpenSSL.

Example (from `evidence/testnet/summary.json`, a refused mutation, verbatim host text trimmed): `HostError: Error(Auth, InvalidAction); host diagnostic: failed account authentication with Error(Crypto, InvalidInput)`.

## Install and run

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

## Supported versions

| Component | Version |
|---|---|
| `@stellar/stellar-sdk` | 17.2.1 (exact) |
| `stellar-xdr` (Rust adapter) | =28.0.1 |
| `soroban-sdk` (fixtures) | =28.0.0 (host crate `soroban-env-host` 28.0.2) |
| Credential types with vectors | `address` (legacy), `addressV2` |
| Credential types decode-only | `addressWithDelegates`, `sourceAccount` |
| Testnet protocol with recorded host results | 29 |

## Repository map

- `vectors/` reviewed vectors and RFC 8032 vectors; `schema/` generated JSON Schemas (formats in [SPEC.md](https://github.com/Anasabubakar/authmatrix-core/blob/main/SPEC.md))
- `adapters/typescript`, `adapters/rust` the two adapters (protocol `authmatrix-adapter/1`)
- `fixtures/nested-auth` outer/inner contracts, real-host tests, committed wasm and its hashes
- `evidence/` native results, testnet results and raw RPC recordings, conformance report
- `docs/host-verification.md` exactly what the host checks do and do not establish; `docs/adr/` decisions and the comparison with existing tools

## Known tokens

Calls named like SEP-41 (`transfer`, `transfer_from`, `approve`, `burn`, `burn_from`, `allowance`, ...) and the Stellar Asset Contract extras (`mint`, `clawback`, `set_admin`, ...) are decoded by a reviewed table in `src/tokens.ts`, checked in tests against signature lines copied from SEP-41 v0.5.2 and `soroban-sdk` 28.0.0. SEP-41 itself defines no `mint` or `clawback` function (events only), so those are labelled as Stellar Asset Contract conventions. Matching is by function name, arity and argument types only: a hit means "token-shaped call", not "this contract is a token". Anything that does not fit stays raw with its XDR. Amounts are exact integers; token decimals are not in an entry and are never assumed.

## Limitations

- Fixture contracts hold no balances; the inner `transfer` only requires authorization and returns the amount.
- Only classic-account (`G...`) ed25519 signers have vectors and host evidence. Contract-account signers, custom `__check_auth`, delegated signing and source-account credentials are not host-verified (delegated entries decode only).
- Testnet runs are simulations: nothing was submitted, nonces were not consumed. The native host is protocol 28, testnet protocol 29; neither is mainnet, which this project never contacts. The public-network vector is labelled `historical-unverified`.
- The reviewed vectors were first produced by the SDK path. Their independent confirmation is the Rust adapter, OpenSSL, RFC 8032 and the host; a defect in the shared upstream XDR definition is caught only by the host runs.
- The ed25519 verification rules of the two adapters (noble vs dalek `verify`) can differ on malleable edge-case encodings; no vector covers those.
- Test keys are derived from public phrases and protect nothing. Never fund them on a real network.
- No audit, no safety claim, and no wallet or SDK maintainer has reviewed this. A decoded authorization is not a statement about what contracts do with it.

## Licence

MIT. See [LICENSE](https://github.com/Anasabubakar/authmatrix-core/blob/main/LICENSE), [CONTRIBUTING.md](https://github.com/Anasabubakar/authmatrix-core/blob/main/CONTRIBUTING.md), [SECURITY.md](https://github.com/Anasabubakar/authmatrix-core/blob/main/SECURITY.md).

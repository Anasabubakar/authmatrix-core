# AuthMatrix core: specification

Status: version one. Everything below is implemented and exercised by `pnpm test`, the Rust tests in `fixtures/nested-auth`, and the recorded evidence under `evidence/`.

## 1. User and problem

Wallet, SDK, relayer and contract authors who build or review Soroban authorization entries (`SorobanAuthorizationEntry`). Since Protocol 27 (CAP-71) the bytes a signer signs depend on the credential type, and the old and new payloads coexist. Two implementations that disagree on those bytes produce signatures a host rejects, and a signer who cannot see what an entry authorizes cannot judge it. AuthMatrix provides:

1. A language-neutral, versioned set of vectors with the canonical preimage, hash and signature, plus mutation vectors.
2. Two independent adapters that must reproduce the reviewed bytes, and a runner that proves they agree.
3. Evidence from the real Soroban host, offline and live on testnet, that signatures verify and that mutated entries are refused.
4. A decoder for known token calls (SEP-41 and Stellar Asset Contract) that leaves everything else raw.

## 2. Scope (version one)

In scope:
- Credential types `SOROBAN_CREDENTIALS_ADDRESS` (legacy payload) and `SOROBAN_CREDENTIALS_ADDRESS_V2` (address-bound payload, CAP-71), with an ed25519 classic-account (`G...`) signer, for build, sign, decode and verify.
- `SOROBAN_CREDENTIALS_ADDRESS_WITH_DELEGATES` and `SOURCE_ACCOUNT`: decode only (type, address, nonce, expiry, delegate count, invocation tree). No vectors sign delegated entries and there is no host evidence for them.
- Invocation trees of `ContractFn` invocations. `createContractHostFn` / `createContractV2HostFn` invocations decode as opaque XDR (`kind: "createContract"`).
- Mutation fields: recipient, amount, network, nonce, expiry, function, contractId.
- Host-backed verification with a nested pair of fixture contracts.

Non-goals:
- Contract-account (`C...`) signers and custom `__check_auth` logic. The vector format requires a `G...` address.
- Predicting contract effects, simulating a transaction's state changes, or any safety or audit claim. A decoded entry says what the signer authorizes at the XDR level; it does not say what the contracts do with that authority.
- Mainnet interaction of any kind. Public-network vectors are static data.
- A wallet, a signer service, or key management. Signing keys are public test phrases.
- Re-implementing cryptography. All signing and hashing is done by the SDK (`@noble/*`), `ed25519-dalek` or `sha2`.

## 3. Data model

### 3.1 Authorization (neutral model)

```
Authorization {
  networkPassphrase: string
  credentialType: "address" | "addressV2"
  address: G...                      // authorizing account, must equal the signer public key
  nonce: decimal int64 string
  signatureExpirationLedger: uint32
  rootInvocation: Invocation
}
Invocation { contractId: C..., functionName: string<=32, args: base64(ScVal XDR)[], subInvocations: Invocation[] }
```

### 3.2 Signature payload

Per CAP-71 as documented in the SDK's Protocol 27 migration guide (`https://stellar.github.io/js-stellar-sdk/migration/protocol-27-soroban-auth/`, read 2026-10-07):

- `address` (type 1): `HashIdPreimage.ENVELOPE_TYPE_SOROBAN_AUTHORIZATION { networkId, nonce, signatureExpirationLedger, invocation }`. Not bound to the address.
- `addressV2` (type 2) and `addressWithDelegates` (type 3): `ENVELOPE_TYPE_SOROBAN_AUTHORIZATION_WITH_ADDRESS { networkId, nonce, signatureExpirationLedger, address, invocation }`. For delegates the address is the top-level address.
- `payload = SHA-256(XDR(preimage))`, `networkId = SHA-256(passphrase)`.
- The signature stored in the credential is `scvVec([scvMap({public_key: bytes32, signature: bytes64})])`, keys sorted. The signature value format did not change in Protocol 27.

The guide's code samples use the v16 SDK accessor style (`entry.credentials().addressV2()`). `@stellar/stellar-sdk` 17.2.1 xdr values are immutable classes; the same data is read as properties (`entry.credentials.type === "sorobanCredentialsAddressV2"`, `entry.credentials.addressV2`). The adapter uses the 17.x API and the helpers the guide recommends (`authorizeEntry`, `buildAuthorizationEntryPreimage`, `inspectAuthEntry`).

### 3.3 Vector file (`schema/vector.v1.schema.json`)

`{ format: "authmatrix-vectors", formatVersion: "1.0.0", generator, vectors[] }`. Each vector:

| Field | Meaning |
|---|---|
| `id`, `title`, `labels[]` | Identity and labels (`synthetic`, `legacy`, `historical`, `host-verifiable`, `not-host-verified`, ...) |
| `signer` | `publicKey` and a derivation: `seed = SHA-256(UTF-8 phrase)`. Public, test-only key |
| `authorization` | The neutral model above |
| `expected` | `preimageType`, `preimageXdr`, `payloadHashHex`, `signatureHex`, `unsignedEntryXdr`, `signedEntryXdr`. The reviewed canonical bytes |
| `compatibility` | `protocol.min/max`, `status` (`current`, `legacy-still-valid`, `historical-unverified`), a note, and `hostVerified[]` entries pointing at evidence files |
| `mutations[]` | One per field: the mutated authorization, `changedPaths`, the mutated preimage and hash, an entry carrying the original signature, the expectation `hostExpectation: "reject"`, and a positive control: the same mutated tree freshly signed (`resignedEntryXdr`) which a host must accept |

Compatibility is a label, not an assumption: only protocols listed in `hostVerified` have a recorded host result. `legacy-pubnet-historical-transfer` is labelled `historical-unverified`; AuthMatrix never contacts mainnet.

Versioning: `formatVersion` is semver. Adding optional fields is a minor bump; changing a required field or a canonical byte rule is major. Consumers must reject a different major.

### 3.4 Adapter protocol (`schema/adapter-protocol.v1.schema.json`)

Newline-delimited JSON on stdin/stdout; `protocol: "authmatrix-adapter/1"`, an integer `id` echoed in the response, `op` and `params`. A response is `{ok: true, result}` or `{ok: false, error}`. Operations:

| op | params | result |
|---|---|---|
| `describe` | none | adapter name, language, XDR / signing / hash implementations, ops |
| `derive_key` | `phrase` | `publicKey` (G...), `publicKeyHex` |
| `build` | `authorization`, `phrase` | the `expected` object of a vector: preimage, hash, signature, unsigned and signed entry |
| `decode` | `entryXdr` | credential type, address, nonce, expiry, signature classification, delegate count, invocation tree with args as base64 ScVal |
| `verify` | `entryXdr`, `networkPassphrase` | rebuilt preimage and hash, `signatureValid`, `reason`. The expiry used is the one inside the entry |
| `ed25519_sign` | `secretKeyHex`, `messageHex` | public key and signature (RFC 8032) |

An adapter must refuse `build` when the phrase does not derive `authorization.address`, and must answer malformed input with `ok: false`, not a crash.

### 3.5 Evidence (`schema/evidence.v1.schema.json`)

`{ format: "authmatrix-evidence", kind, recordedAt, environment, limits[], results[] }`. A result is `{vectorId, case, expectation, outcome, detail}`. `case` is `original`, a mutation field, `<field>-resigned` (positive control), or a `control-*` case. Every evidence file states what it does not establish.

## 4. Independence of the adapters

| | TypeScript adapter | Rust adapter |
|---|---|---|
| Language/runtime | TypeScript on Node | Rust |
| XDR | `@stellar/stellar-sdk` 17.2.1 generated classes (`@stellar/js-xdr`) | `stellar-xdr` =28.0.1 (`rs-stellar-xdr`) |
| SHA-256 | `@noble/hashes` through the SDK | `sha2` =0.10.9 |
| ed25519 | `@noble/ed25519` through the SDK | `ed25519-dalek` =2.2.0 |
| Strkey | SDK `StrKey`/`Address` | `stellar-strkey` through `stellar-xdr` |
| Entry construction | SDK `authorizeEntry` / `buildAuthorizationEntryPreimage` | hand-assembled from generated types |

They share no source and no dependency. The XDR definitions both derive from are the same upstream `.x` files, so a mistake in the protocol definition itself would not be caught by agreement alone; that is covered by the real host runs. Two wrappers of one SDK would not satisfy this table.

The reviewed bytes in the vector file were first produced by the TypeScript path (`scripts/gen-vectors.ts`). The Rust adapter, the Soroban host (native and testnet) and an OpenSSL-based test each confirm them independently; none of those confirmations call the SDK.

## 5. What host verification does and does not establish

See `docs/host-verification.md`. In short: `set_auths` installs entries into the real host's enforcing authorization manager; the host itself matches entries to the executed call tree, rebuilds the payload, runs the built-in account's ed25519 check and consumes the nonce. It is not a transaction: there is no footprint, fee or resource accounting, and the ledger sequence and network id are set by the test. The testnet runs call `simulateTransaction` with `authMode: "enforce"` and therefore use the live host and ledger state, but nothing is submitted.

## 6. Failure classes

| Class | Behavior |
|---|---|
| Adapter disagreement | The runner reports each `(vector, op)` where results differ; exit code 1 |
| Reviewed value mismatch | Reported per check with expected and actual prefixes |
| Missing adapter | The runner and tests fail; a missing second adapter is never a skip |
| Malformed adapter input | `ok:false` with a message; the adapter stays alive |
| Evidence contradicting an expectation | `test/evidence.test.ts` fails |
| Live read failure | The testnet script exits non-zero; a failed read is never recorded as a rejection |

## 7. Architecture

```
src/vector.ts      zod schemas = source of truth for all JSON formats
src/entry.ts       SDK-backed build/decode/verify (TypeScript adapter core)
src/scval.ts       lossless typed ScVal view
src/tokens.ts      reviewed SEP-41 / SAC mappings, name+arity+type matching only
src/mutate.ts      deterministic mutations + diff paths
src/runner.ts      spawns adapters, checks, compares
adapters/typescript, adapters/rust
fixtures/nested-auth   outer/inner contracts + native host tests + wasm artifacts
scripts/           gen-vectors, gen-schema, conformance, testnet-evidence
vectors/, schema/, evidence/
```

## 8. Acceptance

1. `pnpm test` passes with the Rust adapter built (a missing adapter is a failure).
2. `pnpm run check:schema` and `pnpm run check:vectors` report up to date.
3. `cargo test` in `fixtures/nested-auth` passes against the committed vectors.
4. `evidence/testnet/summary.json` records originals accepted, mutations rejected by account authentication, and re-signed controls accepted, with the protocol version.
5. README states the limitations in section 2 and does not claim contract safety.

# ADR 0001: What AuthMatrix adds over existing tools

Status: accepted, 2026-10-07. Evidence below is what was read on that date. No competing tool was executed, and nothing here is a survey of all tools.

## Context

Protocol 27 (CAP-71) added `SOROBAN_CREDENTIALS_ADDRESS_V2` and `..._ADDRESS_WITH_DELEGATES` whose signature payload is the address-bound `ENVELOPE_TYPE_SOROBAN_AUTHORIZATION_WITH_ADDRESS`, while the legacy `ADDRESS` payload remains valid. Anyone who builds, signs or displays authorization entries now has two payload rules and a nested invocation tree to get right.

## What was read

- **js-stellar-sdk "Protocol 27 - Soroban authorization migration" page** (full text). It documents the four credential types, the address-bound payload, `authorizeEntry`, `buildAuthorizationEntryPreimage`, `authorizeInvocation` (V2 by default), delegated signing, and a checklist. Its code samples use the v16 accessor style (`entry.credentials().addressV2()`); SDK 17.2.1 xdr values are immutable classes read as properties. AuthMatrix pins 17.2.1 and uses the 17.x shape, and cites the page for the payload rules.
- **js-stellar-sdk unit tests** (`test/unit/base/auth.test.ts`, test names and structure only; I did not read every body). They cover `authorizeEntry` with a Keypair and callbacks, credential-type switching and payload differences (including "produces different signatures for different networks"), `authorizeInvocation`, nonce handling, delegate builders and `buildAuthorizationEntryPreimage`. They test the SDK against itself.
- **js-stellar-sdk 17.2.1 type declarations and `auth.js`** (read from the installed package). `inspectAuthEntry` and `checkAuthEntryReadiness` already return credential type, address, nonce, expiry, signers and the invocation. AuthMatrix uses these rather than re-deriving them.
- **Stellar Lab** (`stellar/laboratory` README). Describes an interactive toolkit for building, signing, simulating and submitting transactions, XDR-to-JSON conversion and a contract explorer. I did not run it, and its README does not mention authorization-entry vectors or a second independent implementation.
- **Freighter** (`stellar/freighter` README and `docs/docs/guide/signXdr.md`). The signing flow shows a review with Summary, Operation Details ("optionally walks through the invocation chain and highlights authorizations") and Raw XDR. I did not run the extension and did not inspect how it renders a given entry.
- **"Crucible"**. A web search for a Stellar or Soroban tool of that name returned only a Solana fuzzing framework by Asymmetric Research (from search-result summaries; I did not open its README) and Soroban's documentation on cargo-fuzz. I found no Stellar project called Crucible and make no statement about it.

## Gap this project fills

1. **A shared, versioned, language-neutral set of expected bytes** (vectors plus mutation vectors) that any implementation can be tested against. The SDK tests assert against the SDK's own output.
2. **Two implementations built on different XDR codebases** (JS SDK and `stellar-xdr` in Rust) required to agree byte-for-byte, with the protocol documented so a third can be added.
3. **Host-backed evidence** that those bytes are accepted by the real Soroban host and that single-field mutations are refused, on testnet at protocol 29 and offline with `set_auths`. Mutation expectations come with positive controls so a refusal can be attributed to the signature.
4. **A decoder that keeps unknown data raw** and maps known token calls through a reviewed SEP-41 / Stellar Asset Contract table.

## Decision

Build on the SDK (do not reimplement crypto), keep the product narrow (vectors, adapters, evidence, decode), and make the SDK's own helpers the TypeScript adapter. If the SDK or Stellar Lab later publishes equivalent shared vectors, contribute the vector format there instead of competing.

## Consequences

- The reviewed vectors were produced by the SDK path; independence comes from the Rust adapter, OpenSSL checks, RFC 8032 and the host, not from the generator.
- A decoded preview describes what an entry authorizes at the XDR level. It is not a statement about contract safety or effects, and no wallet comparison is claimed beyond what was read.
- Adoption by any wallet or SDK maintainer has not happened; nothing here implies endorsement.

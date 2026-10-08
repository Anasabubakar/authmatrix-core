# Overview

Soroban authorization entries changed in Protocol 27. This repo checks that two independent implementations compute the same signature payload for the same entry, and that the real Soroban host agrees.

AuthMatrix core is a language-neutral, versioned set of **authorization vectors** (with single-field **mutation vectors**), **two independent adapters** (TypeScript on `@stellar/stellar-sdk` 17.2.1, Rust on `stellar-xdr`), a **conformance runner**, a pair of **nested fixture contracts**, and **recorded host evidence** (offline with the Soroban host, and live on Stellar testnet). The browser UI that consumes it is a separate repo, `authmatrix-inspector`.

Background: CAP-71 (Protocol 27) added `SOROBAN_CREDENTIALS_ADDRESS_V2` and `..._ADDRESS_WITH_DELEGATES`, whose signature payload is `ENVELOPE_TYPE_SOROBAN_AUTHORIZATION_WITH_ADDRESS` (binds the signer's address). The legacy `ADDRESS` payload is still valid. See the SDK's [Protocol 27 migration page](https://stellar.github.io/js-stellar-sdk/migration/protocol-27-soroban-auth/). Testnet reported Protocol 29 when the evidence here was recorded.

Source: [authmatrix-core on GitHub](https://github.com/Auth-Matrix/authmatrix-core). Releases: [GitHub releases](https://github.com/Auth-Matrix/authmatrix-core/releases).

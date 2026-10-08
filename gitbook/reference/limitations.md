# Limitations

- Fixture contracts hold no balances; the inner `transfer` only requires authorization and returns the amount.
- Only classic-account (`G...`) ed25519 signers have vectors and host evidence. Contract-account signers, custom `__check_auth`, delegated signing and source-account credentials are not host-verified (delegated entries decode only).
- Testnet runs are simulations: nothing was submitted, nonces were not consumed. The native host is protocol 28, testnet protocol 29; neither is mainnet, which this project never contacts. The public-network vector is labelled `historical-unverified`.
- The reviewed vectors were first produced by the SDK path. Their independent confirmation is the Rust adapter, OpenSSL, RFC 8032 and the host; a defect in the shared upstream XDR definition is caught only by the host runs.
- The ed25519 verification rules of the two adapters (noble vs dalek `verify`) can differ on malleable edge-case encodings; no vector covers those.
- Test keys are derived from public phrases and protect nothing. Never fund them on a real network.
- No audit, no safety claim, and no wallet or SDK maintainer has reviewed this. A decoded authorization is not a statement about what contracts do with it.

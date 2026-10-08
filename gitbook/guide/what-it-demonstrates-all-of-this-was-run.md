# What it demonstrates (all of this was run)

- **Canonical bytes agree.** `pnpm run conformance` drives 4 vectors and 27 mutations through both adapters: 372 checks pass and the adapters agree on 74 operation results byte-for-byte (preimage XDR, SHA-256 payload hash, signature, unsigned and signed entry XDR).
- **Mutations invalidate the signature.** Changing recipient, amount, network, nonce, expiry, function or contract id changes the payload hash, and the original ed25519 signature no longer verifies.
- **The real host agrees.** The original entries are accepted and the mutated entries refused, with each refusal attributed to account authentication, and each mutated call re-signed and accepted as a positive control:
  - offline, `soroban-sdk` testutils `set_auths` (protocol 28 host): 34 recorded cases, `evidence/native-host/`;
  - live, testnet `simulateTransaction` with `authMode: "enforce"` (protocol 29): 28 recorded cases, raw RPC requests and responses in `evidence/testnet/`.
- **The signing primitive is checked against a standard.** RFC 8032 section 7.1 vectors are verified in both adapters, in the SDK and in OpenSSL.

Example (from `evidence/testnet/summary.json`, a refused mutation, verbatim host text trimmed): `HostError: Error(Auth, InvalidAction); host diagnostic: failed account authentication with Error(Crypto, InvalidInput)`.

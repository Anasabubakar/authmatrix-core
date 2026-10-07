# What host-backed verification does and does not establish

Two host runs back the vectors. Both use the real Soroban host (`soroban-env-host`); neither mocks authorization.

## 1. Native: `soroban-sdk` testutils `Env::set_auths`

Code: `fixtures/nested-auth/contracts/outer/src/test.rs`. Run: `cd fixtures/nested-auth && cargo test -j2`. Recorded: `evidence/native-host/`.

What `set_auths` does, from reading `soroban-sdk` 28.0.0 (`Env::set_auths`) and `soroban-env-host` 28.0.2 (`Host::set_authorization_entries`, `auth.rs`): it replaces the host's authorization manager with an **enforcing** one built from the supplied entries. This is not `mock_all_auths`/`mock_auths`; the SDK doc says it "requires valid signatures for the authorization to be successful".

What the host then really does when a contract calls `require_auth`:

| Step | Source function (soroban-env-host 28.0.2) | Real here? |
|---|---|---|
| Match the executing call (contract, function, args) against the entry's invocation tree, including nesting | `maybe_authorize_invocation` / `InvocationTracker` | yes |
| Rebuild the signature payload from the host's network id, the entry's nonce, expiry, address (for V2) and invocation | `get_signature_payload` (legacy and address-bound `HashIdPreimage` variants) | yes |
| Verify the account signature: load the account ledger entry, check signer ordering and weight vs thresholds, call ed25519 verification | `check_account_authentication`, `verify_sig_ed25519` | yes (built-in account contract) |
| Check `signature_expiration_ledger` against the ledger sequence and the maximum, then consume the nonce | `verify_and_consume_nonce` | yes |
| Emit diagnostic events such as "failed account authentication with error" | `maybe_authorize_invocation` | yes, and the test uses them to tell a signature refusal from "no entry matched" |

Order matters: authentication (signature) runs before expiry and nonce checks, so a mutated entry fails with "failed account authentication", while a correctly signed but expired entry would fail with "signature has expired".

What is **not** real in the native run:
- There is no transaction envelope, footprint, fee, resource metering or network.
- The ledger sequence (500) and network id (SHA-256 of the vector's passphrase) are values the test sets, not values read from a network.
- The signer's classic account entry is synthetic (master weight 1, thresholds 1) and added directly to host storage.
- Contracts run natively (compiled into the test), not as the deployed wasm.
- The host is `soroban-env-host` 28.0.2, protocol 28 in the recorded environment, not testnet's protocol 29.
- Host-error text is a single `Error(Auth, InvalidAction)` for every refusal; the diagnostic event is what distinguishes the reason.

Controls recorded alongside each vector: no auth entries at all (refused, no signature event), the unsigned entry (refused at authentication), and for every mutation a **re-signed** mutated entry (accepted), which shows that the refusal of the original-signature variant is about the signature, not about a malformed call.

## 2. Live: Stellar testnet `simulateTransaction` with `authMode: "enforce"`

Code: `scripts/testnet-evidence.ts` (opt-in, needs network). Recorded: `evidence/testnet/summary.json` and one raw RPC request/response per case under `evidence/testnet/raw/`.

- The RPC at `https://soroban-testnet.stellar.org` reported version 29.0.0 and protocol 29 when recorded.
- The fixture wasm (built with `stellar contract build`; hashes in `evidence/testnet/deployment.json`) was deployed with the stellar CLI using a throwaway funded account. The vector signer's account was created via friendbot so that the built-in account check has a ledger entry.
- Each case builds an `invokeHostFunction` transaction with the signed entry in its `auth`, and asks the RPC to simulate it in enforce mode. In enforce mode the supplied entries are used and checked by the live host against live ledger state.
- The live variants reuse each static vector's structure with the deployed contract ids and `expiry = latest ledger + 5000`. Both adapters built the live entries and agreed byte-for-byte before the request was sent.
- Rejections are recorded with the host's own text. All 14 rejected mutations carry the diagnostic "failed account authentication with Error(Crypto, InvalidInput)", i.e. the account's signature check refused the entry.
- The **network** mutation cannot flip the passphrase of a single live network, so it is run as: sign the original call under a different passphrase and submit to testnet. The payload the host rebuilds (testnet network id) differs from the signed one, which is the same inequality.
- Re-signed controls were accepted for every field except network (the original is that control).

What the live run does **not** establish:
- Nothing was submitted; this is simulation. Nonces were not consumed and no state changed.
- Only the fixture contracts were run. The synthetic vectors (token operations, public-network passphrase) have no host result.
- Acceptance on testnet at protocol 29 says nothing about mainnet or other protocol versions; AuthMatrix does not contact mainnet.
- Both legacy `address` and `addressV2` entries were accepted by the protocol 29 testnet at recording time. That is an observation, not a guarantee about future protocols.

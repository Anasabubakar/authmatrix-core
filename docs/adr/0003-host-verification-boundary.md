# ADR 0003: Host verification boundary and how it was researched

Status: accepted, 2026-10-07.

## Decision

Use two host runs and describe each precisely (see `docs/host-verification.md`): `set_auths` in `soroban-sdk` 28.0.0 testutils for deterministic offline runs, and testnet `simulateTransaction` with `authMode: "enforce"` for the live host.

## Research

I read `soroban-sdk` 28.0.0 `Env::set_auths` and `soroban-env-host` 28.0.2 `Host::set_authorization_entries` and `auth.rs` (`maybe_authorize_invocation`, `authenticate`, `verify_and_consume_nonce`, the signature payload builder, `check_account_authentication`). `set_auths` creates an enforcing authorization manager, so unlike `mock_all_auths` it checks matching, payload, signature, expiry and nonce. The rest of the transaction pipeline is absent. The host reports all auth refusals as `Error(Auth, InvalidAction)`; the diagnostic event "failed account authentication" separates a signature refusal from "no matching entry".

## Consequences

- Every mutation test asserts that the refusal carried the authentication diagnostic, and pairs it with a re-signed positive control.
- The native host is protocol 28 (the crate version); testnet recorded protocol 29. Neither covers mainnet.
- Custom contract-account `__check_auth` and delegated signing are out of scope for host verification in version one.

//! Host-backed verification of AuthMatrix vectors with the real Soroban host (soroban-env-host,
//! via soroban-sdk testutils). Nothing here is mocked: `set_auths` installs the signed
//! SorobanAuthorizationEntry into the host's enforcing authorization manager, and the host itself
//! matches the invocation tree, checks the nonce and expiration, rebuilds the signature payload
//! (including the address-bound CAP-71 preimage), and runs the account's ed25519 check.
//!
//! What is real: matching of entries to the executed call tree, nonce consumption, signature
//! expiration vs ledger sequence, payload construction from the network id, and ed25519
//! verification by the built-in account contract. What is NOT: there is no transaction, no
//! footprint/fee/resource accounting, no RPC, and the ledger sequence and network id are values this
//! test sets (a fixed ledger and the testnet passphrase hash). Contracts run natively, not as wasm.
//! See evidence/native-host/ for recorded output and README for the live testnet counterpart.
extern crate std;

use crate::Outer;
#[allow(unused_imports)]
use std::prelude::v1::*;
use authmatrix_inner::Inner;
use sha2::{Digest, Sha256};
use soroban_sdk::{
    testutils::{Ledger, LedgerInfo},
    xdr::{
        AccountEntry, AccountEntryExt, AccountId, LedgerEntry, LedgerEntryData, LedgerEntryExt,
        LedgerKey, LedgerKeyAccount, Limits, PublicKey, ReadXdr, ScAddress, ScVal, SequenceNumber,
        SorobanAuthorizationEntry, Thresholds, Uint256, VecM,
    },
    Address, Env, TryFromVal, Val, Vec as SVec,
};
use std::{fs, path::PathBuf, rc::Rc, string::String, vec::Vec};

const LEDGER_SEQUENCE: u32 = 500;

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../vectors/authmatrix-vectors.v1.json")
}

fn load() -> serde_json::Value {
    serde_json::from_str(&fs::read_to_string(vectors_path()).expect("vectors file")).expect("vectors json")
}

fn network_id(passphrase: &str) -> [u8; 32] {
    Sha256::digest(passphrase.as_bytes()).into()
}

fn entry_from_b64(b64: &str) -> SorobanAuthorizationEntry {
    SorobanAuthorizationEntry::from_xdr_base64(b64, Limits::none()).expect("entry xdr")
}

fn address(env: &Env, strkey: &str) -> Address {
    Address::from_str(env, strkey)
}

/// A fresh host at the fixed ledger with the given network passphrase, the signer's classic account
/// present on the ledger (master weight 1, thresholds 1) so the built-in account contract can
/// authenticate it, and two outer instances plus the inner contract registered at the vector's ids.
fn env_for(passphrase: &str, signer: &str, ids: &Ids) -> Env {
    let env = Env::default();
    env.ledger().set(LedgerInfo {
        protocol_version: env.ledger().get().protocol_version,
        sequence_number: LEDGER_SEQUENCE,
        timestamp: 1_700_000_000,
        network_id: network_id(passphrase),
        base_reserve: 5_000_000,
        min_temp_entry_ttl: 16,
        min_persistent_entry_ttl: 16,
        max_entry_ttl: 6_000_000,
    });
    let account_id = match ScAddress::from(&address(&env, signer)) {
        ScAddress::Account(a) => a,
        other => panic!("signer is not a classic account: {other:?}"),
    };
    let AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(_))) = account_id.clone();
    let key = Rc::new(LedgerKey::Account(LedgerKeyAccount { account_id: account_id.clone() }));
    let val = Rc::new(LedgerEntry {
        data: LedgerEntryData::Account(AccountEntry {
            account_id,
            balance: 1_000_000_000,
            seq_num: SequenceNumber(0),
            num_sub_entries: 0,
            inflation_dest: None,
            flags: 0,
            home_domain: Default::default(),
            thresholds: Thresholds([1, 1, 1, 1]),
            signers: VecM::default(),
            ext: AccountEntryExt::V0,
        }),
        last_modified_ledger_seq: 0,
        ext: LedgerEntryExt::V0,
    });
    env.host().add_ledger_entry(&key, &val, None).expect("add account entry");
    env.register_at(&address(&env, &ids.inner), Inner, ());
    env.register_at(&address(&env, &ids.outer), Outer, ());
    env.register_at(&address(&env, &ids.outer2), Outer, ());
    env
}

struct Ids {
    inner: String,
    outer: String,
    outer2: String,
}

/// Executes exactly the call described by `root` (contract, function, args) and reports
/// Ok(return value debug) when the host accepted it or Err(host error debug) when it refused.
fn call(env: &Env, root: &serde_json::Value) -> Result<String, String> {
    let contract = address(env, root["contractId"].as_str().unwrap());
    let func = root["functionName"].as_str().unwrap();
    let mut args: SVec<Val> = SVec::new(env);
    for a in root["args"].as_array().unwrap() {
        let sc = ScVal::from_xdr_base64(a.as_str().unwrap(), Limits::none()).unwrap();
        args.push_back(Val::try_from_val(env, &sc).unwrap());
    }
    match env.try_invoke_contract::<i128, soroban_sdk::Error>(&contract, &soroban_sdk::Symbol::new(env, func), args) {
        Ok(Ok(v)) => Ok(std::format!("returned {v}")),
        Ok(Err(e)) => Err(std::format!("conversion error: {e:?}")),
        Err(e) => {
            // The host reports every auth refusal as Error(Auth, InvalidAction). Its diagnostic
            // events distinguish "an entry matched the call but account authentication failed"
            // from "no entry matched". Capture that distinction.
            let auth_failed = env
                .host()
                .get_diagnostic_events()
                .map(|ev| ev.0.iter().any(|h| std::format!("{h:?}").contains("failed account authentication")))
                .unwrap_or(false);
            Err(std::format!(
                "{e:?} [diagnostic: {}]",
                if auth_failed { "failed account authentication (entry matched the call; signature/expiry/nonce check refused it)" } else { "no 'failed account authentication' event (no entry matched, or call failed elsewhere)" }
            ))
        }
    }
}

struct Outcome {
    vector_id: String,
    case: String,
    expectation: &'static str,
    outcome: &'static str,
    detail: String,
}

fn ids() -> Ids {
    // Contract ids are the strkeys committed in the vector file (derived from SHA-256 labels).
    let v = load();
    let v1 = &v["vectors"][0];
    let root = &v1["authorization"]["rootInvocation"];
    Ids {
        outer: root["contractId"].as_str().unwrap().into(),
        inner: root["subInvocations"][0]["contractId"].as_str().unwrap().into(),
        outer2: v1["mutations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["field"] == "contractId")
            .unwrap()["mutatedAuthorization"]["rootInvocation"]["contractId"]
            .as_str()
            .unwrap()
            .into(),
    }
}

fn run_all() -> Vec<Outcome> {
    let data = load();
    let ids = ids();
    let mut out = Vec::new();
    for v in data["vectors"].as_array().unwrap() {
        let labels: Vec<&str> = v["labels"].as_array().unwrap().iter().map(|l| l.as_str().unwrap()).collect();
        if !labels.contains(&"host-verifiable") {
            continue;
        }
        let vid = v["id"].as_str().unwrap().to_string();
        let signer = v["authorization"]["address"].as_str().unwrap();
        let passphrase = v["authorization"]["networkPassphrase"].as_str().unwrap();

        // The original, correctly signed entry must be accepted.
        let env = env_for(passphrase, signer, &ids);
        env.set_auths(&[entry_from_b64(v["expected"]["signedEntryXdr"].as_str().unwrap())]);
        let r = call(&env, &v["authorization"]["rootInvocation"]);
        out.push(Outcome { vector_id: vid.clone(), case: "original".into(), expectation: "accept", outcome: if r.is_ok() { "accepted" } else { "rejected" }, detail: r.unwrap_or_else(|e| e) });

        // Controls: no entries at all, and the unsigned entry.
        let env = env_for(passphrase, signer, &ids);
        let r = call(&env, &v["authorization"]["rootInvocation"]);
        out.push(Outcome { vector_id: vid.clone(), case: "control-no-auth".into(), expectation: "reject", outcome: if r.is_ok() { "accepted" } else { "rejected" }, detail: r.unwrap_or_else(|e| e) });
        let env = env_for(passphrase, signer, &ids);
        env.set_auths(&[entry_from_b64(v["expected"]["unsignedEntryXdr"].as_str().unwrap())]);
        let r = call(&env, &v["authorization"]["rootInvocation"]);
        out.push(Outcome { vector_id: vid.clone(), case: "control-unsigned".into(), expectation: "reject", outcome: if r.is_ok() { "accepted" } else { "rejected" }, detail: r.unwrap_or_else(|e| e) });

        // Each mutation: the mutated entry (original signature kept) and the call that matches the
        // mutated tree must be refused. For the network mutation the host's network id is the
        // mutated passphrase's, so the entry (signed for the original network) is evaluated by a host
        // on a different network.
        for m in v["mutations"].as_array().unwrap() {
            let mut_pass = m["mutatedAuthorization"]["networkPassphrase"].as_str().unwrap();
            let env = env_for(mut_pass, signer, &ids);
            env.set_auths(&[entry_from_b64(m["expected"]["entryXdrWithOriginalSignature"].as_str().unwrap())]);
            let r = call(&env, &m["mutatedAuthorization"]["rootInvocation"]);
            let field = m["field"].as_str().unwrap();
            out.push(Outcome { vector_id: vid.clone(), case: field.into(), expectation: "reject", outcome: if r.is_ok() { "accepted" } else { "rejected" }, detail: r.unwrap_or_else(|e| e) });

            // Positive control: the same mutated tree, freshly signed, must be accepted. This shows
            // the refusal above is about the signature and not about a malformed call.
            let env = env_for(mut_pass, signer, &ids);
            env.set_auths(&[entry_from_b64(m["expected"]["resignedEntryXdr"].as_str().unwrap())]);
            let r = call(&env, &m["mutatedAuthorization"]["rootInvocation"]);
            out.push(Outcome { vector_id: vid.clone(), case: std::format!("{field}-resigned"), expectation: "accept", outcome: if r.is_ok() { "accepted" } else { "rejected" }, detail: r.unwrap_or_else(|e| e) });
        }
    }
    out
}

#[test]
fn host_accepts_originals_and_rejects_mutations_and_controls() {
    let outcomes = run_all();
    assert!(!outcomes.is_empty(), "no host-verifiable vectors found");
    let mut failures = Vec::new();
    for o in &outcomes {
        let want = if o.expectation == "accept" { "accepted" } else { "rejected" };
        std::println!("{:<34} {:<16} expected {:<6} -> {:<8} {}", o.vector_id, o.case, o.expectation, o.outcome, o.detail);
        let is_mutation_reject = o.expectation == "reject" && !o.case.starts_with("control");
        let auth_failed = o.detail.contains("failed account authentication (entry matched");
        if is_mutation_reject && !auth_failed {
            failures.push(std::format!("{} / {}: rejected, but not by account authentication ({})", o.vector_id, o.case, o.detail));
        }
        if o.outcome != want {
            failures.push(std::format!("{} / {}: expected {} got {} ({})", o.vector_id, o.case, want, o.outcome, o.detail));
        }
    }
    if let Ok(path) = std::env::var("AUTHMATRIX_WRITE_EVIDENCE") {
        let env = Env::default();
        let results: Vec<serde_json::Value> = outcomes
            .iter()
            .map(|o| serde_json::json!({ "vectorId": o.vector_id, "case": o.case, "expectation": o.expectation, "outcome": o.outcome, "detail": o.detail }))
            .collect();
        let doc = serde_json::json!({
            "format": "authmatrix-evidence",
            "formatVersion": "1.0.0",
            "kind": "native-testutils",
            "recordedAt": std::env::var("AUTHMATRIX_RECORDED_AT").unwrap_or_default(),
            "environment": {
                "host": "soroban-env-host 28.0.2 via soroban-sdk =28.0.0 (testutils)",
                "protocolVersion": env.ledger().get().protocol_version,
                "ledgerSequence": LEDGER_SEQUENCE,
                "networkIdFrom": "SHA-256 of the vector's network passphrase",
                "contracts": "fixtures/nested-auth outer+inner, run natively (not wasm)",
            },
            "limits": [
                "No transaction envelope, footprint, fee or resource accounting was exercised.",
                "Ledger sequence and network id are set by the test, not read from a network.",
                "Contracts ran natively; the compiled wasm is exercised by the testnet evidence instead.",
                "The signer's classic account entry is synthetic (master weight 1, thresholds 1).",
            ],
            "results": results,
        });
        fs::write(path, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
    }
    assert!(failures.is_empty(), "host disagreed with vectors:\n{}", failures.join("\n"));
}

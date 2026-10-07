//! AuthMatrix adapter B (Rust). Implements `authmatrix-adapter/1`: newline-delimited JSON on
//! stdin/stdout. XDR comes from `stellar-xdr` (rs-stellar-xdr, generated from the same .x files but
//! a different code generator and language runtime than the JS SDK), hashing from `sha2`, and
//! ed25519 from `ed25519-dalek`. No code or dependency is shared with the TypeScript adapter.
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{BufRead, Write};
use std::str::FromStr;
use stellar_xdr::{
    AccountId, Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization,
    HashIdPreimageSorobanAuthorizationWithAddress, InvokeContractArgs, Limits, PublicKey, ReadXdr,
    ScAddress, ScBytes, ScMap, ScMapEntry, ScSymbol, ScVal, ScVec, SorobanAddressCredentials,
    SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
    SorobanCredentials, Uint256, VecM, WriteXdr,
};

const PROTOCOL: &str = "authmatrix-adapter/1";
type R<T> = Result<T, String>;

fn e<E: std::fmt::Display>(err: E) -> String {
    err.to_string()
}
fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}
fn b64_to_xdr<T: ReadXdr>(s: &str) -> R<T> {
    T::from_xdr_base64(s, Limits::none()).map_err(e)
}
fn to_b64<T: WriteXdr>(v: &T) -> R<String> {
    v.to_xdr_base64(Limits::none()).map_err(e)
}
fn str_field<'a>(v: &'a Value, k: &str) -> R<&'a str> {
    v.get(k).and_then(Value::as_str).ok_or_else(|| format!("missing string field {k}"))
}

struct Auth {
    passphrase: String,
    cred_v2: bool,
    address: ScAddress,
    nonce: i64,
    expiry: u32,
    root: SorobanAuthorizedInvocation,
}

fn invocation(v: &Value) -> R<SorobanAuthorizedInvocation> {
    let args = v.get("args").and_then(Value::as_array).ok_or("args must be an array")?;
    let mut scvals = Vec::new();
    for a in args {
        scvals.push(b64_to_xdr::<ScVal>(a.as_str().ok_or("arg must be a string")?)?);
    }
    let subs = v.get("subInvocations").and_then(Value::as_array).ok_or("subInvocations must be an array")?;
    let mut sub_out = Vec::new();
    for s in subs {
        sub_out.push(invocation(s)?);
    }
    Ok(SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: ScAddress::from_str(str_field(v, "contractId")?).map_err(e)?,
            function_name: ScSymbol(str_field(v, "functionName")?.try_into().map_err(e)?),
            args: scvals.try_into().map_err(e)?,
        }),
        sub_invocations: sub_out.try_into().map_err(e)?,
    })
}

fn parse_auth(v: &Value) -> R<Auth> {
    let cred = str_field(v, "credentialType")?;
    Ok(Auth {
        passphrase: str_field(v, "networkPassphrase")?.to_string(),
        cred_v2: match cred {
            "addressV2" => true,
            "address" => false,
            other => return Err(format!("unsupported credentialType {other}")),
        },
        address: ScAddress::from_str(str_field(v, "address")?).map_err(e)?,
        nonce: str_field(v, "nonce")?.parse::<i64>().map_err(e)?,
        expiry: v.get("signatureExpirationLedger").and_then(Value::as_u64).ok_or("signatureExpirationLedger")?.try_into().map_err(e)?,
        root: invocation(v.get("rootInvocation").ok_or("rootInvocation")?)?,
    })
}

fn preimage(cred_v2: bool, passphrase: &str, nonce: i64, expiry: u32, address: &ScAddress, root: &SorobanAuthorizedInvocation) -> HashIdPreimage {
    let network_id = Hash(sha256(passphrase.as_bytes()));
    if cred_v2 {
        HashIdPreimage::SorobanAuthorizationWithAddress(HashIdPreimageSorobanAuthorizationWithAddress {
            network_id,
            nonce,
            signature_expiration_ledger: expiry,
            address: address.clone(),
            invocation: root.clone(),
        })
    } else {
        HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
            network_id,
            nonce,
            signature_expiration_ledger: expiry,
            invocation: root.clone(),
        })
    }
}

fn preimage_name(p: &HashIdPreimage) -> R<&'static str> {
    match p {
        HashIdPreimage::SorobanAuthorization(_) => Ok("envelopeTypeSorobanAuthorization"),
        HashIdPreimage::SorobanAuthorizationWithAddress(_) => Ok("envelopeTypeSorobanAuthorizationWithAddress"),
        _ => Err("unexpected preimage type".into()),
    }
}

fn signing_key(phrase: &str) -> SigningKey {
    SigningKey::from_bytes(&sha256(phrase.as_bytes()))
}
fn account_address(pk: &[u8; 32]) -> ScAddress {
    ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(*pk))))
}

fn sig_scval(pk: &[u8; 32], sig: &[u8; 64]) -> R<ScVal> {
    let entry = |k: &str, v: &[u8]| -> R<ScMapEntry> {
        Ok(ScMapEntry {
            key: ScVal::Symbol(ScSymbol(k.try_into().map_err(e)?)),
            val: ScVal::Bytes(ScBytes(v.to_vec().try_into().map_err(e)?)),
        })
    };
    let map = ScMap(vec![entry("public_key", pk)?, entry("signature", sig)?].try_into().map_err(e)?);
    Ok(ScVal::Vec(Some(ScVec(vec![ScVal::Map(Some(map))].try_into().map_err(e)?))))
}

fn credentials(cred_v2: bool, address: &ScAddress, nonce: i64, expiry: u32, signature: ScVal) -> SorobanCredentials {
    let c = SorobanAddressCredentials { address: address.clone(), nonce, signature_expiration_ledger: expiry, signature };
    if cred_v2 { SorobanCredentials::AddressV2(c) } else { SorobanCredentials::Address(c) }
}

fn op_build(p: &Value) -> R<Value> {
    let a = parse_auth(p.get("authorization").ok_or("authorization")?)?;
    let sk = signing_key(str_field(p, "phrase")?);
    let pk = sk.verifying_key().to_bytes();
    if account_address(&pk) != a.address {
        return Err("signer derived from phrase does not match authorization.address".into());
    }
    let pre = preimage(a.cred_v2, &a.passphrase, a.nonce, a.expiry, &a.address, &a.root);
    let pre_bytes = pre.to_xdr(Limits::none()).map_err(e)?;
    let payload = sha256(&pre_bytes);
    let sig = sk.sign(&payload).to_bytes();
    let unsigned = SorobanAuthorizationEntry {
        credentials: credentials(a.cred_v2, &a.address, a.nonce, 0, ScVal::Vec(Some(ScVec(VecM::default())))),
        root_invocation: a.root.clone(),
    };
    let signed = SorobanAuthorizationEntry {
        credentials: credentials(a.cred_v2, &a.address, a.nonce, a.expiry, sig_scval(&pk, &sig)?),
        root_invocation: a.root.clone(),
    };
    Ok(json!({
        "preimageType": preimage_name(&pre)?,
        "preimageXdr": B64.encode(&pre_bytes),
        "payloadHashHex": hex::encode(payload),
        "signatureHex": hex::encode(sig),
        "unsignedEntryXdr": to_b64(&unsigned)?,
        "signedEntryXdr": to_b64(&signed)?,
    }))
}

fn decode_invocation(inv: &SorobanAuthorizedInvocation) -> R<Value> {
    let mut subs = Vec::new();
    for s in inv.sub_invocations.iter() {
        subs.push(decode_invocation(s)?);
    }
    Ok(match &inv.function {
        SorobanAuthorizedFunction::ContractFn(c) => {
            let mut args = Vec::new();
            for a in c.args.iter() {
                args.push(Value::String(to_b64(a)?));
            }
            json!({
                "kind": "contractFn",
                "contractId": c.contract_address.to_string(),
                "functionName": c.function_name.0.to_utf8_string_lossy(),
                "args": args,
                "subInvocations": subs,
            })
        }
        other => json!({ "kind": "createContract", "functionXdr": to_b64(other)?, "subInvocations": subs }),
    })
}

/// Returns (kind, public_key_hex, signature_hex) for a signature ScVal.
fn classify_signature(s: &ScVal) -> (&'static str, Option<String>, Option<String>) {
    match s {
        ScVal::Void => ("none", None, None),
        ScVal::Vec(None) => ("none", None, None),
        ScVal::Vec(Some(v)) if v.0.is_empty() => ("none", None, None),
        ScVal::Vec(Some(v)) if v.0.len() == 1 => {
            if let ScVal::Map(Some(m)) = &v.0[0] {
                let (mut pk, mut sg) = (None, None);
                for ent in m.0.iter() {
                    if let (ScVal::Symbol(k), ScVal::Bytes(b)) = (&ent.key, &ent.val) {
                        match (k.0.to_utf8_string_lossy().as_str(), b.0.len()) {
                            ("public_key", 32) => pk = Some(hex::encode(b.0.as_slice())),
                            ("signature", 64) => sg = Some(hex::encode(b.0.as_slice())),
                            _ => {}
                        }
                    }
                }
                if m.0.len() == 2 && pk.is_some() && sg.is_some() {
                    return ("ed25519", pk, sg);
                }
            }
            ("raw", None, None)
        }
        _ => ("raw", None, None),
    }
}

struct Top<'a> {
    kind: &'static str,
    creds: Option<&'a SorobanAddressCredentials>,
    delegates: usize,
}
fn top(c: &SorobanCredentials) -> Top<'_> {
    fn count(d: &stellar_xdr::SorobanDelegateSignature) -> usize {
        1 + d.nested_delegates.iter().map(count).sum::<usize>()
    }
    match c {
        SorobanCredentials::SourceAccount => Top { kind: "sourceAccount", creds: None, delegates: 0 },
        SorobanCredentials::Address(a) => Top { kind: "address", creds: Some(a), delegates: 0 },
        SorobanCredentials::AddressV2(a) => Top { kind: "addressV2", creds: Some(a), delegates: 0 },
        SorobanCredentials::AddressWithDelegates(d) => Top {
            kind: "addressWithDelegates",
            creds: Some(&d.address_credentials),
            delegates: d.delegates.iter().map(count).sum(),
        },
    }
}

fn op_decode(p: &Value) -> R<Value> {
    let entry: SorobanAuthorizationEntry = b64_to_xdr(str_field(p, "entryXdr")?)?;
    let t = top(&entry.credentials);
    let (raw, sig_kind, pk, sg) = match t.creds {
        Some(c) => {
            let (k, pk, sg) = classify_signature(&c.signature);
            (to_b64(&c.signature)?, k, pk, sg)
        }
        None => (to_b64(&ScVal::Void)?, "none", None, None),
    };
    let mut signature = json!({ "kind": sig_kind, "rawXdr": raw });
    if let Some(pk) = pk { signature["publicKeyHex"] = Value::String(pk); }
    if let Some(sg) = sg { signature["signatureHex"] = Value::String(sg); }
    Ok(json!({
        "credentialType": t.kind,
        "address": t.creds.map(|c| c.address.to_string()),
        "nonce": t.creds.map(|c| c.nonce.to_string()),
        "signatureExpirationLedger": t.creds.map(|c| c.signature_expiration_ledger),
        "signature": signature,
        "delegateCount": t.delegates,
        "rootInvocation": decode_invocation(&entry.root_invocation)?,
    }))
}

fn op_verify(p: &Value) -> R<Value> {
    let entry: SorobanAuthorizationEntry = b64_to_xdr(str_field(p, "entryXdr")?)?;
    let passphrase = str_field(p, "networkPassphrase")?;
    let t = top(&entry.credentials);
    let c = t.creds.ok_or("entry has no address credentials")?;
    let v2 = t.kind != "address";
    let pre = preimage(v2, passphrase, c.nonce, c.signature_expiration_ledger, &c.address, &entry.root_invocation);
    let pre_bytes = pre.to_xdr(Limits::none()).map_err(e)?;
    let payload = sha256(&pre_bytes);
    let mut out = json!({
        "preimageType": preimage_name(&pre)?,
        "preimageXdr": B64.encode(&pre_bytes),
        "payloadHashHex": hex::encode(payload),
    });
    let (kind, pk, sg) = classify_signature(&c.signature);
    let (valid, reason) = if kind != "ed25519" {
        (false, "no ed25519 signature in credentials".to_string())
    } else {
        let pk_bytes: [u8; 32] = hex::decode(pk.unwrap()).map_err(e)?.try_into().map_err(|_| "pk len")?;
        if account_address(&pk_bytes) != c.address {
            (false, "signature public_key is not the authorizing address".to_string())
        } else {
            let sig_bytes: [u8; 64] = hex::decode(sg.unwrap()).map_err(e)?.try_into().map_err(|_| "sig len")?;
            let vk = VerifyingKey::from_bytes(&pk_bytes).map_err(e)?;
            match vk.verify(&payload, &Signature::from_bytes(&sig_bytes)) {
                Ok(()) => (true, "ok".to_string()),
                Err(_) => (false, "ed25519 signature does not verify over the payload hash".to_string()),
            }
        }
    };
    out["signatureValid"] = Value::Bool(valid);
    out["reason"] = Value::String(reason);
    Ok(out)
}

fn op_ed25519_sign(p: &Value) -> R<Value> {
    let seed: [u8; 32] = hex::decode(str_field(p, "secretKeyHex")?).map_err(e)?.try_into().map_err(|_| "seed must be 32 bytes")?;
    let msg = hex::decode(str_field(p, "messageHex")?).map_err(e)?;
    let sk = SigningKey::from_bytes(&seed);
    Ok(json!({ "publicKeyHex": hex::encode(sk.verifying_key().to_bytes()), "signatureHex": hex::encode(sk.sign(&msg).to_bytes()) }))
}

fn op_derive_key(p: &Value) -> R<Value> {
    let sk = signing_key(str_field(p, "phrase")?);
    let pk = sk.verifying_key().to_bytes();
    Ok(json!({ "publicKey": account_address(&pk).to_string(), "publicKeyHex": hex::encode(pk) }))
}

fn describe() -> Value {
    json!({
        "adapter": "authmatrix-adapter-rust",
        "language": "Rust",
        "xdrImplementation": "stellar-xdr =28.0.1 (rs-stellar-xdr)",
        "signingImplementation": "ed25519-dalek =2.2.0",
        "hashImplementation": "sha2 =0.10.9",
        "ops": ["describe", "derive_key", "build", "decode", "verify", "ed25519_sign"],
    })
}

fn handle(line: &str) -> Value {
    let req: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(err) => return json!({ "protocol": PROTOCOL, "id": -1, "ok": false, "error": format!("invalid json: {err}") }),
    };
    let id = req.get("id").and_then(Value::as_i64).unwrap_or(-1);
    let run = || -> R<Value> {
        if req.get("protocol").and_then(Value::as_str) != Some(PROTOCOL) {
            return Err("unsupported protocol".into());
        }
        let params = req.get("params").cloned().unwrap_or(Value::Null);
        match req.get("op").and_then(Value::as_str).ok_or("missing op")? {
            "describe" => Ok(describe()),
            "derive_key" => op_derive_key(&params),
            "build" => op_build(&params),
            "decode" => op_decode(&params),
            "verify" => op_verify(&params),
            "ed25519_sign" => op_ed25519_sign(&params),
            other => Err(format!("unknown op {other}")),
        }
    };
    match run() {
        Ok(result) => json!({ "protocol": PROTOCOL, "id": id, "ok": true, "result": result }),
        Err(error) => json!({ "protocol": PROTOCOL, "id": id, "ok": false, "error": error }),
    }
}

fn main() {
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = match line { Ok(l) => l, Err(_) => break };
        if line.trim().is_empty() { continue; }
        let _ = writeln!(out, "{}", handle(&line));
        let _ = out.flush();
    }
}

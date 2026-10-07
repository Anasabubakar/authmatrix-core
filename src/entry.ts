/**
 * TypeScript adapter core. Everything cryptographic or XDR-related is delegated to
 * @stellar/stellar-sdk 17.2.1 official helpers (authorizeEntry,
 * buildAuthorizationEntryPreimage, inspectAuthEntry, hash, Keypair). This file
 * contains no hashing, signing or XDR encoding of its own.
 *
 * API note: the Protocol 27 migration page documents the v16 accessor style
 * (`entry.credentials().addressV2()`). SDK 17 xdr values are immutable classes, so the
 * same data is read as properties (`entry.credentials.type === "sorobanCredentialsAddressV2"`,
 * `entry.credentials.addressV2`). This module uses the 17.x shape.
 */
import {
  Address,
  Keypair,
  authorizeEntry,
  buildAuthorizationEntryPreimage,
  hash,
  inspectAuthEntry,
  xdr,
} from "@stellar/stellar-sdk";
import { fromBase64, fromHex, toBase64, toHex } from "./bytes.ts";
import type { Authorization, Canonical, DecodedEntry, DecodedInvocation, Invocation, VerifyResult } from "./vector.ts";

export function deriveKeypair(phrase: string): Keypair {
  return Keypair.fromRawEd25519Seed(hash(phrase));
}

function invocationToXdr(inv: Invocation): xdr.SorobanAuthorizedInvocation {
  return new xdr.SorobanAuthorizedInvocation({
    function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
      new xdr.InvokeContractArgs({
        contractAddress: new Address(inv.contractId).toScAddress(),
        functionName: inv.functionName,
        args: inv.args.map((a) => xdr.ScVal.fromXdr(a, "base64")),
      }),
    ),
    subInvocations: inv.subInvocations.map(invocationToXdr),
  });
}

/** Unsigned entry: empty signature vec, expiration 0 (authorizeEntry commits the real expiry). */
export function authorizationToUnsignedEntry(a: Authorization): xdr.SorobanAuthorizationEntry {
  const creds = new xdr.SorobanAddressCredentials({
    address: new Address(a.address).toScAddress(),
    nonce: BigInt(a.nonce),
    signatureExpirationLedger: 0,
    signature: xdr.ScVal.scvVec([]),
  });
  return new xdr.SorobanAuthorizationEntry({
    credentials:
      a.credentialType === "addressV2"
        ? xdr.SorobanCredentials.sorobanCredentialsAddressV2(creds)
        : xdr.SorobanCredentials.sorobanCredentialsAddress(creds),
    rootInvocation: invocationToXdr(a.rootInvocation),
  });
}

function preimageKind(p: xdr.HashIdPreimage): Canonical["preimageType"] {
  if (p.type === "envelopeTypeSorobanAuthorization") return "envelopeTypeSorobanAuthorization";
  if (p.type === "envelopeTypeSorobanAuthorizationWithAddress") return "envelopeTypeSorobanAuthorizationWithAddress";
  throw new Error(`unexpected preimage type ${p.type}`);
}

export async function buildCanonical(a: Authorization, phrase: string): Promise<Canonical> {
  const kp = deriveKeypair(phrase);
  if (kp.publicKey() !== a.address) throw new Error("signer derived from phrase does not match authorization.address");
  const unsigned = authorizationToUnsignedEntry(a);
  const preimage = buildAuthorizationEntryPreimage(unsigned, a.signatureExpirationLedger, a.networkPassphrase);
  const preimageBytes = preimage.toXdr();
  const payload = hash(preimageBytes);
  const signed = await authorizeEntry(unsigned, kp, a.signatureExpirationLedger, a.networkPassphrase);
  const info = inspectAuthEntry(signed);
  const sig = info.signers[0]?.signatures?.[0];
  if (!sig) throw new Error("authorizeEntry produced no ed25519 signature");
  return {
    preimageType: preimageKind(preimage),
    preimageXdr: toBase64(preimageBytes),
    payloadHashHex: toHex(payload),
    signatureHex: toHex(sig.signature),
    unsignedEntryXdr: toBase64(unsigned.toXdr()),
    signedEntryXdr: toBase64(signed.toXdr()),
  };
}

function decodeInvocation(inv: xdr.SorobanAuthorizedInvocation): DecodedInvocation {
  const subInvocations = inv.subInvocations.map(decodeInvocation);
  const fn = inv.function;
  if (fn.type === "sorobanAuthorizedFunctionTypeContractFn") {
    const c = fn.contractFn;
    return {
      kind: "contractFn",
      contractId: Address.fromScAddress(c.contractAddress).toString(),
      functionName: c.functionName.toString(),
      args: c.args.map((v) => toBase64(v.toXdr())),
      subInvocations,
    };
  }
  return { kind: "createContract", functionXdr: toBase64(fn.toXdr()), subInvocations };
}

export function entryFromXdr(b64: string): xdr.SorobanAuthorizationEntry {
  return xdr.SorobanAuthorizationEntry.fromXdr(fromBase64(b64));
}

export function decodeEntry(entry: xdr.SorobanAuthorizationEntry): DecodedEntry {
  const info = inspectAuthEntry(entry);
  const creds = entry.credentials;
  let rawSig: xdr.ScVal;
  let delegateCount = 0;
  if (creds.type === "sorobanCredentialsAddress") rawSig = creds.address.signature;
  else if (creds.type === "sorobanCredentialsAddressV2") rawSig = creds.addressV2.signature;
  else if (creds.type === "sorobanCredentialsAddressWithDelegates") {
    rawSig = creds.addressWithDelegates.addressCredentials.signature;
    delegateCount = info.signers.length - 1;
  } else rawSig = xdr.ScVal.scvVoid();
  const top = info.signers[0];
  const ed = top?.signatures?.[0];
  let signature: DecodedEntry["signature"];
  if (ed) {
    signature = {
      kind: "ed25519",
      publicKeyHex: toHex(new Address(ed.publicKey).toBuffer()),
      signatureHex: toHex(ed.signature),
      rawXdr: toBase64(rawSig.toXdr()),
    };
  } else {
    signature = { kind: top?.signed ? "raw" : "none", rawXdr: toBase64(rawSig.toXdr()) };
  }
  return {
    credentialType: info.credentialType,
    address: info.address,
    nonce: info.nonce === null ? null : info.nonce.toString(),
    signatureExpirationLedger: info.signatureExpirationLedger,
    signature,
    delegateCount,
    rootInvocation: decodeInvocation(entry.rootInvocation),
  };
}

export function verifyEntry(entryXdr: string, networkPassphrase: string): VerifyResult {
  const entry = entryFromXdr(entryXdr);
  const info = inspectAuthEntry(entry);
  if (info.address === null || info.signatureExpirationLedger === null) throw new Error("entry has no address credentials");
  const preimage = buildAuthorizationEntryPreimage(entry, info.signatureExpirationLedger, networkPassphrase);
  const preimageBytes = preimage.toXdr();
  const payload = hash(preimageBytes);
  const base = { preimageType: preimageKind(preimage), preimageXdr: toBase64(preimageBytes), payloadHashHex: toHex(payload) };
  const sig = info.signers[0]?.signatures?.[0];
  if (!sig) return { ...base, signatureValid: false, reason: "no ed25519 signature in credentials" };
  if (sig.publicKey !== info.address) {
    return { ...base, signatureValid: false, reason: "signature public_key is not the authorizing address" };
  }
  const ok = Keypair.fromPublicKey(sig.publicKey).verify(payload, sig.signature);
  return { ...base, signatureValid: ok, reason: ok ? "ok" : "ed25519 signature does not verify over the payload hash" };
}

export function ed25519Sign(secretKeyHex: string, messageHex: string): { publicKeyHex: string; signatureHex: string } {
  const kp = Keypair.fromRawEd25519Seed(fromHex(secretKeyHex));
  return { publicKeyHex: toHex(kp.rawPublicKey()), signatureHex: toHex(kp.sign(fromHex(messageHex))) };
}

/** Rebuild an entry from the neutral model, attaching an existing signature ScVal (base64 XDR) and the model's expiry. */
export function assembleEntry(a: Authorization, signatureScValXdr: string): xdr.SorobanAuthorizationEntry {
  const creds = new xdr.SorobanAddressCredentials({
    address: new Address(a.address).toScAddress(),
    nonce: BigInt(a.nonce),
    signatureExpirationLedger: a.signatureExpirationLedger,
    signature: xdr.ScVal.fromXdr(signatureScValXdr, "base64"),
  });
  return new xdr.SorobanAuthorizationEntry({
    credentials:
      a.credentialType === "addressV2"
        ? xdr.SorobanCredentials.sorobanCredentialsAddressV2(creds)
        : xdr.SorobanCredentials.sorobanCredentialsAddress(creds),
    rootInvocation: invocationToXdr(a.rootInvocation),
  });
}

function decodedToInvocation(d: DecodedInvocation): Invocation {
  if (d.kind !== "contractFn") throw new Error("only contract-function invocations can be converted to the neutral model");
  return { contractId: d.contractId, functionName: d.functionName, args: d.args, subInvocations: d.subInvocations.map(decodedToInvocation) };
}

/** Neutral model from a decoded entry. Throws for credential kinds / invocation kinds the vector format does not cover. */
export function decodedToAuthorization(d: DecodedEntry, networkPassphrase: string): Authorization {
  if ((d.credentialType !== "address" && d.credentialType !== "addressV2") || d.address === null || d.nonce === null || d.signatureExpirationLedger === null) {
    throw new Error(`credential type ${d.credentialType} is not covered by the neutral model (address and addressV2 only)`);
  }
  return {
    networkPassphrase,
    credentialType: d.credentialType,
    address: d.address,
    nonce: d.nonce,
    signatureExpirationLedger: d.signatureExpirationLedger,
    rootInvocation: decodedToInvocation(d.rootInvocation),
  };
}

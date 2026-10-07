// Generates vectors/authmatrix-vectors.v1.json from the TypeScript adapter core (stellar-sdk helpers).
// Usage: node --experimental-strip-types scripts/gen-vectors.ts [--check]
// The output is deterministic (ed25519 signatures are deterministic, RFC 8032). It is committed and
// REVIEWED; the Rust adapter and the Soroban host must reproduce/accept it independently.
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { Address, Keypair, Networks, StrKey, hash, nativeToScVal, xdr } from "@stellar/stellar-sdk";
import { assembleEntry, buildCanonical, decodeEntry, entryFromXdr } from "../src/entry.ts";
import { toBase64, toHex } from "../src/bytes.ts";
import { diffPaths, mutateAuthorization } from "../src/mutate.ts";
import { evidenceFileSchema, VECTOR_FORMAT, VECTOR_FORMAT_VERSION } from "../src/vector.ts";
import type { Authorization, EvidenceFile, Invocation, MutationField, Vector, VectorFile } from "../src/vector.ts";
import { buildAuthorizationEntryPreimage } from "@stellar/stellar-sdk";

const OUT = "vectors/authmatrix-vectors.v1.json";
const check = process.argv.includes("--check");

const SIGNER_PHRASE = "authmatrix test vector signer 1: public test phrase, key has no value";
const signer = Keypair.fromRawEd25519Seed(hash(SIGNER_PHRASE));
const recipient = (n: string) => Keypair.fromRawEd25519Seed(hash("authmatrix test vector recipient " + n)).publicKey();
const spender = recipient("spender");
const contract = (label: string) => StrKey.encodeContract(hash("authmatrix:fixture:" + label));

const OUTER = contract("outer");
const OUTER2 = contract("outer-second-instance");
const INNER = contract("inner");
const TOKEN = contract("synthetic-token");
const CUSTOM = contract("synthetic-unknown-contract");

const addr = (a: string) => toBase64(xdr.ScVal.scvAddress(new Address(a).toScAddress()).toXdr());
const i128 = (n: bigint) => toBase64(nativeToScVal(n, { type: "i128" }).toXdr());
const u32 = (n: number) => toBase64(xdr.ScVal.scvU32(n).toXdr());

function relayTree(o: { fn: string; to: string; amount: bigint }): Invocation {
  const from = signer.publicKey();
  return {
    contractId: OUTER,
    functionName: o.fn,
    args: [addr(INNER), addr(from), addr(o.to), i128(o.amount)],
    subInvocations: [{ contractId: INNER, functionName: "transfer", args: [addr(from), addr(o.to), i128(o.amount)], subInvocations: [] }],
  };
}

function tokenOpsTree(): Invocation {
  const from = signer.publicKey();
  const to = recipient("A");
  const unknownMap = xdr.ScVal.scvMap([
    new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol("memo"), val: xdr.ScVal.scvString("unrecognized payload") }),
    new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol("tag"), val: xdr.ScVal.scvBytes(new Uint8Array([1, 2, 3, 4])) }),
  ]);
  return {
    contractId: TOKEN,
    functionName: "approve",
    args: [addr(from), addr(spender), i128(5_000_0000000n), u32(2_000_000)],
    subInvocations: [
      { contractId: TOKEN, functionName: "transfer", args: [addr(from), addr(to), i128(1_250_0000000n)], subInvocations: [] },
      { contractId: TOKEN, functionName: "mint", args: [addr(to), i128(42n)], subInvocations: [] },
      { contractId: TOKEN, functionName: "burn_from", args: [addr(spender), addr(from), i128(7n)], subInvocations: [] },
      { contractId: CUSTOM, functionName: "settle", args: [toBase64(unknownMap.toXdr()), toBase64(xdr.ScVal.scvVec([xdr.ScVal.scvU32(9), xdr.ScVal.scvBool(true)]).toXdr())], subInvocations: [] },
    ],
  };
}

function tokenTransferTree(to: string, amount: bigint): Invocation {
  return { contractId: TOKEN, functionName: "transfer", args: [addr(signer.publicKey()), addr(to), i128(amount)], subInvocations: [] };
}

interface Spec {
  id: string;
  title: string;
  labels: string[];
  auth: Authorization;
  compat: Vector["compatibility"];
  fields: MutationField[];
  contractIdOverride?: string;
}

const base = (o: Pick<Authorization, "credentialType" | "networkPassphrase" | "nonce" | "signatureExpirationLedger" | "rootInvocation">): Authorization => ({ address: signer.publicKey(), ...o });

const specs: Spec[] = [
  {
    id: "v2-nested-relay-testnet",
    title: "ADDRESS_V2: outer.relay requires auth, nested inner.transfer requires auth (testnet passphrase)",
    labels: ["fixture-contracts", "host-verifiable"],
    auth: base({ credentialType: "addressV2", networkPassphrase: Networks.TESTNET, nonce: "7316487300985", signatureExpirationLedger: 1000, rootInvocation: relayTree({ fn: "relay", to: recipient("A"), amount: 1_250_0000000n }) }),
    compat: { protocol: { min: 27, max: null }, status: "current", note: "CAP-71 credential type, introduced in Protocol 27; testnet reports Protocol 29 at recording time (see hostVerified).", hostVerified: [] },
    fields: ["recipient", "amount", "network", "nonce", "expiry", "function", "contractId"],
    contractIdOverride: OUTER2,
  },
  {
    id: "legacy-nested-relay-testnet",
    title: "Legacy ADDRESS: same nested invocation, non-address-bound payload (testnet passphrase)",
    labels: ["fixture-contracts", "host-verifiable", "legacy"],
    auth: base({ credentialType: "address", networkPassphrase: Networks.TESTNET, nonce: "5110024781663", signatureExpirationLedger: 1000, rootInvocation: relayTree({ fn: "relay", to: recipient("A"), amount: 1_250_0000000n }) }),
    compat: { protocol: { min: 20, max: null }, status: "legacy-still-valid", note: "Pre-Protocol-27 payload. The SDK migration guide says the legacy ADDRESS type is still valid; this is only claimed for protocols listed under hostVerified.", hostVerified: [] },
    fields: ["recipient", "amount", "network", "nonce", "expiry", "function", "contractId"],
    contractIdOverride: OUTER2,
  },
  {
    id: "v2-token-ops-synthetic",
    title: "ADDRESS_V2: synthetic tree of SEP-41 and SAC calls plus an unknown contract with unknown ScVals",
    labels: ["synthetic", "decode-coverage", "not-host-verified"],
    auth: base({ credentialType: "addressV2", networkPassphrase: Networks.TESTNET, nonce: "9001", signatureExpirationLedger: 2_000_000, rootInvocation: tokenOpsTree() }),
    compat: { protocol: { min: 27, max: null }, status: "current", note: "Synthetic contract ids; no host run exists for this vector.", hostVerified: [] },
    fields: ["recipient", "amount", "network", "nonce", "expiry", "function", "contractId"],
  },
  {
    id: "legacy-pubnet-historical-transfer",
    title: "Legacy ADDRESS bound to the public-network passphrase (historical-style entry)",
    labels: ["synthetic", "historical", "not-host-verified"],
    auth: base({ credentialType: "address", networkPassphrase: Networks.PUBLIC, nonce: "123456789", signatureExpirationLedger: 52_000_000, rootInvocation: tokenTransferTree(recipient("A"), 100_0000000n) }),
    compat: { protocol: { min: 20, max: null }, status: "historical-unverified", note: "Public-network passphrase. AuthMatrix never contacts mainnet, so acceptance there is NOT established; do not read this as valid on any network.", hostVerified: [] },
    fields: ["recipient", "amount", "network", "nonce", "expiry", "contractId"],
  },
];

function loadEvidence(path: string): EvidenceFile | null {
  if (!existsSync(path)) return null;
  return evidenceFileSchema.parse(JSON.parse(readFileSync(path, "utf8")));
}

async function main() {
  const native = loadEvidence("evidence/native-host/results.json");
  const testnet = loadEvidence("evidence/testnet/summary.json");
  const vectors: Vector[] = [];
  for (const s of specs) {
    const canonical = await buildCanonical(s.auth, SIGNER_PHRASE);
    const signedEntry = entryFromXdr(canonical.signedEntryXdr);
    const sigScValXdr = decodeEntry(signedEntry).signature.rawXdr;
    const mutations = [];
    for (const field of s.fields) {
      const mutated = mutateAuthorization(s.auth, field, field === "contractId" && s.contractIdOverride ? { contractId: s.contractIdOverride } : {});
      if (!mutated) throw new Error(`${s.id}: ${field} not applicable`);
      const withOrig = assembleEntry(mutated, sigScValXdr);
      const pre = buildAuthorizationEntryPreimage(withOrig, mutated.signatureExpirationLedger, mutated.networkPassphrase);
      const pre64 = toBase64(pre.toXdr());
      const hashHex = toHex(hash(pre.toXdr()));
      if (hashHex === canonical.payloadHashHex) throw new Error(`${s.id}/${field}: payload hash did not change`);
      const resigned = await buildCanonical(mutated, SIGNER_PHRASE);
      mutations.push({
        id: `${s.id}--${field}`,
        field,
        description: describeMutation(field),
        changedPaths: diffPaths(s.auth, mutated),
        mutatedAuthorization: mutated,
        expected: {
          payloadHashChanged: true as const,
          mutatedPreimageXdr: pre64,
          mutatedPayloadHashHex: hashHex,
          originalSignatureVerifies: false as const,
          entryXdrWithOriginalSignature: toBase64(withOrig.toXdr()),
          hostExpectation: "reject" as const,
          resignedEntryXdr: resigned.signedEntryXdr,
          resignedSignatureHex: resigned.signatureHex,
        },
      });
    }
    const compat = { ...s.compat, hostVerified: hostVerified(s, native, testnet) };
    vectors.push({
      id: s.id,
      title: s.title,
      labels: s.labels,
      signer: {
        publicKey: signer.publicKey(),
        derivation: { scheme: "sha256-of-utf8-phrase", phrase: SIGNER_PHRASE, note: "Seed = SHA-256(UTF-8 phrase). Public, test-only key; it protects nothing and must never hold value on any network." },
      },
      authorization: s.auth,
      expected: canonical,
      compatibility: compat,
      mutations,
    });
  }
  const file: VectorFile = {
    format: VECTOR_FORMAT,
    formatVersion: VECTOR_FORMAT_VERSION,
    generator: { tool: "authmatrix-core scripts/gen-vectors.ts", version: JSON.parse(readFileSync("package.json", "utf8")).version, sdk: "@stellar/stellar-sdk@17.2.1", note: "Canonical values come from the SDK's official helpers; the Rust adapter and the Soroban host independently confirm them (see README)." },
    vectors,
  };
  const text = JSON.stringify(file, null, 2) + "\n";
  if (check) {
    const cur = existsSync(OUT) ? readFileSync(OUT, "utf8") : "";
    if (cur !== text) {
      console.error(`${OUT} is out of date; run pnpm vectors`);
      process.exit(1);
    }
    console.log(`${OUT} is up to date (${vectors.length} vectors)`);
  } else {
    writeFileSync(OUT, text);
    console.log(`wrote ${OUT}: ${vectors.length} vectors, ${vectors.reduce((n, v) => n + v.mutations.length, 0)} mutations`);
  }
}

function describeMutation(f: MutationField): string {
  const d: Record<MutationField, string> = {
    recipient: "recipient address replaced everywhere it appears in the invocation tree",
    amount: "amount multiplied by ten everywhere it appears in the invocation tree",
    network: "network passphrase replaced (entry signed for a different network)",
    nonce: "nonce incremented by one",
    expiry: "signature expiration ledger incremented by one",
    function: "root function name replaced by a sibling function name",
    contractId: "root contract id replaced by another contract id",
  };
  return d[f];
}

function hostVerified(s: Spec, native: EvidenceFile | null, testnet: EvidenceFile | null): Vector["compatibility"]["hostVerified"] {
  const out: Vector["compatibility"]["hostVerified"] = [];
  for (const [ev, path, env] of [
    [native, "evidence/native-host/results.json", "native-testutils"],
    [testnet, "evidence/testnet/summary.json", "testnet-simulate-enforce"],
  ] as const) {
    if (!ev) continue;
    const rs = ev.results.filter((r) => r.vectorId === s.id);
    const orig = rs.find((r) => r.case === "original");
    if (!orig || orig.outcome !== "accepted") continue;
    const rejected = s.fields.filter((f) => rs.some((r) => r.case === f && r.outcome === "rejected") && (f === "network" || rs.some((r) => r.case === f + "-resigned" && r.outcome === "accepted")));
    const pv = typeof ev.environment["protocolVersion"] === "number" ? (ev.environment["protocolVersion"] as number) : undefined;
    out.push({ environment: env, ...(pv !== undefined ? { protocolVersion: pv } : {}), evidence: path, original: "accepted", mutationsRejected: rejected });
  }
  return out;
}

await main();

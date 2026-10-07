// OPT-IN network script. Records real Stellar testnet simulateTransaction(authMode: "enforce") results.
//   node --experimental-strip-types --no-warnings scripts/testnet-evidence.ts [--rust <adapter binary>]
// Prerequisites: evidence/testnet/deployment.json (contracts deployed with the stellar CLI) and a funded
// throwaway source account whose address is listed there. No secret key is read or stored here: simulation
// does not need a transaction signature, and authorization signatures come from the public test phrase.
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { isDeepStrictEqual, parseArgs } from "node:util";
import { Account, Networks, Operation, TransactionBuilder, rpc, xdr, Address } from "@stellar/stellar-sdk";
import { toBase64 } from "../src/bytes.ts";
import { loadVectors } from "../src/node.ts";
import { entryFromXdr, buildCanonical } from "../src/entry.ts";
import { mutateAuthorization } from "../src/mutate.ts";
import { AdapterProcess } from "../src/runner.ts";
import { EVIDENCE_FORMAT, EVIDENCE_FORMAT_VERSION } from "../src/vector.ts";
import type { Authorization, EvidenceFile, EvidenceResult, Invocation, MutationField } from "../src/vector.ts";

const { values } = parseArgs({ options: { rust: { type: "string" } } });
const RPC = "https://soroban-testnet.stellar.org";
const dep = JSON.parse(readFileSync("evidence/testnet/deployment.json", "utf8"));
const vectors = loadVectors("vectors/authmatrix-vectors.v1.json");
const server = new rpc.Server(RPC);
const rustBin = values.rust ?? `${process.env["CARGO_TARGET_DIR"] ?? "adapters/rust/target"}/release/authmatrix-adapter-rust`;
if (!existsSync(rustBin)) throw new Error(`build the rust adapter first (${rustBin})`);
const rustAdapter = new AdapterProcess({ name: "rust", command: rustBin, args: [] });

async function friendbot(address: string) {
  const r = await fetch(`https://friendbot.stellar.org/?addr=${address}`);
  const body = await r.text();
  // Already-funded accounts return an error body; that is fine.
  return { status: r.status, already: /already funded|createAccountAlreadyExist|op_already_exists/i.test(body) };
}

function replaceIds(inv: Invocation, map: Map<string, string>): Invocation {
  const args = inv.args.map((a) => {
    const v = xdr.ScVal.fromXdr(a, "base64");
    if (v.type !== "scvAddress") return a;
    const id = Address.fromScAddress(v.address).toString();
    const to = map.get(id);
    return to ? toBase64(xdr.ScVal.scvAddress(new Address(to).toScAddress()).toXdr()) : a;
  });
  return { ...inv, args, contractId: map.get(inv.contractId) ?? inv.contractId, subInvocations: inv.subInvocations.map((s) => replaceIds(s, map)) };
}

function invokeOp(root: Invocation, entry: xdr.SorobanAuthorizationEntry) {
  const func = xdr.HostFunction.hostFunctionTypeInvokeContract(
    new xdr.InvokeContractArgs({
      contractAddress: new Address(root.contractId).toScAddress(),
      functionName: root.functionName,
      args: root.args.map((a) => xdr.ScVal.fromXdr(a, "base64")),
    }),
  );
  return Operation.invokeHostFunction({ func, auth: [entry] });
}

const results: EvidenceResult[] = [];
mkdirSync("evidence/testnet/raw", { recursive: true });

async function simulate(label: string, vectorId: string, kase: string, expectation: "accept" | "reject", auth: Authorization, entryXdr: string, extra: Record<string, unknown>) {
  const account = await server.getAccount(dep.deployerAddress);
  const root = auth.rootInvocation;
  const tx = new TransactionBuilder(new Account(dep.deployerAddress, account.sequenceNumber()), { fee: "1000000", networkPassphrase: Networks.TESTNET })
    .addOperation(invokeOp(root, entryFromXdr(entryXdr)))
    .setTimeout(300)
    .build();
  const raw = (await (server as unknown as { _simulateTransaction(t: unknown, r: unknown, m: string): Promise<Record<string, unknown>> })._simulateTransaction(tx, undefined, "enforce"));
  const error = typeof raw["error"] === "string" ? (raw["error"] as string) : null;
  const outcome = error === null && Array.isArray(raw["results"]) ? "accepted" : "rejected";
  const retXdr = Array.isArray(raw["results"]) ? (raw["results"] as { xdr?: string }[])[0]?.xdr : undefined;
  const m = error?.match(/failed account authentication with error",\s*\w+,\s*(Error\([^)]*\))/);
  let detail = error !== null ? `${error.split("\n")[0]}${m ? `; host diagnostic: failed account authentication with ${m[1]} (account signature check refused the entry)` : "; no 'failed account authentication' diagnostic"}` : `simulation succeeded; return ScVal xdr ${retXdr ?? "(none)"}`;
  if (retXdr) detail += ` = ${(() => { try { return xdr.ScVal.fromXdr(retXdr, "base64").type; } catch { return "?"; } })()}`;
  const file = `evidence/testnet/raw/${label}.json`;
  writeFileSync(file, JSON.stringify({ request: { rpc: RPC, method: "simulateTransaction", authMode: "enforce", transactionXdr: tx.toXDR(), authorization: auth, authEntryXdr: entryXdr, ...extra }, response: raw }, null, 2) + "\n");
  results.push({ vectorId, case: kase, expectation, outcome, detail: detail.slice(0, 600), raw: { path: file } });
  console.log(`${vectorId.padEnd(30)} ${kase.padEnd(18)} expect ${expectation.padEnd(6)} -> ${outcome}  ${detail.slice(0, 140)}`);
}

async function main() {
  const latest = await server.getLatestLedger();
  const version = await server.getVersionInfo();
  console.log(`testnet protocol ${latest.protocolVersion}, ledger ${latest.sequence}, rpc ${version.version}`);
  const signer = vectors.vectors[0]!.authorization.address;
  console.log("friendbot (signer account):", JSON.stringify(await friendbot(signer)));

  const idMap = new Map<string, string>();
  const first = vectors.vectors.find((v) => v.id === "v2-nested-relay-testnet")!;
  idMap.set(first.authorization.rootInvocation.contractId, dep.contracts.outer);
  idMap.set(first.authorization.rootInvocation.subInvocations[0]!.contractId, dep.contracts.inner);
  const outer2Static = first.mutations.find((m) => m.field === "contractId")!.mutatedAuthorization.rootInvocation.contractId;
  idMap.set(outer2Static, dep.contracts.outerSecondInstance);

  const expiry = latest.sequence + 5000;
  for (const v of vectors.vectors.filter((x) => x.labels.includes("host-verifiable"))) {
    const phrase = v.signer.derivation.phrase;
    const live: Authorization = { ...v.authorization, signatureExpirationLedger: expiry, rootInvocation: replaceIds(v.authorization.rootInvocation, idMap) };
    const liveCanon = await buildCanonical(live, phrase);
    const rustCanon = (await rustAdapter.request("build", { authorization: live, phrase })) as typeof liveCanon;
    const agree = isDeepStrictEqual(rustCanon, liveCanon);
    if (!agree) throw new Error(`adapters disagree on live authorization for ${v.id}`);
    const cross = { rustAdapterReproducedSignedEntryBytes: true };
    await simulate(`${v.id}--original`, v.id, "original", "accept", live, liveCanon.signedEntryXdr, { ...cross, note: "live variant: contract ids replaced by testnet deployments, expiry = latest ledger + 5000" });

    for (const m of v.mutations) {
      const field = m.field as MutationField;
      const mutated = mutateAuthorization(live, field, field === "contractId" ? { contractId: dep.contracts.outerSecondInstance } : {});
      if (!mutated) continue;
      if (field === "network") {
        // A single testnet host has one network id, so the entry is signed under the mutated passphrase
        // and submitted to testnet: the host rebuilds the payload with the testnet id and the signature
        // fails, which is the same inequality as "original signature checked under a different network".
        const wrongNet = await buildCanonical(mutated, phrase);
        await simulate(`${v.id}--network`, v.id, "network", "reject", live, wrongNet.signedEntryXdr, { note: `entry for the ORIGINAL call, signed with passphrase "${mutated.networkPassphrase}" and submitted to testnet` });
        continue;
      }
      // Mutated tree + the ORIGINAL signature (credentials expiry/nonce as mutated).
      const { assembleEntry, decodeEntry } = await import("../src/entry.ts");
      const sigRaw = decodeEntry(entryFromXdr(liveCanon.signedEntryXdr)).signature.rawXdr;
      const withOrig = assembleEntry(mutated, sigRaw).toXdr("base64");
      await simulate(`${v.id}--${field}`, v.id, field, "reject", mutated, withOrig, { note: "mutated authorization carrying the original signature" });
      const resigned = await buildCanonical(mutated, phrase);
      await simulate(`${v.id}--${field}-resigned`, v.id, `${field}-resigned`, "accept", mutated, resigned.signedEntryXdr, { note: "positive control: same mutated call freshly signed" });
    }
  }
  const doc: EvidenceFile = {
    format: EVIDENCE_FORMAT,
    formatVersion: EVIDENCE_FORMAT_VERSION,
    kind: "testnet-simulate-enforce",
    recordedAt: new Date().toISOString(),
    environment: {
      rpc: RPC,
      rpcVersion: version.version,
      protocolVersion: latest.protocolVersion,
      ledgerSequence: latest.sequence,
      networkPassphrase: Networks.TESTNET,
      authMode: "enforce",
      deployment: "evidence/testnet/deployment.json",
      signerAccount: signer,
    },
    limits: [
      "simulateTransaction is a simulation: nothing was submitted, no transaction was applied, nonces were not consumed.",
      "Only the vectors labelled host-verifiable (fixture contracts) were run; the synthetic vectors have no host result.",
      "The network mutation signs under a different passphrase and submits to testnet (one network per run).",
      "Testnet is not mainnet; acceptance on testnet does not establish acceptance on any other network or protocol.",
    ],
    results,
  };
  writeFileSync("evidence/testnet/summary.json", JSON.stringify(doc, null, 2) + "\n");
  rustAdapter.close();
  const bad = results.filter((r) => (r.expectation === "accept") !== (r.outcome === "accepted"));
  console.log(`${results.length} results, ${bad.length} contradict expectations`);
  process.exit(bad.length === 0 ? 0 : 1);
}
await main();

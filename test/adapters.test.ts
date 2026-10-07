import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Keypair, authorizeEntry, buildWithDelegatesEntry, hash } from "@stellar/stellar-sdk";
import { toBase64 } from "../src/bytes.ts";
import { entryFromXdr } from "../src/entry.ts";
import { AdapterProcess, runConformance, type AdapterSpec } from "../src/runner.ts";
import type { VectorFile } from "../src/vector.ts";
import { adapterSpecs, rfc, vectors } from "./helpers.ts";

describe("two independent adapters", () => {
  it("both adapters pass every check and agree byte-for-byte", async () => {
    const report = await runConformance(vectors, rfc, adapterSpecs());
    expect(report.adapters.map((a) => a.adapter).sort()).toEqual(["authmatrix-adapter-rust", "authmatrix-adapter-typescript"]);
    expect(report.checks.filter((c) => !c.ok)).toEqual([]);
    expect(report.agreements.filter((a) => !a.ok)).toEqual([]);
    expect(report.checks.length).toBeGreaterThan(300);
  });

  it("the adapters declare genuinely different XDR, hash and signing implementations", async () => {
    const report = await runConformance({ ...vectors, vectors: vectors.vectors.slice(0, 1) }, { ...rfc, vectors: [] }, adapterSpecs());
    const [a, b] = [...report.adapters].sort((x, y) => x.language.localeCompare(y.language));
    expect(a!.language).not.toBe(b!.language);
    const joined = JSON.stringify(report.adapters);
    expect(joined).toContain("stellar-xdr");
    expect(joined).toContain("@stellar/stellar-sdk");
    expect(joined).toContain("ed25519-dalek");
    expect(joined).toContain("@noble/ed25519");
  });

  it("the runner detects a tampered reviewed value (it can fail)", async () => {
    const bad = structuredClone(vectors) as VectorFile;
    const h = bad.vectors[0]!.expected.payloadHashHex;
    bad.vectors[0]!.expected.payloadHashHex = (h[0] === "0" ? "1" : "0") + h.slice(1);
    const report = await runConformance({ ...bad, vectors: [bad.vectors[0]!] }, { ...rfc, vectors: [] }, adapterSpecs());
    expect(report.failed).toBeGreaterThan(0);
    expect(report.checks.some((c) => !c.ok && c.check.includes("canonical"))).toBe(true);
  });

  it("the runner detects a tampered mutation expectation", async () => {
    const bad = structuredClone(vectors) as VectorFile;
    const m = bad.vectors[0]!.mutations[0]!;
    m.expected.mutatedPreimageXdr = bad.vectors[0]!.expected.preimageXdr;
    const report = await runConformance({ ...bad, vectors: [bad.vectors[0]!] }, { ...rfc, vectors: [] }, adapterSpecs());
    expect(report.checks.some((c) => !c.ok && c.check.includes("mutated preimage"))).toBe(true);
  });
});

describe("adapter protocol robustness", () => {
  let procs: AdapterProcess[] = [];
  beforeAll(() => {
    procs = adapterSpecs().map((s: AdapterSpec) => new AdapterProcess(s));
  });
  afterAll(() => procs.forEach((p) => p.close()));

  it("both reject unknown ops and malformed params with ok:false, not a crash", async () => {
    for (const p of procs) {
      await expect(p.request("nope")).rejects.toThrow();
      await expect(p.request("decode", { entryXdr: "AAAA" })).rejects.toThrow();
      await expect(p.request("build", { authorization: {}, phrase: "x" })).rejects.toThrow();
      // still alive afterwards
      expect(await p.request("describe")).toBeTruthy();
    }
  });

  it("both refuse to sign when the phrase does not derive the authorizing address", async () => {
    const v = vectors.vectors[0]!;
    for (const p of procs) {
      await expect(p.request("build", { authorization: v.authorization, phrase: "a different phrase entirely" })).rejects.toThrow(/does not match/);
    }
  });

  it("both decode an ADDRESS_WITH_DELEGATES entry identically (decode-only support)", async () => {
    const kp = Keypair.fromRawEd25519Seed(hash("authmatrix delegates test"));
    const d1 = Keypair.fromRawEd25519Seed(hash("authmatrix delegate 1"));
    const d2 = Keypair.fromRawEd25519Seed(hash("authmatrix delegate 2"));
    const v = vectors.vectors[0]!;
    const unsigned = entryFromXdr(v.expected.unsignedEntryXdr);
    const entry = buildWithDelegatesEntry({
      entry: unsigned,
      validUntilLedgerSeq: 777,
      delegates: [{ address: d1.publicKey() }, { address: d2.publicKey(), nestedDelegates: [{ address: kp.publicKey() }] }],
    });
    const signed = await authorizeEntry(entry, d1, 777, v.authorization.networkPassphrase, d1.publicKey());
    const b64 = toBase64(signed.toXdr());
    const decoded = await Promise.all(procs.map((p) => p.request("decode", { entryXdr: b64 }) as Promise<{ credentialType: string; delegateCount: number; signatureExpirationLedger: number }>));
    expect(decoded[0]).toEqual(decoded[1]);
    expect(decoded[0]!.credentialType).toBe("addressWithDelegates");
    expect(decoded[0]!.delegateCount).toBe(3);
    expect(decoded[0]!.signatureExpirationLedger).toBe(777);
  });
});

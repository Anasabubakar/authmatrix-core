import { describe, expect, it } from "vitest";
import { hash } from "@stellar/stellar-sdk";
import { toHex } from "../src/bytes.ts";
import { decodeEntry, assembleEntry, verifyEntry, entryFromXdr } from "../src/entry.ts";
import { MUTATION_FIELDS, altNetwork, diffPaths, mutateAuthorization } from "../src/mutate.ts";
import { vectors } from "./helpers.ts";

describe("mutateAuthorization", () => {
  const v = vectors.vectors[0]!;
  it("changes exactly the intended paths", () => {
    expect(diffPaths(v.authorization, mutateAuthorization(v.authorization, "network")!)).toEqual(["networkPassphrase"]);
    expect(diffPaths(v.authorization, mutateAuthorization(v.authorization, "nonce")!)).toEqual(["nonce"]);
    expect(diffPaths(v.authorization, mutateAuthorization(v.authorization, "expiry")!)).toEqual(["signatureExpirationLedger"]);
    expect(diffPaths(v.authorization, mutateAuthorization(v.authorization, "function")!)).toEqual(["rootInvocation.functionName"]);
    expect(diffPaths(v.authorization, mutateAuthorization(v.authorization, "contractId")!)).toEqual(["rootInvocation.contractId"]);
    expect(diffPaths(v.authorization, mutateAuthorization(v.authorization, "recipient")!)).toEqual(["rootInvocation.args[2]", "rootInvocation.subInvocations[0].args[1]"]);
    expect(diffPaths(v.authorization, mutateAuthorization(v.authorization, "amount")!)).toEqual(["rootInvocation.args[3]", "rootInvocation.subInvocations[0].args[2]"]);
  });
  it("is deterministic", () => {
    for (const f of MUTATION_FIELDS) expect(mutateAuthorization(v.authorization, f)).toEqual(mutateAuthorization(v.authorization, f));
  });
  it("returns null when a tree has no recipient (nothing to mutate)", () => {
    const a = structuredClone(v.authorization);
    a.rootInvocation = { ...a.rootInvocation, functionName: "unknown_fn", subInvocations: [] };
    expect(mutateAuthorization(a, "recipient")).toBeNull();
    expect(mutateAuthorization(a, "amount")).toBeNull();
  });
  it("network mutation is a different well-known passphrase", () => {
    expect(altNetwork("Test SDF Network ; September 2015")).toBe("Test SDF Future Network ; October 2022");
    expect(altNetwork("Public Global Stellar Network ; September 2015")).toBe("Test SDF Network ; September 2015");
  });
  it("every stored mutation: original signature fails, stored hash equals sha256 of the stored preimage", () => {
    for (const x of vectors.vectors) {
      const sigRaw = decodeEntry(entryFromXdr(x.expected.signedEntryXdr)).signature.rawXdr;
      for (const m of x.mutations) {
        const r = verifyEntry(assembleEntry(m.mutatedAuthorization, sigRaw).toXdr("base64"), m.mutatedAuthorization.networkPassphrase);
        expect(r.signatureValid).toBe(false);
        expect(r.payloadHashHex).toBe(m.expected.mutatedPayloadHashHex);
        expect(r.payloadHashHex).not.toBe(x.expected.payloadHashHex);
        expect(toHex(hash(Buffer.from(m.expected.mutatedPreimageXdr, "base64")))).toBe(m.expected.mutatedPayloadHashHex);
      }
    }
  });
  it("assembling the unmodified model with the original signature still verifies", () => {
    const sigRaw = decodeEntry(entryFromXdr(v.expected.signedEntryXdr)).signature.rawXdr;
    expect(verifyEntry(assembleEntry(v.authorization, sigRaw).toXdr("base64"), v.authorization.networkPassphrase).signatureValid).toBe(true);
  });
});

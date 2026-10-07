// These checks use Node's OpenSSL-backed crypto and a hand-written parse: a third implementation
// that shares nothing with the SDK adapter or the Rust adapter.
import { createHash, createPrivateKey, createPublicKey, verify } from "node:crypto";
import { describe, expect, it } from "vitest";
import { StrKey } from "@stellar/stellar-sdk";
import { fromBase64, fromHex } from "../src/bytes.ts";
import { vectorFileSchema } from "../src/vector.ts";
import { vectors } from "./helpers.ts";

function spkiFromG(g: string): ReturnType<typeof createPublicKey> {
  const raw = StrKey.decodeEd25519PublicKey(g);
  const prefix = Buffer.from("302a300506032b6570032100", "hex");
  return createPublicKey({ key: Buffer.concat([prefix, Buffer.from(raw)]), format: "der", type: "spki" });
}
const sha256 = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");

describe("vector file", () => {
  it("is valid against the zod schema and has the declared format", () => {
    expect(vectorFileSchema.parse(vectors)).toBeTruthy();
    expect(vectors.format).toBe("authmatrix-vectors");
    expect(vectors.formatVersion).toBe("1.0.0");
  });

  it("covers both credential types, a historical label, and all seven mutation fields on host-verifiable vectors", () => {
    expect(new Set(vectors.vectors.map((v) => v.authorization.credentialType))).toEqual(new Set(["address", "addressV2"]));
    expect(vectors.vectors.some((v) => v.compatibility.status === "historical-unverified")).toBe(true);
    for (const v of vectors.vectors.filter((x) => x.labels.includes("host-verifiable"))) {
      expect(new Set(v.mutations.map((m) => m.field))).toEqual(new Set(["recipient", "amount", "network", "nonce", "expiry", "function", "contractId"]));
    }
  });

  for (const v of vectors.vectors) {
    describe(v.id, () => {
      const pre = fromBase64(v.expected.preimageXdr);
      const dv = new DataView(pre.buffer, pre.byteOffset, pre.byteLength);
      it("preimage starts with the right envelope-type discriminant (XDR int)", () => {
        // ENVELOPE_TYPE_SOROBAN_AUTHORIZATION = 9, ..._WITH_ADDRESS = 10 (stellar-xdr generated unions)
        expect(dv.getInt32(0)).toBe(v.authorization.credentialType === "addressV2" ? 10 : 9);
      });
      it("preimage embeds sha256(network passphrase) right after the discriminant", () => {
        expect(Buffer.from(pre.subarray(4, 36)).toString("hex")).toBe(sha256(Buffer.from(v.authorization.networkPassphrase)));
      });
      it("preimage then carries the nonce and expiry big-endian", () => {
        expect(dv.getBigInt64(36)).toBe(BigInt(v.authorization.nonce));
        expect(dv.getUint32(44)).toBe(v.authorization.signatureExpirationLedger);
      });
      it("payload hash is sha256(preimage)", () => {
        expect(sha256(pre)).toBe(v.expected.payloadHashHex);
      });
      it("original signature verifies (OpenSSL ed25519) over the payload hash", () => {
        expect(verify(null, fromHex(v.expected.payloadHashHex), spkiFromG(v.signer.publicKey), fromHex(v.expected.signatureHex))).toBe(true);
      });
      it("signer key derivation is SHA-256 of the phrase", () => {
        const seed = createHash("sha256").update(v.signer.derivation.phrase).digest();
        expect(StrKey.encodeEd25519PublicKey(Buffer.from(spkiFromSeedPublic(seed)))).toBe(v.signer.publicKey);
      });
      for (const m of v.mutations) {
        it(`mutation ${m.field}: hash changes and the original signature fails (OpenSSL)`, () => {
          const mp = fromBase64(m.expected.mutatedPreimageXdr);
          const h = sha256(mp);
          expect(h).toBe(m.expected.mutatedPayloadHashHex);
          expect(h).not.toBe(v.expected.payloadHashHex);
          expect(verify(null, fromHex(h), spkiFromG(v.signer.publicKey), fromHex(v.expected.signatureHex))).toBe(false);
          expect(verify(null, fromHex(h), spkiFromG(v.signer.publicKey), fromHex(m.expected.resignedSignatureHex))).toBe(true);
          expect(m.changedPaths.length).toBeGreaterThan(0);
        });
      }
    });
  }
});

function spkiFromSeedPublic(seed: Buffer): Buffer {
  // derive the public key with OpenSSL from a PKCS#8-wrapped seed
  const pk = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]), format: "der", type: "pkcs8" });
  const spki = createPublicKey(pk).export({ format: "der", type: "spki" });
  return Buffer.from(spki).subarray(-32);
}

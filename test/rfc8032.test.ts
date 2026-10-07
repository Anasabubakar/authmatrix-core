import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import { describe, expect, it } from "vitest";
import { Keypair } from "@stellar/stellar-sdk";
import { ed25519Sign } from "../src/entry.ts";
import { fromHex, toHex } from "../src/bytes.ts";
import { rfc } from "./helpers.ts";

describe("RFC 8032 section 7.1 (independent source of truth for the signing primitive)", () => {
  it("has the expected number of vectors extracted from the RFC", () => {
    expect(rfc.vectors.length).toBe(4);
  });
  for (const t of rfc.vectors) {
    it(`${t.name}: SDK Keypair reproduces the RFC signature and public key`, () => {
      const r = ed25519Sign(t.secretKeyHex, t.messageHex);
      expect(r.publicKeyHex).toBe(t.publicKeyHex);
      expect(r.signatureHex).toBe(t.signatureHex);
      expect(Keypair.fromRawEd25519Seed(fromHex(t.secretKeyHex)).verify(fromHex(t.messageHex), fromHex(t.signatureHex))).toBe(true);
    });
    it(`${t.name}: OpenSSL reproduces it too`, () => {
      const key = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(t.secretKeyHex, "hex")]), format: "der", type: "pkcs8" });
      expect(toHex(sign(null, Buffer.from(t.messageHex, "hex"), key))).toBe(t.signatureHex);
      expect(Buffer.from(createPublicKey(key).export({ format: "der", type: "spki" })).subarray(-32).toString("hex")).toBe(t.publicKeyHex);
    });
  }
});

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { Address, nativeToScVal, xdr } from "@stellar/stellar-sdk";
import { toBase64 } from "../src/bytes.ts";
import { MAPPINGS, decodeCall } from "../src/tokens.ts";

const G = "GCNJ6G6URZQABOZET4ATLCF45IZV72NMOCU6VVQIXNG4FL7OVOCJ65O4";
const G2 = "GAFFHZ6ZU42PYHATI2LQPXP2WXIMVMRGJHRRCNA4XNZ7TBKJBUG4N5N3";
const addr = (a: string) => toBase64(xdr.ScVal.scvAddress(new Address(a).toScAddress()).toXdr());
const i128 = (n: bigint) => toBase64(nativeToScVal(n, { type: "i128" }).toXdr());

function parseSignatures(path: string): { name: string; args: { name: string; type: string }[] }[] {
  return readFileSync(path, "utf8")
    .split("\n")
    .filter((l) => l.trim().startsWith("fn "))
    .map((l) => {
      const m = l.match(/fn (\w+)\(env: Env,?\s*(.*?)\)(?: -> [\w]+)?;/)!;
      const args = m[2]!.trim() === "" ? [] : m[2]!.split(",").map((a) => {
        const [name, type] = a.split(":").map((x) => x.trim());
        return { name: name!, type: type! };
      });
      return { name: m[1]!, args };
    });
}

describe("token mappings agree with the reviewed source signatures", () => {
  const kindOf: Record<string, string> = { Address: "address", MuxedAddress: "address", i128: "i128", u32: "u32", bool: "bool" };
  for (const [file, source] of [
    ["docs/sources/sep41-signatures.txt", "SEP-41 v0.5.2"],
    ["docs/sources/sac-extra-signatures.txt", "Stellar Asset Contract (soroban-sdk 28.0.0 StellarAssetInterface; not in SEP-41)"],
  ] as const) {
    for (const sig of parseSignatures(file)) {
      it(`${source}: ${sig.name}(${sig.args.map((a) => a.name).join(", ")})`, () => {
        const m = MAPPINGS.find((x) => x.name === sig.name && x.source === source);
        expect(m, `mapping for ${sig.name}`).toBeTruthy();
        expect(m!.args.map((a) => a.name)).toEqual(sig.args.map((a) => a.name));
        expect(m!.args.map((a) => a.kind)).toEqual(sig.args.map((a) => kindOf[a.type]));
      });
    }
  }
  it("has no non-fixture mapping that is absent from the reviewed sources", () => {
    const known = new Set([...parseSignatures("docs/sources/sep41-signatures.txt"), ...parseSignatures("docs/sources/sac-extra-signatures.txt")].map((s) => s.name));
    for (const m of MAPPINGS.filter((x) => !x.source.startsWith("AuthMatrix"))) expect(known.has(m.name)).toBe(true);
  });
  it("SEP-41 defines no mint function; mint is labelled as a Stellar Asset Contract convention", () => {
    const sep = readFileSync("docs/sources/sep41-signatures.txt", "utf8");
    expect(sep).not.toMatch(/fn mint\(/);
    expect(MAPPINGS.find((m) => m.name === "mint")!.source).toMatch(/not in SEP-41/);
  });
});

describe("decodeCall", () => {
  it("decodes a SEP-41 transfer with exact i128 amounts and roles", () => {
    const d = decodeCall("transfer", [addr(G), addr(G2), i128(-170141183460469231731687303715884105728n)]);
    expect(d.status).toBe("mapped");
    if (d.status !== "mapped") return;
    expect(d.mapping.source).toBe("SEP-41 v0.5.2");
    expect(d.args.map((a) => [a.name, a.role, a.value])).toEqual([
      ["from", "sender", G],
      ["to", "recipient", G2],
      ["amount", "amount", "-170141183460469231731687303715884105728"],
    ]);
  });
  it("keeps unknown functions raw and typed", () => {
    const d = decodeCall("settle", [toBase64(xdr.ScVal.scvSymbol("x").toXdr())]);
    expect(d.status).toBe("unmapped");
    if (d.status === "unmapped") expect(d.args[0]!.typed).toEqual({ type: "symbol", value: "x" });
  });
  it("refuses a known name with the wrong arity or argument type (not guessed)", () => {
    expect(decodeCall("transfer", [addr(G), addr(G2)]).status).toBe("unmapped");
    const wrong = decodeCall("transfer", [addr(G), addr(G2), toBase64(xdr.ScVal.scvU32(5).toXdr())]);
    expect(wrong.status).toBe("unmapped");
    if (wrong.status === "unmapped") expect(wrong.reason).toMatch(/amount.*i128/);
  });
  it("decodes approve with the live_until_ledger as u32", () => {
    const d = decodeCall("approve", [addr(G), addr(G2), i128(5n), toBase64(xdr.ScVal.scvU32(99).toXdr())]);
    expect(d.status === "mapped" && d.args[3]!.value).toBe(99);
  });
  it("treats a muxed (M...) transfer destination as an address", () => {
    const m = "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK";
    const d = decodeCall("transfer", [addr(G), addr(m), i128(1n)]);
    expect(d.status).toBe("mapped");
  });
});

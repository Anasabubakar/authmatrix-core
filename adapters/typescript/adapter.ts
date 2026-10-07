// AuthMatrix adapter A: TypeScript on @stellar/stellar-sdk 17.2.1 (official helpers).
// Speaks authmatrix-adapter/1: one JSON request per stdin line, one JSON response per stdout line.
import { createInterface } from "node:readline";
import { Address } from "@stellar/stellar-sdk";
import { buildCanonical, decodeEntry, deriveKeypair, ed25519Sign, entryFromXdr, verifyEntry } from "../../src/entry.ts";
import { toHex } from "../../src/bytes.ts";
import { ADAPTER_PROTOCOL, requestSchema } from "../../src/vector.ts";
import type { DescribeResult } from "../../src/vector.ts";

// Pinned exactly in package.json; test/adapter-describe checks package.json agrees.
const sdkVersion = "17.2.1";

const describe: DescribeResult = {
  adapter: "authmatrix-adapter-typescript",
  language: "TypeScript (Node)",
  xdrImplementation: `@stellar/stellar-sdk ${sdkVersion} generated xdr classes (@stellar/js-xdr)`,
  signingImplementation: `@stellar/stellar-sdk ${sdkVersion} Keypair / authorizeEntry (ed25519 via @noble/ed25519, sha512 via @noble/hashes)`,
  hashImplementation: `@stellar/stellar-sdk ${sdkVersion} hash() (sha256 via @noble/hashes)`,
  ops: ["describe", "derive_key", "build", "decode", "verify", "ed25519_sign"],
};

async function handle(line: string): Promise<unknown> {
  let id = -1;
  try {
    const raw = JSON.parse(line);
    if (typeof raw?.id === "number") id = raw.id;
    const req = requestSchema.parse(raw);
    switch (req.op) {
      case "describe":
        return { protocol: ADAPTER_PROTOCOL, id, ok: true, result: describe };
      case "derive_key": {
        const kp = deriveKeypair(req.params.phrase);
        return { protocol: ADAPTER_PROTOCOL, id, ok: true, result: { publicKey: kp.publicKey(), publicKeyHex: toHex(new Address(kp.publicKey()).toBuffer()) } };
      }
      case "build":
        return { protocol: ADAPTER_PROTOCOL, id, ok: true, result: await buildCanonical(req.params.authorization, req.params.phrase) };
      case "decode":
        return { protocol: ADAPTER_PROTOCOL, id, ok: true, result: decodeEntry(entryFromXdr(req.params.entryXdr)) };
      case "verify":
        return { protocol: ADAPTER_PROTOCOL, id, ok: true, result: verifyEntry(req.params.entryXdr, req.params.networkPassphrase) };
      case "ed25519_sign":
        return { protocol: ADAPTER_PROTOCOL, id, ok: true, result: ed25519Sign(req.params.secretKeyHex, req.params.messageHex) };
    }
  } catch (e) {
    return { protocol: ADAPTER_PROTOCOL, id, ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}

const rl = createInterface({ input: process.stdin });
const pending: Promise<void>[] = [];
let chain: Promise<void> = Promise.resolve();
rl.on("line", (line) => {
  if (line.trim() === "") return;
  chain = chain.then(async () => {
    process.stdout.write(JSON.stringify(await handle(line)) + "\n");
  });
  pending.push(chain);
});
rl.on("close", () => {
  void chain.then(() => process.exit(0));
});

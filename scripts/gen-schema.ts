// Run with: node --experimental-strip-types scripts/gen-schema.ts [--check]
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { z } from "zod";
import {
  decodedEntrySchema,
  describeResultSchema,
  evidenceFileSchema,
  requestSchema,
  responseSchema,
  rfc8032Schema,
  vectorFileSchema,
  verifyResultSchema,
  canonicalSchema,
} from "../src/vector.ts";

const check = process.argv.includes("--check");
const protocolDoc = z.object({
  request: requestSchema,
  response: responseSchema,
  results: z.object({
    describe: describeResultSchema,
    derive_key: z.object({ publicKey: z.string(), publicKeyHex: z.string() }),
    build: canonicalSchema,
    decode: decodedEntrySchema,
    verify: verifyResultSchema,
    ed25519_sign: z.object({ publicKeyHex: z.string(), signatureHex: z.string() }),
  }),
});

const targets: Array<[string, z.ZodType, string]> = [
  ["schema/vector.v1.schema.json", vectorFileSchema, "AuthMatrix vector file v1"],
  ["schema/adapter-protocol.v1.schema.json", protocolDoc, "AuthMatrix adapter protocol v1 (newline-delimited JSON over stdio)"],
  ["schema/evidence.v1.schema.json", evidenceFileSchema, "AuthMatrix host-verification evidence v1"],
  ["schema/rfc8032.v1.schema.json", rfc8032Schema, "AuthMatrix RFC 8032 vectors v1"],
];

mkdirSync("schema", { recursive: true });
let stale = false;
for (const [path, schema, title] of targets) {
  const json = { title, ...z.toJSONSchema(schema, { target: "draft-2020-12", io: "input", unrepresentable: "any" }) };
  const text = JSON.stringify(json, null, 2) + "\n";
  if (check) {
    let current = "";
    try {
      current = readFileSync(path, "utf8");
    } catch {
      /* missing counts as stale */
    }
    if (current !== text) {
      console.error(`${path} is out of date; run pnpm schema`);
      stale = true;
    }
  } else {
    writeFileSync(path, text);
    console.log(`wrote ${path}`);
  }
}
if (stale) process.exit(1);

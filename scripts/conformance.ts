// Runs both adapters over the committed vectors. Usage:
//   node --experimental-strip-types scripts/conformance.ts [--rust <path-to-binary>] [--out report.json]
import { existsSync, writeFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { loadRfc8032, loadVectors } from "../src/node.ts";
import { runConformance, type AdapterSpec } from "../src/runner.ts";

const { values } = parseArgs({ options: { rust: { type: "string" }, out: { type: "string" } } });
const target = process.env["CARGO_TARGET_DIR"] ?? "adapters/rust/target";
const rustBin = values.rust ?? `${target}/release/authmatrix-adapter-rust`;
if (!existsSync(rustBin)) {
  console.error(`Rust adapter binary not found at ${rustBin}. Build it: (cd adapters/rust && cargo build --release -j2)`);
  process.exit(2);
}
const specs: AdapterSpec[] = [
  { name: "typescript", command: process.execPath, args: ["--experimental-strip-types", "--no-warnings", "adapters/typescript/adapter.ts"] },
  { name: "rust", command: rustBin, args: [] },
];
const report = await runConformance(loadVectors("vectors/authmatrix-vectors.v1.json"), loadRfc8032("vectors/rfc8032-ed25519.json"), specs);
for (const a of report.adapters) console.log(`adapter ${a.adapter}: ${a.xdrImplementation}; ${a.signingImplementation}; ${a.hashImplementation}`);
for (const c of report.checks.filter((c) => !c.ok)) console.log(`FAIL [${c.adapter}] ${c.vectorId}: ${c.check} :: ${c.detail}`);
for (const a of report.agreements.filter((a) => !a.ok)) console.log(`DISAGREE ${a.vectorId} ${a.op}: ${a.detail}`);
console.log(`checks ok ${report.checks.filter((c) => c.ok).length}/${report.checks.length}; adapter agreements ok ${report.agreements.filter((a) => a.ok).length}/${report.agreements.length}`);
if (values.out) writeFileSync(values.out, JSON.stringify({ ...report, checks: undefined, summary: { checks: report.checks.length, agreements: report.agreements.length, failed: report.failed } }, null, 2) + "\n");
process.exit(report.failed === 0 ? 0 : 1);

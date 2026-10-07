import { existsSync } from "node:fs";
import { loadRfc8032, loadVectors } from "../src/node.ts";
import type { AdapterSpec } from "../src/runner.ts";

export const vectors = loadVectors("vectors/authmatrix-vectors.v1.json");
export const rfc = loadRfc8032("vectors/rfc8032-ed25519.json");

export function rustBinary(): string {
  const target = process.env["CARGO_TARGET_DIR"] ?? "adapters/rust/target";
  const bin = process.env["AUTHMATRIX_RUST_ADAPTER"] ?? `${target}/release/authmatrix-adapter-rust`;
  if (!existsSync(bin)) {
    // A missing second adapter is a failure, never a skip: independence is the point.
    throw new Error(`Rust adapter not built at ${bin}. Run: (cd adapters/rust && cargo build --release -j2), or set AUTHMATRIX_RUST_ADAPTER.`);
  }
  return bin;
}

export function adapterSpecs(): AdapterSpec[] {
  return [
    { name: "typescript", command: process.execPath, args: ["--experimental-strip-types", "--no-warnings", "adapters/typescript/adapter.ts"] },
    { name: "rust", command: rustBinary(), args: [] },
  ];
}

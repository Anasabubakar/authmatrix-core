/** Node-only helpers (file loading). Not part of the browser-safe entry point. */
import { readFileSync } from "node:fs";
import { evidenceFileSchema, rfc8032Schema, vectorFileSchema, type EvidenceFile, type Rfc8032File, type VectorFile } from "./vector.ts";

export function loadVectors(path: string): VectorFile {
  return vectorFileSchema.parse(JSON.parse(readFileSync(path, "utf8")));
}
export function loadRfc8032(path: string): Rfc8032File {
  return rfc8032Schema.parse(JSON.parse(readFileSync(path, "utf8")));
}
export function loadEvidence(path: string): EvidenceFile {
  return evidenceFileSchema.parse(JSON.parse(readFileSync(path, "utf8")));
}

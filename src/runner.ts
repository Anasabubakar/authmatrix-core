/**
 * Conformance runner (Node only). Spawns adapters that speak authmatrix-adapter/1, drives every
 * vector and mutation through each, checks each against the reviewed vector file, and checks that
 * all adapters agree with each other on the exact bytes.
 */
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createInterface } from "node:readline";
import { isDeepStrictEqual } from "node:util";
import {
  ADAPTER_PROTOCOL,
  describeResultSchema,
  responseSchema,
  type DecodedEntry,
  type DescribeResult,
  type Rfc8032File,
  type Vector,
  type VectorFile,
} from "./vector.ts";

export interface AdapterSpec {
  name: string;
  command: string;
  args: string[];
  cwd?: string;
}

export class AdapterProcess {
  private child: ChildProcessWithoutNullStreams;
  private pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();
  private nextId = 1;
  private stderr = "";
  readonly spec: AdapterSpec;
  constructor(spec: AdapterSpec) {
    this.spec = spec;
    this.child = spawn(spec.command, spec.args, { cwd: spec.cwd, stdio: ["pipe", "pipe", "pipe"] });
    this.child.stderr.on("data", (d) => (this.stderr += String(d)));
    createInterface({ input: this.child.stdout }).on("line", (line) => {
      let parsed;
      try {
        parsed = responseSchema.parse(JSON.parse(line));
      } catch (e) {
        this.failAll(new Error(`${spec.name}: unparseable response: ${line.slice(0, 200)}`));
        return;
      }
      const p = this.pending.get(parsed.id);
      if (!p) return;
      this.pending.delete(parsed.id);
      if (parsed.ok) p.resolve(parsed.result);
      else p.reject(new Error(`${spec.name}: ${parsed.error}`));
    });
    this.child.on("exit", (code) => this.failAll(new Error(`${spec.name} exited with code ${code}. stderr: ${this.stderr.slice(0, 500)}`)));
    this.child.on("error", (e) => this.failAll(new Error(`${spec.name}: failed to start: ${e.message}`)));
  }
  private failAll(err: Error) {
    for (const p of this.pending.values()) p.reject(err);
    this.pending.clear();
  }
  request(op: string, params?: unknown): Promise<unknown> {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.child.stdin.write(JSON.stringify({ protocol: ADAPTER_PROTOCOL, id, op, ...(params === undefined ? {} : { params }) }) + "\n");
    });
  }
  close() {
    this.child.stdin.end();
  }
}

export interface Check {
  adapter: string;
  vectorId: string;
  check: string;
  ok: boolean;
  detail?: string;
}
export interface Agreement {
  vectorId: string;
  op: string;
  ok: boolean;
  detail?: string;
}
export interface ConformanceReport {
  adapters: DescribeResult[];
  checks: Check[];
  agreements: Agreement[];
  passed: number;
  failed: number;
}

function expectEqual(checks: Check[], adapter: string, vectorId: string, check: string, actual: unknown, expected: unknown) {
  const ok = isDeepStrictEqual(actual, expected);
  checks.push({ adapter, vectorId, check, ok, ...(ok ? {} : { detail: `expected ${JSON.stringify(expected).slice(0, 160)} got ${JSON.stringify(actual).slice(0, 160)}` }) });
}

function invocationShape(inv: Vector["authorization"]["rootInvocation"]): unknown {
  return { kind: "contractFn", contractId: inv.contractId, functionName: inv.functionName, args: inv.args, subInvocations: inv.subInvocations.map(invocationShape) };
}

function expectedDecode(v: Vector): Omit<DecodedEntry, "signature"> {
  const a = v.authorization;
  return {
    credentialType: a.credentialType,
    address: a.address,
    nonce: a.nonce,
    signatureExpirationLedger: a.signatureExpirationLedger,
    delegateCount: 0,
    rootInvocation: invocationShape(a.rootInvocation) as DecodedEntry["rootInvocation"],
  };
}

export async function runConformance(vectors: VectorFile, rfc: Rfc8032File, specs: AdapterSpec[]): Promise<ConformanceReport> {
  const procs = specs.map((s) => new AdapterProcess(s));
  const checks: Check[] = [];
  const agreements: Agreement[] = [];
  try {
    const adapters = await Promise.all(procs.map(async (p) => describeResultSchema.parse(await p.request("describe"))));
    const record = async (vectorId: string, op: string, params: unknown) => {
      const results = await Promise.all(procs.map((p) => p.request(op, params)));
      const first = results[0];
      const ok = results.every((r) => isDeepStrictEqual(r, first));
      agreements.push({ vectorId, op, ok, ...(ok ? {} : { detail: `adapters disagree: ${results.map((r) => JSON.stringify(r).slice(0, 120)).join(" | ")}` }) });
      return results;
    };

    for (const v of vectors.vectors) {
      const phrase = v.signer.derivation.phrase;
      const keys = (await record(v.id, "derive_key", { phrase })) as { publicKey: string }[];
      const builds = (await record(v.id, "build", { authorization: v.authorization, phrase })) as unknown[];
      const decodes = (await record(v.id, "decode", { entryXdr: v.expected.signedEntryXdr })) as DecodedEntry[];
      const verifies = (await record(v.id, "verify", { entryXdr: v.expected.signedEntryXdr, networkPassphrase: v.authorization.networkPassphrase })) as { signatureValid: boolean; payloadHashHex: string }[];
      for (let i = 0; i < procs.length; i++) {
        const name = adapters[i]!.adapter;
        expectEqual(checks, name, v.id, "derive_key matches vector signer", keys[i]!.publicKey, v.signer.publicKey);
        expectEqual(checks, name, v.id, "build reproduces reviewed canonical bytes", builds[i], v.expected);
        const { signature, ...rest } = decodes[i]!;
        expectEqual(checks, name, v.id, "decode(signedEntry) matches authorization", rest, expectedDecode(v));
        expectEqual(checks, name, v.id, "decoded signature is the reviewed ed25519 signature", { kind: signature.kind, signatureHex: signature.signatureHex }, { kind: "ed25519", signatureHex: v.expected.signatureHex });
        expectEqual(checks, name, v.id, "original signature verifies over the reviewed payload hash", { valid: verifies[i]!.signatureValid, hash: verifies[i]!.payloadHashHex }, { valid: true, hash: v.expected.payloadHashHex });
      }
      for (const m of v.mutations) {
        const mid = m.id;
        const mv = (await record(mid, "verify", { entryXdr: m.expected.entryXdrWithOriginalSignature, networkPassphrase: m.mutatedAuthorization.networkPassphrase })) as { signatureValid: boolean; payloadHashHex: string; preimageXdr: string }[];
        const mb = (await record(mid, "build", { authorization: m.mutatedAuthorization, phrase })) as { payloadHashHex: string; preimageXdr: string; signatureHex: string; signedEntryXdr: string }[];
        for (let i = 0; i < procs.length; i++) {
          const name = adapters[i]!.adapter;
          expectEqual(checks, name, mid, "mutated payload hash equals reviewed value", mv[i]!.payloadHashHex, m.expected.mutatedPayloadHashHex);
          expectEqual(checks, name, mid, "mutated preimage equals reviewed bytes", mv[i]!.preimageXdr, m.expected.mutatedPreimageXdr);
          expectEqual(checks, name, mid, "mutated payload hash differs from original", mv[i]!.payloadHashHex !== v.expected.payloadHashHex, true);
          expectEqual(checks, name, mid, "original signature no longer verifies", mv[i]!.signatureValid, false);
          expectEqual(checks, name, mid, "re-signing the mutated tree yields a different signature", mb[i]!.signatureHex !== v.expected.signatureHex && mb[i]!.payloadHashHex === m.expected.mutatedPayloadHashHex, true);
          expectEqual(checks, name, mid, "re-signed mutated entry equals reviewed bytes", { entry: mb[i]!.signedEntryXdr, sig: mb[i]!.signatureHex }, { entry: m.expected.resignedEntryXdr, sig: m.expected.resignedSignatureHex });
        }
      }
    }
    for (const t of rfc.vectors) {
      const rs = (await record("rfc8032:" + t.name, "ed25519_sign", { secretKeyHex: t.secretKeyHex, messageHex: t.messageHex })) as { publicKeyHex: string; signatureHex: string }[];
      for (let i = 0; i < procs.length; i++) {
        expectEqual(checks, adapters[i]!.adapter, "rfc8032:" + t.name, "ed25519 signature equals RFC 8032 value", rs[i], { publicKeyHex: t.publicKeyHex, signatureHex: t.signatureHex });
      }
    }
    const passed = checks.filter((c) => c.ok).length + agreements.filter((a) => a.ok).length;
    const failed = checks.filter((c) => !c.ok).length + agreements.filter((a) => !a.ok).length;
    return { adapters, checks, agreements, passed, failed };
  } finally {
    procs.forEach((p) => p.close());
  }
}

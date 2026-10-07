import { Address, Keypair, StrKey, hash, nativeToScVal, xdr } from "@stellar/stellar-sdk";
import { toBase64 } from "./bytes.ts";
import { findMapping } from "./tokens.ts";
import type { Authorization, Invocation, MutationField } from "./vector.ts";

export const MUTATION_FIELDS: MutationField[] = ["recipient", "amount", "network", "nonce", "expiry", "function", "contractId"];

export interface MutateOptions {
  /** Replacement recipient (G... or C...). Default: deterministic derivation from the original. */
  recipient?: string;
  /** Replacement contract id for the ROOT invocation. Default: deterministic derivation. */
  contractId?: string;
  networkPassphrase?: string;
}

const I128_MAX = (1n << 127n) - 1n;

function mapInvocation(inv: Invocation, f: (i: Invocation) => Invocation): Invocation {
  const mapped = f(inv);
  return { ...mapped, subInvocations: inv.subInvocations.map((s) => mapInvocation(s, f)) };
}

function altRecipient(original: string): string {
  return Keypair.fromRawEd25519Seed(hash("authmatrix:recipient-mutation:" + original)).publicKey();
}

export function altNetwork(passphrase: string): string {
  if (passphrase === "Test SDF Network ; September 2015") return "Test SDF Future Network ; October 2022";
  return "Test SDF Network ; September 2015";
}

/** Returns the mutated authorization, or null if the field has nothing to mutate in this tree. */
export function mutateAuthorization(a: Authorization, field: MutationField, opts: MutateOptions = {}): Authorization | null {
  switch (field) {
    case "network":
      return { ...a, networkPassphrase: opts.networkPassphrase ?? altNetwork(a.networkPassphrase) };
    case "nonce": {
      const n = BigInt(a.nonce);
      return { ...a, nonce: (n === (1n << 63n) - 1n ? n - 1n : n + 1n).toString() };
    }
    case "expiry":
      return { ...a, signatureExpirationLedger: a.signatureExpirationLedger === 4294967295 ? a.signatureExpirationLedger - 1 : a.signatureExpirationLedger + 1 };
    case "function": {
      const name = a.rootInvocation.functionName;
      const next = name === "relay" ? "relay_alt" : name === "relay_alt" ? "relay" : name.length < 32 ? name + "_" : name.slice(0, -1);
      return { ...a, rootInvocation: { ...a.rootInvocation, functionName: next } };
    }
    case "contractId": {
      const raw = StrKey.decodeContract(a.rootInvocation.contractId);
      const next = opts.contractId ?? StrKey.encodeContract(hash(raw));
      return { ...a, rootInvocation: { ...a.rootInvocation, contractId: next } };
    }
    case "recipient":
    case "amount": {
      let changed = false;
      const role = field === "recipient" ? "recipient" : "amount";
      const rootInv = mapInvocation(a.rootInvocation, (inv) => {
        const m = findMapping(inv.functionName, inv.args.length);
        if (!m) return inv;
        const args = inv.args.map((arg, i) => {
          if (m.args[i]?.role !== role) return arg;
          const v = xdr.ScVal.fromXdr(arg, "base64");
          if (role === "recipient" && v.type === "scvAddress") {
            changed = true;
            const orig = Address.fromScAddress(v.address).toString();
            return toBase64(xdr.ScVal.scvAddress(new Address(opts.recipient ?? altRecipient(orig)).toScAddress()).toXdr());
          }
          if (role === "amount" && v.type === "scvI128") {
            const cur = (BigInt.asUintN(64, v.i128.hi) << 64n) | v.i128.lo;
            const signed = BigInt.asIntN(128, cur);
            const next = signed * 10n <= I128_MAX && signed * 10n >= -I128_MAX ? signed * 10n || 1n : signed - 1n;
            changed = true;
            return toBase64(nativeToScVal(next, { type: "i128" }).toXdr());
          }
          return arg;
        });
        return { ...inv, args };
      });
      return changed ? { ...a, rootInvocation: rootInv } : null;
    }
  }
}

/** Paths into the Authorization that differ, e.g. "rootInvocation.args[2]". */
export function diffPaths(a: unknown, b: unknown, path = ""): string[] {
  if (Array.isArray(a) && Array.isArray(b)) {
    const out: string[] = [];
    for (let i = 0; i < Math.max(a.length, b.length); i++) out.push(...diffPaths(a[i], b[i], `${path}[${i}]`));
    return out;
  }
  if (a && b && typeof a === "object" && typeof b === "object") {
    const out: string[] = [];
    for (const k of new Set([...Object.keys(a), ...Object.keys(b)])) {
      out.push(...diffPaths((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k], path ? `${path}.${k}` : k));
    }
    return out;
  }
  return a === b ? [] : [path];
}

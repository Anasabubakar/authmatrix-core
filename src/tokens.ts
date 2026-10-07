/**
 * Reviewed argument-schema mappings for known token functions.
 *
 * Sources (read on 2026-10-07):
 *  - SEP-41 "Soroban Token Interface", version 0.5.2 (stellar-protocol ecosystem/sep-0041.md):
 *    allowance, approve, balance, transfer (to: MuxedAddress), transfer_from, burn, burn_from,
 *    decimals, name, symbol. SEP-41 deliberately defines NO mint/clawback function (events only).
 *  - soroban-sdk 28.0.0 `token::StellarAssetInterface` (the built-in Stellar Asset Contract):
 *    adds set_admin, admin, set_authorized, authorized, mint(to, amount), clawback(from, amount), trust.
 *    These are SAC conventions, not SEP-41, and are labelled as such.
 *
 * A mapping is applied by function name + arity + argument ScVal types ONLY. The contract is not
 * known to be a token; the label says "token-shaped call", never "token transfer".
 */
import { typedFromScVal, type TypedVal } from "./scval.ts";
import { xdr } from "@stellar/stellar-sdk/base";

export type ArgKind = "address" | "i128" | "u32" | "bool";
export type Role = "sender" | "spender" | "recipient" | "holder" | "amount" | "expiryLedger" | "admin" | "target";

export interface ArgSpec {
  name: string;
  kind: ArgKind;
  role?: Role;
}
export type MappingSource = "SEP-41 v0.5.2" | "Stellar Asset Contract (soroban-sdk 28.0.0 StellarAssetInterface; not in SEP-41)" | "AuthMatrix nested-call fixture (not a token standard)";

export interface FnMapping {
  name: string;
  args: ArgSpec[];
  source: MappingSource;
  summary: string;
}

const SEP41: MappingSource = "SEP-41 v0.5.2";
const SAC: MappingSource = "Stellar Asset Contract (soroban-sdk 28.0.0 StellarAssetInterface; not in SEP-41)";
const FIXTURE: MappingSource = "AuthMatrix nested-call fixture (not a token standard)";

export const MAPPINGS: FnMapping[] = [
  { name: "allowance", source: SEP41, summary: "read allowance", args: [{ name: "from", kind: "address", role: "holder" }, { name: "spender", kind: "address", role: "spender" }] },
  {
    name: "approve",
    source: SEP41,
    summary: "set spender allowance",
    args: [
      { name: "from", kind: "address", role: "holder" },
      { name: "spender", kind: "address", role: "spender" },
      { name: "amount", kind: "i128", role: "amount" },
      { name: "live_until_ledger", kind: "u32", role: "expiryLedger" },
    ],
  },
  { name: "balance", source: SEP41, summary: "read balance", args: [{ name: "id", kind: "address", role: "holder" }] },
  {
    name: "transfer",
    source: SEP41,
    summary: "transfer amount from `from` to `to`",
    args: [
      { name: "from", kind: "address", role: "sender" },
      { name: "to", kind: "address", role: "recipient" },
      { name: "amount", kind: "i128", role: "amount" },
    ],
  },
  {
    name: "transfer_from",
    source: SEP41,
    summary: "spender moves amount from `from` to `to` using its allowance",
    args: [
      { name: "spender", kind: "address", role: "spender" },
      { name: "from", kind: "address", role: "sender" },
      { name: "to", kind: "address", role: "recipient" },
      { name: "amount", kind: "i128", role: "amount" },
    ],
  },
  { name: "burn", source: SEP41, summary: "burn amount from `from`", args: [{ name: "from", kind: "address", role: "sender" }, { name: "amount", kind: "i128", role: "amount" }] },
  {
    name: "burn_from",
    source: SEP41,
    summary: "spender burns amount from `from` using its allowance",
    args: [{ name: "spender", kind: "address", role: "spender" }, { name: "from", kind: "address", role: "sender" }, { name: "amount", kind: "i128", role: "amount" }],
  },
  { name: "decimals", source: SEP41, summary: "read decimals", args: [] },
  { name: "name", source: SEP41, summary: "read name", args: [] },
  { name: "symbol", source: SEP41, summary: "read symbol", args: [] },
  { name: "mint", source: SAC, summary: "admin mints amount to `to`", args: [{ name: "to", kind: "address", role: "recipient" }, { name: "amount", kind: "i128", role: "amount" }] },
  { name: "clawback", source: SAC, summary: "admin claws back amount from `from`", args: [{ name: "from", kind: "address", role: "sender" }, { name: "amount", kind: "i128", role: "amount" }] },
  { name: "set_admin", source: SAC, summary: "change admin", args: [{ name: "new_admin", kind: "address", role: "admin" }] },
  { name: "admin", source: SAC, summary: "read admin", args: [] },
  { name: "set_authorized", source: SAC, summary: "set authorization flag for `id`", args: [{ name: "id", kind: "address", role: "target" }, { name: "authorize", kind: "bool" }] },
  { name: "authorized", source: SAC, summary: "read authorization flag", args: [{ name: "id", kind: "address", role: "target" }] },
  { name: "trust", source: SAC, summary: "trust address", args: [{ name: "addr", kind: "address", role: "target" }] },
  ...["relay", "relay_alt"].map(
    (name): FnMapping => ({
      name,
      source: FIXTURE,
      summary: "fixture: requires `from` auth, then calls inner.transfer(from, to, amount)",
      args: [
        { name: "inner", kind: "address", role: "target" },
        { name: "from", kind: "address", role: "sender" },
        { name: "to", kind: "address", role: "recipient" },
        { name: "amount", kind: "i128", role: "amount" },
      ],
    }),
  ),
];

export interface DecodedArg {
  name: string;
  role?: Role;
  kind: ArgKind;
  value: string | number | boolean;
  xdr: string;
}
export type CallDecoding =
  | { status: "mapped"; mapping: { name: string; source: MappingSource; summary: string }; args: DecodedArg[] }
  | { status: "unmapped"; reason: string; args: TypedVal[] };

function matchKind(v: xdr.ScVal, kind: ArgKind): string | number | boolean | null {
  const t = typedFromScVal(v).typed;
  switch (kind) {
    case "address":
      return t.type === "address" ? t.value : null;
    case "i128":
      return t.type === "i128" ? t.value : null;
    case "u32":
      return t.type === "u32" ? t.value : null;
    case "bool":
      return t.type === "bool" ? t.value : null;
  }
}

/** Decode a call's arguments via the reviewed mapping; anything that does not fit stays raw/typed. */
export function decodeCall(functionName: string, argsB64: string[], mappings: FnMapping[] = MAPPINGS): CallDecoding {
  const scvals = argsB64.map((a) => xdr.ScVal.fromXdr(a, "base64"));
  const raw = () => scvals.map(typedFromScVal);
  const candidates = mappings.filter((m) => m.name === functionName);
  if (candidates.length === 0) return { status: "unmapped", reason: "function name is not in the reviewed mapping table", args: raw() };
  let lastReason = "";
  for (const m of candidates) {
    if (m.args.length !== scvals.length) {
      lastReason = `arity ${scvals.length} differs from the ${m.source} signature (${m.args.length})`;
      continue;
    }
    const out: DecodedArg[] = [];
    let ok = true;
    for (let i = 0; i < m.args.length; i++) {
      const spec = m.args[i]!;
      const val = matchKind(scvals[i]!, spec.kind);
      if (val === null) {
        lastReason = `argument ${i} (${spec.name}) is not a ${spec.kind}`;
        ok = false;
        break;
      }
      out.push({ name: spec.name, ...(spec.role ? { role: spec.role } : {}), kind: spec.kind, value: val, xdr: argsB64[i]! });
    }
    if (ok) return { status: "mapped", mapping: { name: m.name, source: m.source, summary: m.summary }, args: out };
  }
  return { status: "unmapped", reason: lastReason, args: raw() };
}

export function findMapping(functionName: string, arity: number): FnMapping | undefined {
  return MAPPINGS.find((m) => m.name === functionName && m.args.length === arity);
}

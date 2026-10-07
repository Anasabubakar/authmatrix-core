import { Address, scValToBigInt, xdr } from "@stellar/stellar-sdk";
import { toBase64, toHex } from "./bytes.ts";

/**
 * Typed, lossless-by-construction view of an ScVal. `xdr` always carries the exact original
 * bytes (base64); `typed` is a convenience reading. Types this module does not interpret stay
 * `raw` with their XDR, never guessed.
 */
export type Typed =
  | { type: "void" }
  | { type: "bool"; value: boolean }
  | { type: "u32" | "i32"; value: number }
  | { type: "u64" | "i64" | "timepoint" | "duration" | "u128" | "i128" | "u256" | "i256"; value: string }
  | { type: "bytes"; hex: string }
  | { type: "string" | "symbol"; value: string }
  | { type: "vec"; items: TypedVal[] | null }
  | { type: "map"; entries: { key: TypedVal; val: TypedVal }[] | null }
  | { type: "address"; value: string; addressType: string }
  | { type: "raw"; scvType: string };

export interface TypedVal {
  xdr: string;
  typed: Typed;
}

function text(s: { toStringStrict(): string }): string | null {
  try {
    return s.toStringStrict();
  } catch {
    return null;
  }
}

export function typedFromScVal(v: xdr.ScVal): TypedVal {
  return { xdr: toBase64(v.toXdr()), typed: typedInner(v) };
}

function typedInner(v: xdr.ScVal): Typed {
  switch (v.type) {
    case "scvVoid":
      return { type: "void" };
    case "scvBool":
      return { type: "bool", value: v.b };
    case "scvU32":
      return { type: "u32", value: v.u32 };
    case "scvI32":
      return { type: "i32", value: v.i32 };
    case "scvU64":
      return { type: "u64", value: v.u64.toString() };
    case "scvI64":
      return { type: "i64", value: v.i64.toString() };
    case "scvTimepoint":
      return { type: "timepoint", value: v.timepoint.toString() };
    case "scvDuration":
      return { type: "duration", value: v.duration.toString() };
    case "scvU128":
      return { type: "u128", value: scValToBigInt(v).toString() };
    case "scvI128":
      return { type: "i128", value: scValToBigInt(v).toString() };
    case "scvU256":
      return { type: "u256", value: scValToBigInt(v).toString() };
    case "scvI256":
      return { type: "i256", value: scValToBigInt(v).toString() };
    case "scvBytes":
      return { type: "bytes", hex: toHex(v.bytes.value) };
    case "scvString": {
      const t = text(v.str);
      return t === null ? { type: "bytes", hex: toHex(v.str.bytes) } : { type: "string", value: t };
    }
    case "scvSymbol": {
      const t = text(v.sym);
      return t === null ? { type: "bytes", hex: toHex(v.sym.bytes) } : { type: "symbol", value: t };
    }
    case "scvVec":
      return { type: "vec", items: v.vec === null ? null : v.vec.map(typedFromScVal) };
    case "scvMap":
      return { type: "map", entries: v.map === null ? null : v.map.map((e) => ({ key: typedFromScVal(e.key), val: typedFromScVal(e.val) })) };
    case "scvAddress": {
      const a = Address.fromScAddress(v.address);
      return { type: "address", value: a.toString(), addressType: a.type };
    }
    default:
      return { type: "raw", scvType: v.type };
  }
}

export function scValFromBase64(b64: string): xdr.ScVal {
  return xdr.ScVal.fromXdr(b64, "base64");
}

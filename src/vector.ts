import { z } from "zod";

/** Format identifiers. Bump formatVersion on any breaking change to the JSON shape. */
export const VECTOR_FORMAT = "authmatrix-vectors";
export const VECTOR_FORMAT_VERSION = "1.0.0";
export const ADAPTER_PROTOCOL = "authmatrix-adapter/1";
export const EVIDENCE_FORMAT = "authmatrix-evidence";
export const EVIDENCE_FORMAT_VERSION = "1.0.0";

const base64 = z.string().regex(/^[A-Za-z0-9+/]*={0,2}$/, "base64");
const hex = (bytes: number) => z.string().regex(new RegExp(`^[0-9a-f]{${bytes * 2}}$`), `${bytes} bytes of lowercase hex`);
const int64String = z.string().regex(/^-?\d{1,19}$/, "decimal int64 string");

export const invocationSchema: z.ZodType<Invocation> = z.lazy(() =>
  z.object({
    contractId: z.string().regex(/^C[A-Z2-7]{55}$/, "contract strkey (C...)"),
    functionName: z.string().min(1).max(32),
    args: z.array(base64).describe("each element is one ScVal serialized as XDR then base64"),
    subInvocations: z.array(invocationSchema),
  }),
);
export interface Invocation {
  contractId: string;
  functionName: string;
  args: string[];
  subInvocations: Invocation[];
}

export const credentialTypeSchema = z.enum(["address", "addressV2"]).describe(
  "address = SOROBAN_CREDENTIALS_ADDRESS (legacy payload, not address-bound); addressV2 = SOROBAN_CREDENTIALS_ADDRESS_V2 (CAP-71, address-bound payload)",
);

export const authorizationSchema = z.object({
  networkPassphrase: z.string().min(1),
  credentialType: credentialTypeSchema,
  address: z.string().regex(/^G[A-Z2-7]{55}$/, "ed25519 account strkey (G...)").describe("the authorizing address; must equal the signer public key"),
  nonce: int64String,
  signatureExpirationLedger: z.number().int().min(0).max(4294967295),
  rootInvocation: invocationSchema,
});
export type Authorization = z.infer<typeof authorizationSchema>;

export const signerSchema = z.object({
  publicKey: z.string().regex(/^G[A-Z2-7]{55}$/),
  derivation: z.object({
    scheme: z.literal("sha256-of-utf8-phrase"),
    phrase: z.string().min(8),
    note: z.string(),
  }),
});
export type Signer = z.infer<typeof signerSchema>;

export const preimageTypeSchema = z.enum(["envelopeTypeSorobanAuthorization", "envelopeTypeSorobanAuthorizationWithAddress"]);

export const canonicalSchema = z.object({
  preimageType: preimageTypeSchema,
  preimageXdr: base64,
  payloadHashHex: hex(32).describe("sha256 over the preimage XDR bytes"),
  signatureHex: hex(64),
  unsignedEntryXdr: base64,
  signedEntryXdr: base64,
});
export type Canonical = z.infer<typeof canonicalSchema>;

export const mutationFieldSchema = z.enum(["recipient", "amount", "network", "nonce", "expiry", "function", "contractId"]);
export type MutationField = z.infer<typeof mutationFieldSchema>;

export const mutationSchema = z.object({
  id: z.string(),
  field: mutationFieldSchema,
  description: z.string(),
  changedPaths: z.array(z.string()).min(1).describe("paths into `authorization` that differ from the original"),
  mutatedAuthorization: authorizationSchema,
  expected: z.object({
    payloadHashChanged: z.literal(true),
    mutatedPreimageXdr: base64,
    mutatedPayloadHashHex: hex(32),
    originalSignatureVerifies: z.literal(false),
    entryXdrWithOriginalSignature: base64.describe("mutated entry carrying the ORIGINAL signature and the mutated expiry"),
    hostExpectation: z.literal("reject").describe("a conforming host must refuse to authorize this entry"),
    resignedEntryXdr: base64.describe("positive control: the SAME mutated authorization freshly signed by the signer; a host must ACCEPT it, which shows the original-signature rejection is about the signature and not about a malformed call"),
    resignedSignatureHex: hex(64),
  }),
});
export type Mutation = z.infer<typeof mutationSchema>;

export const hostVerificationSchema = z.object({
  environment: z.enum(["native-testutils", "testnet-simulate-enforce"]),
  protocolVersion: z.number().int().optional(),
  evidence: z.string().describe("repo-relative path of the recorded output"),
  original: z.enum(["accepted"]),
  mutationsRejected: z.array(mutationFieldSchema),
});

export const compatibilitySchema = z.object({
  protocol: z.object({ min: z.number().int(), max: z.number().int().nullable() }).describe("inclusive protocol range in which this credential type is expected to be accepted; max null = no known upper bound"),
  status: z.enum(["current", "legacy-still-valid", "historical-unverified"]),
  note: z.string(),
  hostVerified: z.array(hostVerificationSchema),
});

export const vectorSchema = z.object({
  id: z.string().regex(/^[a-z0-9][a-z0-9-]*$/),
  title: z.string(),
  labels: z.array(z.string()),
  signer: signerSchema,
  authorization: authorizationSchema,
  expected: canonicalSchema,
  compatibility: compatibilitySchema,
  mutations: z.array(mutationSchema),
});
export type Vector = z.infer<typeof vectorSchema>;

export const vectorFileSchema = z.object({
  format: z.literal(VECTOR_FORMAT),
  formatVersion: z.string().regex(/^\d+\.\d+\.\d+$/),
  generator: z.object({ tool: z.string(), version: z.string(), sdk: z.string(), note: z.string() }),
  vectors: z.array(vectorSchema).min(1),
});
export type VectorFile = z.infer<typeof vectorFileSchema>;

/* ---------- RFC 8032 independent source ---------- */
export const rfc8032Schema = z.object({
  format: z.literal("authmatrix-rfc8032"),
  source: z.string(),
  vectors: z.array(
    z.object({ name: z.string(), secretKeyHex: hex(32), publicKeyHex: hex(32), messageHex: z.string().regex(/^([0-9a-f]{2})*$/), signatureHex: hex(64) }),
  ),
});
export type Rfc8032File = z.infer<typeof rfc8032Schema>;

/* ---------- Adapter protocol: newline-delimited JSON over stdio ---------- */
export const requestSchema = z.discriminatedUnion("op", [
  z.object({ protocol: z.literal(ADAPTER_PROTOCOL), id: z.number().int(), op: z.literal("describe") }),
  z.object({ protocol: z.literal(ADAPTER_PROTOCOL), id: z.number().int(), op: z.literal("derive_key"), params: z.object({ phrase: z.string() }) }),
  z.object({ protocol: z.literal(ADAPTER_PROTOCOL), id: z.number().int(), op: z.literal("build"), params: z.object({ authorization: authorizationSchema, phrase: z.string() }) }),
  z.object({ protocol: z.literal(ADAPTER_PROTOCOL), id: z.number().int(), op: z.literal("decode"), params: z.object({ entryXdr: base64 }) }),
  z.object({ protocol: z.literal(ADAPTER_PROTOCOL), id: z.number().int(), op: z.literal("verify"), params: z.object({ entryXdr: base64, networkPassphrase: z.string() }) }),
  z.object({ protocol: z.literal(ADAPTER_PROTOCOL), id: z.number().int(), op: z.literal("ed25519_sign"), params: z.object({ secretKeyHex: hex(32), messageHex: z.string().regex(/^([0-9a-f]{2})*$/) }) }),
]);
export type AdapterRequest = z.infer<typeof requestSchema>;

export const decodedInvocationSchema: z.ZodType<DecodedInvocation> = z.lazy(() =>
  z.union([
    z.object({ kind: z.literal("contractFn"), contractId: z.string(), functionName: z.string(), args: z.array(base64), subInvocations: z.array(decodedInvocationSchema) }),
    z.object({ kind: z.literal("createContract"), functionXdr: base64, subInvocations: z.array(decodedInvocationSchema) }),
  ]),
);
export type DecodedInvocation =
  | { kind: "contractFn"; contractId: string; functionName: string; args: string[]; subInvocations: DecodedInvocation[] }
  | { kind: "createContract"; functionXdr: string; subInvocations: DecodedInvocation[] };

export const decodedEntrySchema = z.object({
  credentialType: z.enum(["sourceAccount", "address", "addressV2", "addressWithDelegates"]),
  address: z.string().nullable(),
  nonce: int64String.nullable(),
  signatureExpirationLedger: z.number().int().nullable(),
  signature: z.object({
    kind: z.enum(["none", "ed25519", "raw"]),
    publicKeyHex: hex(32).optional(),
    signatureHex: hex(64).optional(),
    rawXdr: base64.describe("the signature ScVal as XDR base64"),
  }),
  delegateCount: z.number().int(),
  rootInvocation: decodedInvocationSchema,
});
export type DecodedEntry = z.infer<typeof decodedEntrySchema>;

export const verifyResultSchema = z.object({
  preimageType: preimageTypeSchema,
  preimageXdr: base64,
  payloadHashHex: hex(32),
  signatureValid: z.boolean(),
  reason: z.string().describe("why signatureValid is false, or 'ok'"),
});
export type VerifyResult = z.infer<typeof verifyResultSchema>;

export const describeResultSchema = z.object({
  adapter: z.string(),
  language: z.string(),
  xdrImplementation: z.string(),
  signingImplementation: z.string(),
  hashImplementation: z.string(),
  ops: z.array(z.string()),
});
export type DescribeResult = z.infer<typeof describeResultSchema>;

export const responseSchema = z.union([
  z.object({ protocol: z.literal(ADAPTER_PROTOCOL), id: z.number().int(), ok: z.literal(true), result: z.unknown() }),
  z.object({ protocol: z.literal(ADAPTER_PROTOCOL), id: z.number().int(), ok: z.literal(false), error: z.string() }),
]);
export type AdapterResponse = z.infer<typeof responseSchema>;

/* ---------- Host-verification evidence ---------- */
export const evidenceResultSchema = z.object({
  vectorId: z.string(),
  case: z.string().describe("original | <mutation field> | <mutation field>-resigned | control-no-auth | control-unsigned"),
  expectation: z.enum(["accept", "reject"]),
  outcome: z.enum(["accepted", "rejected"]),
  detail: z.string().describe("host return value or verbatim host error text"),
  note: z.string().optional(),
  raw: z.unknown().optional().describe("recorded raw RPC response (testnet evidence only)"),
});
export type EvidenceResult = z.infer<typeof evidenceResultSchema>;

export const evidenceFileSchema = z.object({
  format: z.literal(EVIDENCE_FORMAT),
  formatVersion: z.string().regex(/^\d+\.\d+\.\d+$/),
  kind: z.enum(["native-testutils", "testnet-simulate-enforce"]),
  recordedAt: z.string(),
  environment: z.record(z.string(), z.unknown()),
  limits: z.array(z.string()).describe("what this evidence does NOT establish"),
  results: z.array(evidenceResultSchema),
});
export type EvidenceFile = z.infer<typeof evidenceFileSchema>;

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { loadEvidence } from "../src/node.ts";
import { vectors } from "./helpers.ts";

const native = loadEvidence("evidence/native-host/results.json");
const testnet = loadEvidence("evidence/testnet/summary.json");
const hostVectors = vectors.vectors.filter((v) => v.labels.includes("host-verifiable"));

describe("recorded host evidence", () => {
  for (const [name, ev] of [["native-testutils", native], ["testnet-simulate-enforce", testnet]] as const) {
    describe(name, () => {
      it("every result matches its expectation (no contradictory evidence is committed)", () => {
        expect(ev.results.length).toBeGreaterThan(10);
        for (const r of ev.results) expect(r.outcome, `${r.vectorId}/${r.case}: ${r.detail}`).toBe(r.expectation === "accept" ? "accepted" : "rejected");
      });
      it("covers every host-verifiable vector: original accepted and every mutation field rejected", () => {
        for (const v of hostVectors) {
          const rs = ev.results.filter((r) => r.vectorId === v.id);
          expect(rs.find((r) => r.case === "original")?.outcome).toBe("accepted");
          for (const m of v.mutations) expect(rs.find((r) => r.case === m.field)?.outcome, `${v.id}/${m.field}`).toBe("rejected");
        }
      });
      it("every rejected mutation was refused by account authentication, not for another reason", () => {
        for (const r of ev.results.filter((x) => x.expectation === "reject" && !x.case.startsWith("control"))) {
          expect(r.detail).toMatch(/failed account authentication/);
        }
      });
      it("states what it does not establish", () => {
        expect(ev.limits.length).toBeGreaterThanOrEqual(3);
      });
    });
  }

  it("the testnet run recorded protocol 29 and enforce mode", () => {
    expect(testnet.environment["protocolVersion"]).toBe(29);
    expect(testnet.environment["authMode"]).toBe("enforce");
  });

  it("positive controls (re-signed mutated entries) were accepted on both hosts", () => {
    for (const ev of [native, testnet]) {
      const controls = ev.results.filter((r) => r.case.endsWith("-resigned"));
      expect(controls.length).toBeGreaterThanOrEqual(10);
      for (const c of controls) expect(c.outcome).toBe("accepted");
    }
  });

  it("vector compatibility.hostVerified reflects the committed evidence", () => {
    for (const v of hostVectors) {
      const envs = v.compatibility.hostVerified.map((h) => h.environment).sort();
      expect(envs).toEqual(["native-testutils", "testnet-simulate-enforce"]);
    }
    for (const v of vectors.vectors.filter((x) => !x.labels.includes("host-verifiable"))) expect(v.compatibility.hostVerified).toEqual([]);
  });

  it("the legacy historical vector is labelled and not claimed valid on any network", () => {
    const h = vectors.vectors.find((v) => v.id === "legacy-pubnet-historical-transfer")!;
    expect(h.compatibility.status).toBe("historical-unverified");
    expect(h.labels).toContain("not-host-verified");
  });

  it("deployed wasm hashes recorded for testnet match the committed artifacts", () => {
    const dep = JSON.parse(readFileSync("evidence/testnet/deployment.json", "utf8"));
    for (const a of Object.values(dep.artifacts) as { file: string; sha256: string }[]) {
      expect(createHash("sha256").update(readFileSync(a.file)).digest("hex")).toBe(a.sha256);
    }
  });
});

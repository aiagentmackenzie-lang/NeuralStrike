import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { parseReport } from "./report";

const fixture = (name: string) => readFileSync(resolve(__dirname, "__fixtures__", name), "utf8");

describe("parseReport", () => {
  it("reads a NeuralStrike JSON corpus report", () => {
    const report = parseReport(fixture("report.json"));
    expect(report.format).toBe("neuralstrike-json");
    expect(report.tool).toBe("NeuralStrike");
    expect(report.summary.total).toBe(3);
    expect(report.summary.succeeded).toBe(1);
    expect(report.summary.resisted).toBe(2);
    expect(report.summary.asr).toBeCloseTo(0.3333);
    expect(report.summary.coverage).toBe(1);
    expect(report.findings).toHaveLength(3);
    const breach = report.findings.find((f) => f.id === "asi01-002");
    expect(breach?.verdict).toBe("succeeded");
    expect(breach?.evidence).toContain("grant_admin_access");
  });

  it("reads a SARIF 2.1.0 report", () => {
    const report = parseReport(fixture("report.sarif"));
    expect(report.format).toBe("sarif");
    expect(report.tool).toBe("NeuralStrike");
    expect(report.version).toBe("1.0.0");
    expect(report.target).toBe("bundled-vulnerable-fixture");
    expect(report.summary.total).toBe(1);
    expect(report.summary.succeeded).toBe(1);
    expect(report.summary.asr).toBe(1);
    expect(report.findings[0].verdict).toBe("succeeded");
    expect(report.findings[0].mitreAtlas).toContain("AML.T0051.001");
  });

  it("returns unknown for unsupported JSON", () => {
    const report = parseReport(JSON.stringify({ foo: "bar" }));
    expect(report.format).toBe("unknown");
    expect(report.findings).toHaveLength(0);
  });
});

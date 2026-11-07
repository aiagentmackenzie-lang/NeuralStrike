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

describe("measurement integrity", () => {
  it("preserves unavailable ASR and incomplete health", () => {
    const report = parseReport(JSON.stringify({
      health: { status: "incomplete" },
      overall: { total: 1, succeeded: 0, resisted: 0, inconclusive: 1, asr: null, coverage: 0 },
      scenario_results: [{ id: "s", counts: { total: 1, inconclusive: 1 },
        trials: [{ verdict: "inconclusive", reason: "outage" }] }],
    }));
    expect(report.summary.asr).toBeNull();
    expect((report as any).health).toBe("incomplete");
  });

  it("uses the actual later violation's evidence", () => {
    const report = parseReport(JSON.stringify({
      overall: { total: 2, succeeded: 1, resisted: 1, inconclusive: 0, asr: .5, coverage: 1 },
      scenario_results: [{ id: "s", counts: { total: 2, succeeded: 1, resisted: 1 }, trials: [
        { trial_index: 0, verdict: "resisted", reason: "first benign", evidence_quote: "benign" },
        { trial_index: 1, verdict: "succeeded", reason: "later violation", evidence_quote: "actual breach" },
      ] }],
    }));
    expect(report.findings[0].reason).toBe("later violation");
    expect(report.findings[0].evidence).toBe("actual breach");
  });

  it("uses canonical SARIF counts rather than oracle rows", () => {
    const report = parseReport(JSON.stringify({ $schema: "sarif", version: "2.1.0", runs: [{
      invocations: [{ executionSuccessful: false, properties: {
        health: { status: "incomplete" }, overall: { total: 1, succeeded: 0, resisted: 0,
          inconclusive: 1, asr: null, coverage: 0 }, overall_asr: null, overall_coverage: 0,
      } }],
      results: [{ ruleId: "s", level: "none", message: { text: "oracle resisted" } },
                { ruleId: "s", level: "note", message: { text: "oracle inconclusive" } }],
    }] }));
    expect(report.summary.total).toBe(1);
    expect(report.summary.resisted).toBe(0);
    expect(report.summary.inconclusive).toBe(1);
    expect(report.summary.asr).toBeNull();
    expect((report as any).health).toBe("incomplete");
  });

  it("does not show an empty scenario as resisted", () => {
    const report = parseReport(JSON.stringify({ overall: { total: 0 },
      scenario_results: [{ id: "omitted", counts: { total: 0 }, trials: [] }] }));
    expect(report.findings[0].verdict).toBe("inconclusive");
    expect(report.summary.asr).toBeNull();
  });
});

for (const name of ["canonical-mixed.json", "canonical-mixed.sarif"]) {
  it(`round-trips the Python mixed-trial export ${name}`, () => {
    const report = parseReport(fixture(name));
    expect(report.summary.total).toBe(3);
    expect(report.summary.succeeded).toBe(1);
    expect(report.summary.resisted).toBe(1);
    expect(report.summary.inconclusive).toBe(1);
    expect(report.summary.asr).toBe(.5);
    expect(report.summary.coverage).toBeCloseTo(2 / 3);
    expect(report.health).toBe("incomplete");
    expect(report.countBasis).toBe("trials");
    expect(report.selectedTrials).toBe(3);
    expect(report.findings).toHaveLength(1);
    expect(report.findings[0].verdict).toBe("succeeded");
    expect(report.findings[0].evidence).toContain("actual violation");
  });
}

describe("invalid or unsupported reports", () => {
  it("rejects unknown canonical schema versions", () => {
    expect(() => parseReport(JSON.stringify({ schema_version: 999, overall: { total: 0 }, scenario_results: [] })))
      .toThrow(/schema/i);
  });
  it("rejects corrupt metric types", () => {
    expect(() => parseReport(JSON.stringify({ overall: { total: "1", resisted: 1 }, scenario_results: [] })))
      .toThrow(/count|metric/i);
  });
  it("treats an unrecognized SARIF verdict as inconclusive", () => {
    const report = parseReport(JSON.stringify({ $schema: "sarif", version: "2.1.0", runs: [{
      results: [{ ruleId: "s", level: "warning", properties: { verdict: "unknown" } }],
    }] }));
    expect(report.findings[0].verdict).toBe("inconclusive");
    expect(report.summary.asr).toBeNull();
  });
});

describe("evidence provenance", () => {
  it("keeps the selected later trial's links and explicit report limits", () => {
    const document = JSON.parse(fixture("report.json"));
    document.assessment_scope = { selected_scenarios: ["fixture"] };
    document.limitations = ["fixture receipts are not production effects"];
    document.scenario_results[0].counts = { total: 2, succeeded: 1, resisted: 1, inconclusive: 0 };
    document.scenario_results[0].source = { path: "corpus/fixture.yaml", scenario_fingerprint: "sha256:scenario" };
    document.scenario_results[0].trials = [
      { verdict: "resisted", evidence_id: "sha256:first" },
      { verdict: "succeeded", evidence_id: "sha256:actual", evidence_origin: "local-canary-fixture", receipt_id: "receipt-fixture" },
    ];
    const report = parseReport(JSON.stringify(document));
    expect(report.findings[0].evidenceId).toBe("sha256:actual");
    expect(report.findings[0].evidenceOrigin).toBe("local-canary-fixture");
    expect(report.findings[0].sourcePath).toBe("corpus/fixture.yaml");
    expect(report.scope).toEqual(document.assessment_scope);
    expect(report.limitations).toEqual(document.limitations);
  });
});

it.each(["phase1-mixed.json", "phase1-mixed.sarif"])("matches canonical mixed/error/unsupported counts in %s", (name) => {
  const report = parseReport(fixture(name));
  expect(report.summary).toEqual({ total: 4, succeeded: 1, resisted: 1, inconclusive: 2, asr: 0.5, coverage: 0.5 });
  expect(report.health).toBe("incomplete");
  expect(report.findings[0].evidence).toContain("actual violation");
  expect(report.findings[0].evidenceId).toMatch(/^sha256:/);
  expect(report.limitations.length).toBeGreaterThan(0);
  expect(report.scope?.planned_trials).toBe(4);
});

it.each(["phase1-mixed.json", "phase1-mixed.sarif"])("retains parent bundle identity and recorded gate in %s", (name) => {
  const report = parseReport(fixture(name));
  expect(report.assessmentId).toMatch(/^assessment-/);
  expect(report.planDigest).toMatch(/^[0-9a-f]{64}$/);
  expect(report.recordedGate).toEqual({ fail_on: "vuln", exit_code: 3 });
});

it("does not mistake a sharing summary for a replayable raw assessment", () => {
  const report = parseReport(JSON.stringify({ kind: "neuralstrike-share-summary", schema_version: 1,
    overall: { total: 1, succeeded: 0, resisted: 1, inconclusive: 0, coverage: 1, asr: 0 }, scenarios: [] }));
  expect(report.format).toBe("unknown");
  expect(report.health).toBe("unavailable");
});

it("shows selected SARIF scenarios without evidence while counting only recorded trials", () => {
  const document = JSON.parse(fixture("phase1-mixed.sarif"));
  const run = document.runs[0];
  run.tool.driver.rules.push({ id: "missing-selected", properties: {} });
  run.invocations[0].properties.assessment_scope.selected_scenarios.push("missing-selected");
  run.invocations[0].properties.health.selected = 8;
  const report = parseReport(JSON.stringify(document));
  expect(report.summary.total).toBe(4);
  expect(report.findings).toHaveLength(2);
  const missing = report.findings.find(row => row.id === "missing-selected");
  expect(missing?.verdict).toBe("inconclusive");
  expect(missing?.reason).toContain("no committed trial evidence");
  expect(report.health).toBe("incomplete");
});

export interface Summary {
  total: number;
  succeeded: number;
  resisted: number;
  inconclusive: number;
  asr: number;
  coverage: number;
}

export interface Finding {
  id: string;
  owaspCategory: string;
  owaspName: string;
  verdict: "succeeded" | "resisted" | "inconclusive";
  severity: string;
  reason: string;
  evidence?: string;
  mitreAtlas?: string[];
  deliveryVector?: string;
}

export interface Report {
  format: "neuralstrike-json" | "sarif" | "unknown";
  tool: string;
  version: string;
  target?: string;
  summary: Summary;
  findings: Finding[];
}

function emptySummary(): Summary {
  return { total: 0, succeeded: 0, resisted: 0, inconclusive: 0, asr: 0, coverage: 0 };
}

function parseNeuralStrikeJson(data: any): Report {
  const overall = data.overall || {};
  const findings: Finding[] = [];
  for (const scenario of data.scenario_results || []) {
    const counts = scenario.counts || {};
    const total = counts.total || 0;
    const succeeded = counts.succeeded || 0;
    const resisted = counts.resisted || 0;
    const inconclusive = counts.inconclusive || 0;
    // Surface one finding per scenario using the worst verdict.
    let verdict: Finding["verdict"] = "resisted";
    if (succeeded > 0) verdict = "succeeded";
    else if (inconclusive > 0) verdict = "inconclusive";

    const trial = (scenario.trials || [])[0] || {};
    findings.push({
      id: scenario.id,
      owaspCategory: scenario.owasp_category || "",
      owaspName: scenario.owasp_name || "",
      verdict,
      severity: scenario.severity || trial.severity || "info",
      reason: trial.reason || "",
      evidence: trial.evidence_quote || undefined,
      mitreAtlas: scenario.mitre_atlas || [],
      deliveryVector: scenario.delivery_vector || "",
    });

    // Pad summary if the run did not provide an overall block.
    if (!overall.total) {
      overall.total = (overall.total || 0) + total;
      overall.succeeded = (overall.succeeded || 0) + succeeded;
      overall.resisted = (overall.resisted || 0) + resisted;
      overall.inconclusive = (overall.inconclusive || 0) + inconclusive;
    }
  }
  const total = overall.total || findings.length;
  return {
    format: "neuralstrike-json",
    tool: "NeuralStrike",
    version: data.adapter ? "NeuralStrike" : "",
    target: data.target,
    summary: {
      total,
      succeeded: overall.succeeded || 0,
      resisted: overall.resisted || 0,
      inconclusive: overall.inconclusive || 0,
      asr: overall.asr ?? 0,
      coverage: overall.coverage ?? 0,
    },
    findings,
  };
}

function parseSarif(data: any): Report {
  const run = (data.runs || [])[0] || {};
  const driver = run.tool?.driver || {};
  const invocation = (run.invocations || [])[0] || {};
  const props = invocation.properties || {};
  const rulesById = new Map<string, any>();
  for (const rule of driver.rules || []) {
    rulesById.set(rule.id, rule);
  }

  const findings: Finding[] = [];
  for (const result of run.results || []) {
    const rule = rulesById.get(result.ruleId) || {};
    const level = result.level;
    let verdict: Finding["verdict"] = "resisted";
    if (level === "error") verdict = "succeeded";
    else if (level === "note") verdict = "inconclusive";

    findings.push({
      id: result.ruleId,
      owaspCategory: rule.properties?.owasp_category || "",
      owaspName: rule.properties?.owasp_name || rule.name || "",
      verdict,
      severity: rule.properties?.severity || "info",
      reason: result.message?.text || "",
      evidence: result.message?.text || undefined,
      mitreAtlas: rule.properties?.mitre_atlas || [],
      deliveryVector: rule.properties?.delivery_vector || "",
    });
  }

  const succeeded = findings.filter((f) => f.verdict === "succeeded").length;
  const inconclusive = findings.filter((f) => f.verdict === "inconclusive").length;
  const resisted = findings.filter((f) => f.verdict === "resisted").length;
  const total = findings.length;

  return {
    format: "sarif",
    tool: driver.name || "NeuralStrike",
    version: driver.version || "",
    target: props.target,
    summary: {
      total,
      succeeded,
      resisted,
      inconclusive,
      asr: props.overall_asr ?? (total ? succeeded / total : 0),
      coverage: props.overall_coverage ?? 0,
    },
    findings,
  };
}

export function parseReport(text: string): Report {
  let data: any;
  try {
    data = JSON.parse(text);
  } catch (err) {
    throw new Error(`Invalid JSON: ${err}`);
  }

  if (data.$schema && data.version === "2.1.0" && Array.isArray(data.runs)) {
    return parseSarif(data);
  }
  if (data.overall && Array.isArray(data.scenario_results)) {
    return parseNeuralStrikeJson(data);
  }

  return {
    format: "unknown",
    tool: "Unknown",
    version: "",
    summary: emptySummary(),
    findings: [],
  };
}

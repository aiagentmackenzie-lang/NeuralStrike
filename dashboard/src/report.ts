export interface Summary {
  total: number;
  succeeded: number;
  resisted: number;
  inconclusive: number;
  asr: number | null;
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
  health: "complete" | "incomplete" | "unavailable";
  countBasis: "trials" | "legacy rows";
  selectedTrials: number | null;
  summary: Summary;
  findings: Finding[];
}

function emptySummary(): Summary {
  return { total: 0, succeeded: 0, resisted: 0, inconclusive: 0, asr: null, coverage: 0 };
}

function summaryFrom(overall: any, fallback: Summary): Summary {
  const total = overall.total ?? fallback.total;
  const succeeded = overall.succeeded ?? fallback.succeeded;
  const resisted = overall.resisted ?? fallback.resisted;
  const inconclusive = overall.inconclusive ?? fallback.inconclusive;
  for (const value of [total, succeeded, resisted, inconclusive]) {
    if (!Number.isSafeInteger(value) || value < 0) throw new Error("Invalid report count");
  }
  if (total !== succeeded + resisted + inconclusive) throw new Error("Inconsistent report counts");
  for (const value of [overall.asr, overall.coverage]) {
    if (value != null && (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 1)) {
      throw new Error("Invalid report metric");
    }
  }
  const conclusive = succeeded + resisted;
  return {
    total, succeeded, resisted, inconclusive,
    // Older reports used 0 when the denominator was empty. Do not preserve that fiction.
    asr: !conclusive || overall.asr === null ? null : overall.asr ?? succeeded / conclusive,
    coverage: overall.coverage ?? (total ? conclusive / total : 0),
  };
}

function healthFrom(raw: any, summary: Summary, executionSuccessful?: boolean): Report["health"] {
  if (executionSuccessful === false || raw?.status === "incomplete" || raw?.errors > 0) return "incomplete";
  if (raw?.status !== "complete") return "unavailable";
  return summary.total > 0 && summary.coverage === 1 && summary.inconclusive === 0 ? "complete" : "incomplete";
}

function worst(verdicts: Finding["verdict"][]): Finding["verdict"] {
  if (verdicts.includes("succeeded")) return "succeeded";
  if (!verdicts.length || verdicts.includes("inconclusive")) return "inconclusive";
  return "resisted";
}

function parseNeuralStrikeJson(data: any): Report {
  if (data.schema_version !== undefined && data.schema_version !== 2) {
    throw new Error("Unsupported NeuralStrike report schema");
  }
  const fallback = emptySummary();
  const findings: Finding[] = [];
  for (const scenario of data.scenario_results || []) {
    const counts = scenario.counts || {};
    const total = counts.total || 0;
    const succeeded = counts.succeeded || 0;
    const resisted = counts.resisted || 0;
    const inconclusive = counts.inconclusive || 0;
    const verdict: Finding["verdict"] = succeeded ? "succeeded" :
      inconclusive || !total ? "inconclusive" : "resisted";
    const trials = scenario.trials || [];
    // Legacy single-trial fixtures did not contain a verdict; permit that one
    // unambiguous case. Otherwise the evidence must match the displayed verdict.
    const trial = trials.find((t: any) => !t.advisory && t.verdict === verdict) ||
      (trials.length === 1 && !trials[0].verdict ? trials[0] : {});
    findings.push({
      id: scenario.id,
      owaspCategory: scenario.owasp_category || "",
      owaspName: scenario.owasp_name || "",
      verdict,
      severity: trial.severity || scenario.severity || "info",
      reason: trial.reason || "No matching trial evidence available",
      evidence: trial.evidence_quote || undefined,
      mitreAtlas: scenario.mitre_atlas || [],
      deliveryVector: scenario.delivery_vector || "",
    });
    fallback.total += total;
    fallback.succeeded += succeeded;
    fallback.resisted += resisted;
    fallback.inconclusive += inconclusive;
  }
  const summary = summaryFrom(data.overall || {}, fallback);
  return {
    format: "neuralstrike-json", tool: "NeuralStrike", version: data.tool_version || "",
    target: data.target, health: healthFrom(data.health, summary), countBasis: "trials",
    selectedTrials: Number.isSafeInteger(data.health?.selected) ? data.health.selected : null, summary, findings,
  };
}

function parseSarif(data: any): Report {
  const run = (data.runs || [])[0] || {};
  const driver = run.tool?.driver || {};
  const invocation = (run.invocations || [])[0] || {};
  const props = invocation.properties || {};
  if (props.report_schema_version !== undefined && props.report_schema_version !== 2) {
    throw new Error("Unsupported NeuralStrike report schema");
  }
  const rulesById = new Map<string, any>();
  for (const rule of driver.rules || []) rulesById.set(rule.id, rule);

  const groups = new Map<string, any[]>();
  const trialVerdicts = new Map<string, Finding["verdict"][]>();
  let legacyRows = false;
  for (const [index, result] of (run.results || []).entries()) {
    const declared = result.properties?.verdict;
    const known = ["succeeded", "resisted", "inconclusive"].includes(declared);
    const verdict: Finding["verdict"] = declared !== undefined ? (known ? declared : "inconclusive") :
      result.level === "error" ? "succeeded" : result.level === "none" ? "resisted" : "inconclusive";
    const rows = groups.get(result.ruleId) || [];
    rows.push({ result, verdict });
    groups.set(result.ruleId, rows);
    const trialIndex = result.properties?.trial_index;
    if (trialIndex === undefined) legacyRows = true;
    const key = `${result.ruleId}:${trialIndex ?? `row-${index}`}`;
    const verdicts = trialVerdicts.get(key) || [];
    if (!result.properties?.advisory) verdicts.push(verdict);
    trialVerdicts.set(key, verdicts);
  }
  const findings: Finding[] = [];
  for (const [id, rows] of groups) {
    const verdict = worst(rows.filter(r => !r.result.properties?.advisory).map(r => r.verdict));
    const row = rows.find(r => !r.result.properties?.advisory && r.verdict === verdict);
    const rule = rulesById.get(id) || {};
    findings.push({
      id, verdict, owaspCategory: rule.properties?.owasp_category || "",
      owaspName: rule.properties?.owasp_name || rule.name || "",
      severity: row?.result.properties?.severity || rule.properties?.severity || "info",
      reason: row?.result.message?.text || "No matching trial evidence available",
      evidence: row?.result.message?.text || undefined,
      mitreAtlas: rule.properties?.mitre_atlas || [], deliveryVector: rule.properties?.delivery_vector || "",
    });
  }
  const fallback = emptySummary();
  for (const verdicts of trialVerdicts.values()) {
    fallback.total++;
    fallback[worst(verdicts)]++;
  }
  const overall = props.overall || { asr: props.overall_asr, coverage: props.overall_coverage };
  const summary = summaryFrom(overall, fallback);
  return {
    format: "sarif", tool: driver.name || "NeuralStrike", version: driver.version || "",
    target: props.target, health: healthFrom(props.health, summary, invocation.executionSuccessful),
    countBasis: props.overall || !legacyRows ? "trials" : "legacy rows",
    selectedTrials: Number.isSafeInteger(props.health?.selected) ? props.health.selected : null, summary, findings,
  };
}

export function parseReport(text: string): Report {
  let data: any;
  try {
    data = JSON.parse(text);
  } catch (err) {
    throw new Error(`Invalid JSON: ${err}`);
  }
  if (data?.$schema && data.version === "2.1.0" && Array.isArray(data.runs)) return parseSarif(data);
  if (data?.overall && Array.isArray(data.scenario_results)) return parseNeuralStrikeJson(data);
  return { format: "unknown", tool: "Unknown", version: "", health: "unavailable",
    countBasis: "legacy rows", selectedTrials: null, summary: emptySummary(), findings: [] };
}

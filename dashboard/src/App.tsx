import { useMemo, useState } from "react";
import type { Finding, Report } from "./report";
import { parseReport } from "./report";

function Badge({ verdict }: { verdict: Finding["verdict"] }) {
  const colors: Record<Finding["verdict"], string> = {
    succeeded: "#dc2626",
    inconclusive: "#f59e0b",
    resisted: "#16a34a",
  };
  return (
    <span
      style={{
        background: colors[verdict],
        color: "white",
        padding: "2px 8px",
        borderRadius: "999px",
        fontSize: "0.75rem",
        fontWeight: 600,
        textTransform: "uppercase",
      }}
    >
      {verdict}
    </span>
  );
}

export default function App() {
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<Finding["verdict"] | "all">("all");

  const onFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      const parsed = parseReport(text);
      setReport(parsed);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setReport(null);
    }
  };

  const filtered = useMemo(() => {
    if (!report) return [];
    if (filter === "all") return report.findings;
    return report.findings.filter((f) => f.verdict === filter);
  }, [report, filter]);

  return (
    <div style={{ fontFamily: "system-ui, sans-serif", maxWidth: 960, margin: "0 auto", padding: 24 }}>
      <h1>NeuralStrike Results Viewer</h1>
      <p>Open a NeuralStrike JSON report or SARIF 2.1.0 file.</p>
      <input type="file" accept=".json,.sarif" onChange={onFile} />
      {error && <p style={{ color: "#dc2626" }}>{error}</p>}

      {report && (
        <div style={{ marginTop: 24 }}>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(120px, 1fr))",
              gap: 12,
              marginBottom: 24,
            }}
          >
            {[
              { label: "Format", value: report.format },
              { label: "Tool", value: report.tool },
              { label: "Version", value: report.version },
              { label: "Target", value: report.target || "—" },
              { label: "Total", value: report.summary.total },
              { label: "ASR", value: `${(report.summary.asr * 100).toFixed(1)}%` },
              { label: "Coverage", value: `${(report.summary.coverage * 100).toFixed(1)}%` },
              { label: "Succeeded", value: report.summary.succeeded },
              { label: "Resisted", value: report.summary.resisted },
              { label: "Inconclusive", value: report.summary.inconclusive },
            ].map(({ label, value }) => (
              <div key={label} style={{ border: "1px solid #e5e7eb", borderRadius: 8, padding: 12 }}>
                <div style={{ fontSize: "0.75rem", color: "#6b7280" }}>{label}</div>
                <div style={{ fontSize: "1.25rem", fontWeight: 700 }}>{value}</div>
              </div>
            ))}
          </div>

          <div style={{ marginBottom: 12 }}>
            <label style={{ marginRight: 8 }}>Filter:</label>
            <select value={filter} onChange={(e) => setFilter(e.target.value as any)}>
              <option value="all">All</option>
              <option value="succeeded">Succeeded</option>
              <option value="inconclusive">Inconclusive</option>
              <option value="resisted">Resisted</option>
            </select>
          </div>

          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.9rem" }}>
            <thead>
              <tr style={{ background: "#f3f4f6" }}>
                <th style={{ textAlign: "left", padding: 8 }}>ID</th>
                <th style={{ textAlign: "left", padding: 8 }}>OWASP</th>
                <th style={{ textAlign: "left", padding: 8 }}>Severity</th>
                <th style={{ textAlign: "left", padding: 8 }}>Verdict</th>
                <th style={{ textAlign: "left", padding: 8 }}>Reason</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((f) => (
                <tr key={f.id} style={{ borderBottom: "1px solid #e5e7eb" }}>
                  <td style={{ padding: 8 }}>{f.id}</td>
                  <td style={{ padding: 8 }}>{f.owaspCategory} — {f.owaspName}</td>
                  <td style={{ padding: 8 }}>{f.severity}</td>
                  <td style={{ padding: 8 }}><Badge verdict={f.verdict} /></td>
                  <td style={{ padding: 8, maxWidth: 400, wordBreak: "break-word" }}>{f.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

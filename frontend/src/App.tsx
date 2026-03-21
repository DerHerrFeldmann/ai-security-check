import { useState } from "react";
import ReactMarkdown from "react-markdown";

const API = "http://localhost:8080";

interface Finding {
  tool: string;
  file: string;
  line: number;
  severity: string;
  message: string;
  rule: string;
  possible_false_positive: boolean;
  fp_reason?: string;
}

interface ScanResult {
  files_scanned: number;
  deprecated_functions: string[];
  security_flags: string[];
  external_calls: number;
  direct_db_access: boolean;
  min_php_version: string;
  missing_i18n_samples: string[];
  semgrep_findings: Finding[];
  phpcs_findings: Finding[];
}

interface Report {
  slug: string;
  score: number;
  scan: ScanResult;
  summary?: string;
  summaryLoading?: boolean;
}

const ruleExplanations: Record<string, { label: string; explanation: string }> = {
  "echoed-request":           { label: "XSS – Unsanitized Output",       explanation: "User input (e.g. $_GET, $_POST) is printed directly to the page without escaping. An attacker can inject malicious HTML or JavaScript." },
  "tainted-sql-string":       { label: "SQL Injection",                   explanation: "User input flows into a SQL query without proper sanitization. An attacker could read, modify or delete database content." },
  "tainted-filename":         { label: "Path Traversal",                  explanation: "User input is used as a file path. An attacker could read arbitrary files on the server (e.g. ../../wp-config.php)." },
  "curl-ssl-verifypeer-off":  { label: "SSL Verification Disabled",       explanation: "SSL certificate verification is turned off. The plugin can be tricked into connecting to a fake server (man-in-the-middle attack)." },
  "tainted-code-exec":        { label: "Code Execution",                  explanation: "User input is passed to a code execution function like eval(). An attacker could run arbitrary PHP code on the server." },
  "tainted-shell-exec":       { label: "Shell Injection",                 explanation: "User input is passed to a shell command. An attacker could execute arbitrary system commands on the server." },
  "file-inclusion":           { label: "File Inclusion",                  explanation: "User input controls which file is included. An attacker could load malicious files from a remote server." },
  "deserialize-user-input":   { label: "Unsafe Deserialization",          explanation: "User-supplied data is deserialized without validation. This can lead to remote code execution." },
  "hardcoded-secret":         { label: "Hardcoded Secret",                explanation: "A password, API key or token appears to be hardcoded in the source code." },
};

function getRuleInfo(ruleId: string) {
  const key = Object.keys(ruleExplanations).find(k => ruleId.includes(k));
  return key ? ruleExplanations[key] : { label: ruleId.split(".").pop() ?? ruleId, explanation: "" };
}

const scoreColor = (s: number) => s >= 70 ? "#22c55e" : s >= 40 ? "#f59e0b" : "#ef4444";
const scoreBg    = (s: number) => s >= 70 ? "#14532d" : s >= 40 ? "#78350f" : "#7f1d1d";
const scoreLabel = (s: number) => s >= 70 ? "Good"    : s >= 40 ? "Review"  : "Critical";

function Pill({ label, color }: { label: string; color: string }) {
  return (
    <span style={{
      background: color + "20", color, border: `1px solid ${color}40`,
      borderRadius: 20, padding: "3px 12px", fontSize: 13, display: "inline-block",
      margin: "3px 4px 3px 0",
    }}>{label}</span>
  );
}

function StatCard({ label, value, warn }: { label: string; value: string | number; warn?: boolean }) {
  return (
    <div style={{ background: "#0f172a", borderRadius: 12, padding: "16px 20px" }}>
      <div style={{ color: "#64748b", fontSize: 12, marginBottom: 4 }}>{label}</div>
      <div style={{ fontWeight: 700, fontSize: 22, color: warn ? "#f59e0b" : "#f1f5f9" }}>{value}</div>
    </div>
  );
}

function Spinner() {
  return (
    <span style={{
      display: "inline-block", width: 14, height: 14, border: "2px solid #334155",
      borderTop: "2px solid #3b82f6", borderRadius: "50%",
      animation: "spin 0.8s linear infinite", marginRight: 8, verticalAlign: "middle",
    }} />
  );
}

function FindingsTable({ findings, color }: { findings: Finding[]; color: string }) {
  if (findings.length === 0) return <span style={{ color: "#22c55e", fontSize: 14 }}>✓ None found</span>;
  return (
    <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
      <thead>
        <tr style={{ color: "#64748b", textAlign: "left" }}>
          <th style={{ padding: "4px 8px 8px 0", fontWeight: 500 }}>File</th>
          <th style={{ padding: "4px 8px 8px 0", fontWeight: 500, width: 50 }}>Line</th>
          <th style={{ padding: "4px 0 8px 0", fontWeight: 500 }}>Rule</th>
        </tr>
      </thead>
      <tbody>
        {findings.map((f, i) => {
          const info = getRuleInfo(f.rule);
          const fp = f.possible_false_positive;
          return (
            <tr key={i} style={{ borderTop: "1px solid #0f172a", opacity: fp ? 0.6 : 1 }}>
              <td style={{ padding: "8px 8px 8px 0", color: "#94a3b8", fontFamily: "monospace", fontSize: 12, verticalAlign: "top" }}>
                {f.file}
              </td>
              <td style={{ padding: "8px 8px 8px 0", color: "#64748b", fontSize: 12, verticalAlign: "top" }}>{f.line}</td>
              <td style={{ padding: "8px 0", verticalAlign: "top" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{ color: fp ? "#64748b" : color, fontWeight: 600, fontSize: 13 }}>{info.label}</span>
                  {fp && (
                    <span style={{ background: "#1e3a2f", color: "#4ade80", border: "1px solid #16653a", borderRadius: 4, fontSize: 11, padding: "1px 7px" }}>
                      likely false positive
                    </span>
                  )}
                </div>
                {fp && f.fp_reason && (
                  <div style={{ color: "#4ade80", fontSize: 11, marginTop: 2 }}>↳ {f.fp_reason}</div>
                )}
                {!fp && info.explanation && (
                  <div style={{ color: "#94a3b8", fontSize: 12, marginTop: 3, lineHeight: 1.5 }}>{info.explanation}</div>
                )}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

function Collapsible({ title, count, color, children }: { title: string; count: number; color: string; children: React.ReactNode }) {
  const [open, setOpen] = useState(count > 0 && count <= 20);
  return (
    <div style={{ background: "#1e293b", borderRadius: 16, overflow: "hidden" }}>
      <button onClick={() => setOpen(o => !o)} style={{
        width: "100%", display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: 24, background: "none", border: "none", outline: "none", cursor: "pointer", color: "#f1f5f9",
      }}>
        <div style={{ fontSize: 13, fontWeight: 600, color, textTransform: "uppercase", letterSpacing: 1 }}>
          {title} — <span style={{ color: count === 0 ? "#22c55e" : color }}>{count} findings</span>
        </div>
        <span style={{ color: "#64748b", fontSize: 18, transform: open ? "rotate(180deg)" : "none", transition: "transform 0.2s" }}>▾</span>
      </button>
      {open && <div style={{ padding: "0 24px 24px" }}>{children}</div>}
    </div>
  );
}

const mdComponents = {
  h2: ({ children }: { children?: React.ReactNode }) => (
    <h2 style={{ fontSize: 15, fontWeight: 700, color: "#f1f5f9", margin: "20px 0 6px" }}>{children}</h2>
  ),
  h3: ({ children }: { children?: React.ReactNode }) => (
    <h3 style={{ fontSize: 14, fontWeight: 600, color: "#e2e8f0", margin: "14px 0 4px" }}>{children}</h3>
  ),
  p: ({ children }: { children?: React.ReactNode }) => (
    <p style={{ color: "#cbd5e1", fontSize: 14, lineHeight: 1.75, margin: "4px 0 10px" }}>{children}</p>
  ),
  ul: ({ children }: { children?: React.ReactNode }) => (
    <ul style={{ paddingLeft: 20, margin: "4px 0 10px" }}>{children}</ul>
  ),
  ol: ({ children }: { children?: React.ReactNode }) => (
    <ol style={{ paddingLeft: 20, margin: "4px 0 10px" }}>{children}</ol>
  ),
  li: ({ children }: { children?: React.ReactNode }) => (
    <li style={{ color: "#cbd5e1", fontSize: 14, lineHeight: 1.75, marginBottom: 2 }}>{children}</li>
  ),
  strong: ({ children }: { children?: React.ReactNode }) => (
    <strong style={{ color: "#f1f5f9", fontWeight: 700 }}>{children}</strong>
  ),
  code: ({ children }: { children?: React.ReactNode }) => (
    <code style={{ background: "#0f172a", color: "#7dd3fc", borderRadius: 4, padding: "1px 6px", fontSize: 13, fontFamily: "monospace" }}>{children}</code>
  ),
};

function AISummary({ loading, summary }: { loading: boolean; summary?: string }) {
  const [open, setOpen] = useState(true);
  return (
    <div style={{ background: "#1e293b", borderRadius: 16, overflow: "hidden" }}>
      <button onClick={() => setOpen(o => !o)} style={{
        width: "100%", display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: 24, background: "none", border: "none", outline: "none", cursor: "pointer", color: "#f1f5f9",
      }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: "#3b82f6", textTransform: "uppercase", letterSpacing: 1 }}>
          AI Assessment
        </div>
        {loading
          ? <div style={{ color: "#64748b", fontSize: 14 }}><Spinner />Generating…</div>
          : <span style={{ color: "#64748b", fontSize: 18, transform: open ? "rotate(180deg)" : "none", transition: "transform 0.2s" }}>▾</span>
        }
      </button>
      {open && !loading && summary && (
        <div style={{ padding: "0 24px 24px" }}>
          <ReactMarkdown components={mdComponents as never}>{summary}</ReactMarkdown>
        </div>
      )}
    </div>
  );
}

export default function App() {
  const [slug, setSlug]       = useState("wapuugotchi");
  const [loading, setLoading] = useState(false);
  const [report, setReport]   = useState<Report | null>(null);
  const [error, setError]     = useState("");

  async function analyze() {
    if (!slug.trim()) return;
    setLoading(true);
    setReport(null);
    setError("");

    try {
      const res = await fetch(`${API}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ slug: slug.trim().toLowerCase() }),
      });
      const data = await res.json();
      if (data.error) { setError(data.error); return; }

      setReport({ ...data, summaryLoading: true });
      setLoading(false);

      const aiRes = await fetch(`${API}/api/summarize`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ slug: data.slug, score: data.score, scan: data.scan }),
      });
      const aiData = await aiRes.json();
      setReport(prev => prev ? { ...prev, summary: aiData.summary, summaryLoading: false } : prev);

    } catch {
      setError("Could not reach the API. Is the Go server running on :8080?");
    } finally {
      setLoading(false);
    }
  }

  const s = report?.scan;

  return (
    <>
      <style>{`
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { background: #0f172a; color: #f1f5f9; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; }
        @keyframes spin { to { transform: rotate(360deg); } }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: none; } }
        .fade { animation: fadeIn 0.3s ease; }
      `}</style>

      <div style={{ maxWidth: 1100, margin: "0 auto", padding: "48px 32px" }}>

        <div style={{ marginBottom: 40 }}>
          <h1 style={{ fontSize: 32, fontWeight: 800, letterSpacing: -1 }}>WP Plugin Insight</h1>
          <p style={{ color: "#64748b", marginTop: 6, fontSize: 15 }}>AI-powered quality &amp; security analysis for WordPress plugins.</p>
        </div>

        <div style={{ display: "flex", gap: 12, marginBottom: 40, maxWidth: 600 }}>
          <input
            value={slug}
            onChange={e => setSlug(e.target.value)}
            onKeyDown={e => e.key === "Enter" && analyze()}
            placeholder="Plugin slug, e.g. woocommerce"
            style={{ flex: 1, padding: "14px 18px", borderRadius: 12, border: "1px solid #1e293b", background: "#1e293b", color: "#f1f5f9", fontSize: 15, outline: "none" }}
          />
          <button onClick={analyze} disabled={loading} style={{
            padding: "14px 28px", borderRadius: 12, border: "none",
            background: loading ? "#1e293b" : "#3b82f6", color: loading ? "#475569" : "white",
            fontWeight: 600, fontSize: 15, cursor: loading ? "not-allowed" : "pointer", minWidth: 120,
          }}>
            {loading ? <><Spinner />Scanning…</> : "Analyze"}
          </button>
        </div>

        {error && (
          <div className="fade" style={{ background: "#450a0a", border: "1px solid #7f1d1d", borderRadius: 12, padding: "14px 18px", color: "#fca5a5", marginBottom: 24 }}>
            {error}
          </div>
        )}

        {report && s && (
          <div className="fade" style={{ display: "flex", flexDirection: "column", gap: 16 }}>

            {/* Score + Meta + AI */}
            <div style={{ display: "grid", gridTemplateColumns: "180px 1fr", gap: 16 }}>
              <div style={{ background: scoreBg(report.score), border: `1px solid ${scoreColor(report.score)}40`, borderRadius: 16, padding: 24, textAlign: "center" }}>
                <div style={{ color: scoreColor(report.score), fontSize: 64, fontWeight: 800, lineHeight: 1 }}>{report.score}</div>
                <div style={{ color: scoreColor(report.score), fontSize: 13, marginTop: 6, fontWeight: 600 }}>{scoreLabel(report.score)}</div>
                <div style={{ color: "#64748b", fontSize: 12, marginTop: 4 }}>out of 100</div>
              </div>
              <div style={{ background: "#1e293b", borderRadius: 16, padding: 24 }}>
                <div style={{ fontSize: 20, fontWeight: 700, marginBottom: 4 }}>{report.slug}</div>
                <div style={{ color: "#64748b", fontSize: 13 }}>{s.files_scanned} PHP files · min PHP {s.min_php_version}</div>
              </div>
            </div>

            {/* AI Summary */}
            <AISummary loading={!!report.summaryLoading} summary={report.summary} />

            {/* Stats */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12 }}>
              <StatCard label="Files scanned"       value={s.files_scanned} />
              <StatCard label="External HTTP calls" value={s.external_calls} warn={s.external_calls > 3} />
              <StatCard label="Direct DB access"    value={s.direct_db_access ? "Yes" : "No"} warn={s.direct_db_access} />
              <StatCard label="Missing i18n"        value={s.missing_i18n_samples.length} warn={s.missing_i18n_samples.length > 0} />
            </div>

            {/* Security flags + Deprecated */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
              <div style={{ background: "#1e293b", borderRadius: 16, padding: 24 }}>
                <div style={{ fontSize: 13, fontWeight: 600, color: "#ef4444", textTransform: "uppercase", letterSpacing: 1, marginBottom: 12 }}>Security Flags</div>
                {s.security_flags.length === 0
                  ? <span style={{ color: "#22c55e", fontSize: 14 }}>✓ None found</span>
                  : s.security_flags.map(f => <Pill key={f} label={f} color="#ef4444" />)
                }
              </div>
              <div style={{ background: "#1e293b", borderRadius: 16, padding: 24 }}>
                <div style={{ fontSize: 13, fontWeight: 600, color: "#f59e0b", textTransform: "uppercase", letterSpacing: 1, marginBottom: 12 }}>Deprecated Functions</div>
                {s.deprecated_functions.length === 0
                  ? <span style={{ color: "#22c55e", fontSize: 14 }}>✓ None found</span>
                  : s.deprecated_functions.map(f => <Pill key={f} label={f} color="#f59e0b" />)
                }
              </div>
            </div>

            {/* Semgrep findings */}
            <Collapsible title="Semgrep" count={s.semgrep_findings?.length ?? 0} color="#ef4444">
              <FindingsTable findings={s.semgrep_findings ?? []} color="#ef4444" />
            </Collapsible>

            {/* PHPCS findings */}
            <Collapsible title="PHPCS" count={s.phpcs_findings?.length ?? 0} color="#f59e0b">
              <FindingsTable findings={s.phpcs_findings ?? []} color="#f59e0b" />
            </Collapsible>

          </div>
        )}
      </div>
    </>
  );
}

import { useState } from "react";
import ReactMarkdown from "react-markdown";

const GH_OWNER = "DerHerrFeldmann";
const GH_REPO  = "ai-security-check";
const GH_TOKEN = import.meta.env.VITE_GH_TOKEN || "";

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

interface CVEFinding {
  uuid: string;
  title: string;
  cvss_score: number;
  cvss_severity?: string;
  fixed_in?: string;
  unfixed: boolean;
  references?: string[];
}

interface DepVuln {
  package: string;
  version: string;
  id: string;
  cve?: string;
  summary: string;
  severity: string;
  fixed_in?: string[];
}

interface ScanResult {
  version?: string;
  files_scanned: number;
  js_files_scanned: number;
  deprecated_functions: string[];
  security_flags: string[];
  external_calls: number;
  direct_db_access: boolean;
  min_php_version: string;
  missing_i18n_samples: string[];
  semgrep_findings: Finding[];
  phpcs_findings: Finding[];
  cve_findings: CVEFinding[];
  dep_vulns: DepVuln[];
}

interface Report {
  slug: string;
  score: number;
  scan: ScanResult;
  summary?: string;
}

type AnalysisStatus = "idle" | "queued" | "running" | "done" | "error";

const ruleExplanations: Record<string, { label: string; explanation: string }> = {
  "echoed-request":          { label: "XSS – Unsanitized Output",    explanation: "User input (e.g. $_GET, $_POST) is printed directly to the page without escaping. An attacker can inject malicious HTML or JavaScript." },
  "tainted-sql-string":      { label: "SQL Injection",               explanation: "User input flows into a SQL query without proper sanitization. An attacker could read, modify or delete database content." },
  "tainted-filename":        { label: "Path Traversal",              explanation: "User input is used as a file path. An attacker could read arbitrary files on the server (e.g. ../../wp-config.php)." },
  "curl-ssl-verifypeer-off": { label: "SSL Verification Disabled",   explanation: "SSL certificate verification is turned off. The plugin can be tricked into connecting to a fake server (man-in-the-middle attack)." },
  "tainted-code-exec":       { label: "Code Execution",              explanation: "User input is passed to a code execution function like eval(). An attacker could run arbitrary PHP code on the server." },
  "tainted-shell-exec":      { label: "Shell Injection",             explanation: "User input is passed to a shell command. An attacker could execute arbitrary system commands on the server." },
  "file-inclusion":          { label: "File Inclusion",              explanation: "User input controls which file is included. An attacker could load malicious files from a remote server." },
  "deserialize-user-input":  { label: "Unsafe Deserialization",      explanation: "User-supplied data is deserialized without validation. This can lead to remote code execution." },
  "hardcoded-secret":        { label: "Hardcoded Secret",            explanation: "A password, API key or token appears to be hardcoded in the source code." },
};

function getRuleInfo(ruleId: string) {
  const key = Object.keys(ruleExplanations).find(k => ruleId.includes(k));
  return key ? ruleExplanations[key] : { label: ruleId.split(".").pop() ?? ruleId, explanation: "" };
}

const scoreGrade = (s: number) => s >= 80 ? "A" : s >= 65 ? "B" : s >= 50 ? "C" : s >= 35 ? "D" : "F";
const scoreColor = (s: number) => s >= 80 ? "#16a34a" : s >= 65 ? "#65a30d" : s >= 50 ? "#d97706" : s >= 35 ? "#ea580c" : "#dc2626";
const scoreBg    = (s: number) => s >= 80 ? "#f0fdf4" : s >= 65 ? "#f7fee7" : s >= 50 ? "#fffbeb" : s >= 35 ? "#fff7ed" : "#fef2f2";
const scoreDark  = (s: number) => s >= 80 ? "#14532d" : s >= 65 ? "#365314" : s >= 50 ? "#78350f" : s >= 35 ? "#7c2d12" : "#7f1d1d";
const scoreLabel = (s: number) => s >= 80 ? "Excellent" : s >= 65 ? "Good" : s >= 50 ? "Fair" : s >= 35 ? "Poor" : "Critical";

function Pill({ label, color }: { label: string; color: string }) {
  return (
    <span style={{
      background: color + "18", color, border: `1px solid ${color}30`,
      borderRadius: 20, padding: "3px 12px", fontSize: 13, display: "inline-block",
      margin: "3px 4px 3px 0",
    }}>{label}</span>
  );
}

function StatCard({ label, value, warn }: { label: string; value: string | number; warn?: boolean }) {
  return (
    <div className="card-deep" style={{ borderRadius: 12, padding: "16px 20px" }}>
      <div className="text-muted" style={{ fontSize: 12, marginBottom: 4 }}>{label}</div>
      <div style={{ fontWeight: 700, fontSize: 22, color: warn ? "#d97706" : undefined }}>{value}</div>
    </div>
  );
}

function Spinner({ size = 14 }: { size?: number }) {
  return (
    <span style={{
      display: "inline-block", width: size, height: size,
      border: "2px solid var(--border)", borderTop: "2px solid #3b82f6",
      borderRadius: "50%", animation: "spin 0.8s linear infinite",
      marginRight: 8, verticalAlign: "middle", flexShrink: 0,
    }} />
  );
}

function FindingsTable({ findings, color }: { findings: Finding[]; color: string }) {
  if (findings.length === 0) return <span style={{ color: "#16a34a", fontSize: 14 }}>✓ None found</span>;
  return (
    <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
      <thead>
        <tr className="text-muted" style={{ textAlign: "left" }}>
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
            <tr key={i} style={{ borderTop: "1px solid var(--border)", opacity: fp ? 0.6 : 1 }}>
              <td className="text-faint" style={{ padding: "8px 8px 8px 0", fontFamily: "monospace", fontSize: 12, verticalAlign: "top" }}>
                {f.file}
              </td>
              <td className="text-muted" style={{ padding: "8px 8px 8px 0", fontSize: 12, verticalAlign: "top" }}>{f.line}</td>
              <td style={{ padding: "8px 0", verticalAlign: "top" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{ color: fp ? "var(--text-muted)" : color, fontWeight: 600, fontSize: 13 }}>{info.label}</span>
                  {fp && (
                    <span style={{ background: "#f0fdf4", color: "#15803d", border: "1px solid #bbf7d0", borderRadius: 4, fontSize: 11, padding: "1px 7px" }}>
                      likely false positive
                    </span>
                  )}
                </div>
                {fp && f.fp_reason && (
                  <div style={{ color: "#16a34a", fontSize: 11, marginTop: 2 }}>↳ {f.fp_reason}</div>
                )}
                {!fp && info.explanation && (
                  <div className="text-faint" style={{ fontSize: 12, marginTop: 3, lineHeight: 1.5 }}>{info.explanation}</div>
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
    <div className="card" style={{ borderRadius: 16, overflow: "hidden" }}>
      <button onClick={() => setOpen(o => !o)} style={{
        width: "100%", display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: 24, background: "none", border: "none", outline: "none", cursor: "pointer",
      }}>
        <div style={{ fontSize: 13, fontWeight: 600, color, textTransform: "uppercase", letterSpacing: 1 }}>
          {title} — <span style={{ color: count === 0 ? "#16a34a" : color }}>{count} findings</span>
        </div>
        <span className="text-muted" style={{ fontSize: 18, transform: open ? "rotate(180deg)" : "none", transition: "transform 0.2s" }}>▾</span>
      </button>
      {open && <div style={{ padding: "0 24px 24px" }}>{children}</div>}
    </div>
  );
}

const mdComponents = {
  h2: ({ children }: { children?: React.ReactNode }) => (
    <h2 style={{ fontSize: 15, fontWeight: 700, margin: "20px 0 6px" }}>{children}</h2>
  ),
  h3: ({ children }: { children?: React.ReactNode }) => (
    <h3 style={{ fontSize: 14, fontWeight: 600, margin: "14px 0 4px" }}>{children}</h3>
  ),
  p: ({ children }: { children?: React.ReactNode }) => (
    <p className="text-faint" style={{ fontSize: 14, lineHeight: 1.75, margin: "4px 0 10px" }}>{children}</p>
  ),
  ul: ({ children }: { children?: React.ReactNode }) => (
    <ul style={{ paddingLeft: 20, margin: "4px 0 10px" }}>{children}</ul>
  ),
  ol: ({ children }: { children?: React.ReactNode }) => (
    <ol style={{ paddingLeft: 20, margin: "4px 0 10px" }}>{children}</ol>
  ),
  li: ({ children }: { children?: React.ReactNode }) => (
    <li className="text-faint" style={{ fontSize: 14, lineHeight: 1.75, marginBottom: 2 }}>{children}</li>
  ),
  strong: ({ children }: { children?: React.ReactNode }) => (
    <strong style={{ fontWeight: 700 }}>{children}</strong>
  ),
  code: ({ children }: { children?: React.ReactNode }) => (
    <code className="card-deep" style={{ color: "#3b82f6", borderRadius: 4, padding: "1px 6px", fontSize: 13, fontFamily: "monospace" }}>{children}</code>
  ),
};

function AISummary({ summary }: { summary?: string }) {
  const [open, setOpen] = useState(true);
  if (!summary) return null;
  return (
    <div className="card" style={{ borderRadius: 16, overflow: "hidden" }}>
      <button onClick={() => setOpen(o => !o)} style={{
        width: "100%", display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: 24, background: "none", border: "none", outline: "none", cursor: "pointer",
      }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: "#3b82f6", textTransform: "uppercase", letterSpacing: 1 }}>
          AI Assessment
        </div>
        <span className="text-muted" style={{ fontSize: 18, transform: open ? "rotate(180deg)" : "none", transition: "transform 0.2s" }}>▾</span>
      </button>
      {open && (
        <div style={{ padding: "0 24px 24px" }}>
          <ReactMarkdown components={mdComponents as never}>{summary}</ReactMarkdown>
        </div>
      )}
    </div>
  );
}

function StatusBanner({ status }: { status: AnalysisStatus }) {
  if (status === "idle" || status === "done" || status === "error") return null;
  const steps = ["queued", "running", "done"] as const;
  const currentIdx = steps.indexOf(status as typeof steps[number]);
  return (
    <div className="card" style={{ borderRadius: 12, padding: "14px 20px", marginBottom: 24, display: "flex", alignItems: "center", gap: 16 }}>
      <Spinner />
      <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
        {steps.map((step, i) => (
          <span key={step} style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span style={{
              fontSize: 13,
              fontWeight: i <= currentIdx ? 600 : 400,
              color: i < currentIdx ? "#16a34a" : i === currentIdx ? "#3b82f6" : "var(--text-faint)",
            }}>
              {i < currentIdx ? "✓ " : ""}
              {step === "queued" ? "Queued" : step === "running" ? "Running (~5 min)" : "Done"}
            </span>
            {i < steps.length - 1 && <span style={{ color: "var(--border)" }}>→</span>}
          </span>
        ))}
      </div>
    </div>
  );
}

// --- Cache check ---
async function checkCache(slug: string): Promise<{ currentVersion: string; cachedReport: Report | null }> {
  const [wpRes, cached] = await Promise.allSettled([
    fetch(`https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=${slug}`)
      .then(r => r.ok ? r.json() : null),
    fetchReport(slug).catch(() => null),
  ]);
  const currentVersion: string = wpRes.status === "fulfilled" && wpRes.value?.version ? wpRes.value.version : "";
  const cachedReport: Report | null = cached.status === "fulfilled" ? cached.value : null;
  return { currentVersion, cachedReport };
}

// --- GitHub API helpers ---

// Dispatches the workflow and returns the specific run ID so concurrent scans
// don't accidentally poll each other's runs.
async function dispatchWorkflow(slug: string): Promise<number> {
  const beforeDispatch = Date.now();

  const res = await fetch(
    `https://api.github.com/repos/${GH_OWNER}/${GH_REPO}/actions/workflows/analyze.yml/dispatches`,
    {
      method: "POST",
      headers: { Authorization: `Bearer ${GH_TOKEN}`, Accept: "application/vnd.github+json", "Content-Type": "application/json" },
      body: JSON.stringify({ ref: "main", inputs: { plugin_slug: slug } }),
    }
  );
  if (!res.ok) throw new Error(`Failed to dispatch workflow: ${res.status} ${await res.text()}`);

  // GitHub takes a moment to register the run — wait then find our run by creation time
  await new Promise(r => setTimeout(r, 4000));
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    const runsRes = await fetch(
      `https://api.github.com/repos/${GH_OWNER}/${GH_REPO}/actions/workflows/analyze.yml/runs?event=workflow_dispatch&per_page=5`,
      { headers: { Authorization: `Bearer ${GH_TOKEN}`, Accept: "application/vnd.github+json" } }
    );
    if (runsRes.ok) {
      const runs: { id: number; created_at: string }[] = (await runsRes.json()).workflow_runs ?? [];
      const ourRun = runs.find(r => new Date(r.created_at).getTime() >= beforeDispatch);
      if (ourRun) return ourRun.id;
    }
    await new Promise(r => setTimeout(r, 3000));
  }
  throw new Error("Could not find dispatched workflow run — check GitHub Actions.");
}

async function pollRunById(runId: number): Promise<void> {
  const deadline = Date.now() + 10 * 60 * 1000;
  while (Date.now() < deadline) {
    await new Promise(r => setTimeout(r, 5000));
    const res = await fetch(
      `https://api.github.com/repos/${GH_OWNER}/${GH_REPO}/actions/runs/${runId}`,
      { headers: { Authorization: `Bearer ${GH_TOKEN}`, Accept: "application/vnd.github+json" } }
    );
    if (!res.ok) continue;
    const run = await res.json();
    if (run.status === "completed") {
      if (run.conclusion === "success") return;
      throw new Error(`Workflow finished with conclusion: ${run.conclusion}`);
    }
  }
  throw new Error("Timed out waiting for workflow to complete.");
}

async function fetchReport(slug: string): Promise<Report> {
  const res = await fetch(`https://raw.githubusercontent.com/${GH_OWNER}/${GH_REPO}/main/reports/${slug}.json?t=${Date.now()}`);
  if (!res.ok) throw new Error(`Report not found for "${slug}"`);
  return res.json();
}

// --- Main App ---
export default function App() {
  const [slug, setSlug]         = useState("");
  const [status, setStatus]     = useState<AnalysisStatus>("idle");
  const [report, setReport]     = useState<Report | null>(null);
  const [error, setError]       = useState("");
  const [fromCache, setFromCache] = useState(false);

  async function analyze() {
    const s = slug.trim().toLowerCase();
    if (!s) return;
    if (!GH_TOKEN) { setError("No GitHub token configured. Set VITE_GH_TOKEN in the repo secrets."); return; }
    setStatus("queued"); setReport(null); setError(""); setFromCache(false);
    try {
      // Check if cached report is still current
      const { currentVersion, cachedReport } = await checkCache(s);
      const cacheHit =
        cachedReport !== null &&
        (
          // WP.org version matches cached version
          (currentVersion !== "" && cachedReport.scan?.version === currentVersion) ||
          // WP.org API failed/blocked — trust cache rather than always re-scanning
          currentVersion === ""
        );
      if (cacheHit) {
        setStatus("done");
        setFromCache(true);
        setReport(cachedReport!);
        return;
      }
      const runId = await dispatchWorkflow(s);
      setStatus("running");
      await pollRunById(runId);
      setStatus("done");
      setReport(await fetchReport(s));
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
      setStatus("error");
    }
  }

  const scan = report?.scan;
  const loading = status === "queued" || status === "running";

  return (
    <>
      <style>{`
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

        :root {
          color-scheme: light dark;
          --bg:         #f1f5f9;
          --bg-card:    #ffffff;
          --bg-deep:    #f8fafc;
          --border:     #e2e8f0;
          --text:       #0f172a;
          --text-muted: #64748b;
          --text-faint: #94a3b8;
        }
        @media (prefers-color-scheme: dark) {
          :root {
            --bg:         #0f172a;
            --bg-card:    #1e293b;
            --bg-deep:    #0f172a;
            --border:     #334155;
            --text:       #f1f5f9;
            --text-muted: #94a3b8;
            --text-faint: #64748b;
          }
        }

        body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; display: flex; justify-content: center; }
        .card       { background: var(--bg-card); border: 1px solid var(--border); }
        .card-deep  { background: var(--bg-deep); }
        .text-muted { color: var(--text-muted); }
        .text-faint { color: var(--text-faint); }

        @keyframes spin    { to { transform: rotate(360deg); } }
        @keyframes fadeIn  { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: none; } }
        .fade { animation: fadeIn 0.3s ease; }

        input { color-scheme: light dark; }
        input:focus { border-color: #3b82f6 !important; outline: none; }
        a { color: #3b82f6; }
        a:hover { text-decoration: underline; }

        @media (prefers-color-scheme: dark) {
          .score-card-light { display: none !important; }
        }
        @media (prefers-color-scheme: light) {
          .score-card-dark { display: none !important; }
        }
      `}</style>

      <div style={{ maxWidth: 860, width: "100%", margin: "0 auto", padding: "56px 32px" }}>

        {/* Header — centered */}
        <div style={{ textAlign: "center", marginBottom: 48 }}>
          <h1 style={{ fontSize: 34, fontWeight: 800, letterSpacing: -1 }}>WP Plugin Insight</h1>
          <p className="text-muted" style={{ marginTop: 10, fontSize: 15, lineHeight: 1.7, maxWidth: 580, margin: "10px auto 0" }}>
            AI-powered security &amp; quality analysis for WordPress plugins.
            Runs entirely on{" "}
            <a href={`https://github.com/${GH_OWNER}/${GH_REPO}/actions/workflows/analyze.yml`} target="_blank" rel="noreferrer">GitHub Actions</a>
            {" "}— slower than a local tool (~5 min), but 100% transparent.{" "}
            <a href={`https://github.com/${GH_OWNER}/${GH_REPO}`} target="_blank" rel="noreferrer">View source &amp; contribute →</a>
          </p>
        </div>

        {/* Search — centered */}
        <div style={{ display: "flex", gap: 10, marginBottom: 28, maxWidth: 540, margin: "0 auto 28px" }}>
          <input
            value={slug}
            onChange={e => setSlug(e.target.value)}
            onKeyDown={e => e.key === "Enter" && !loading && analyze()}
            placeholder="Plugin slug, e.g. woocommerce"
            style={{
              flex: 1, padding: "13px 18px", borderRadius: 12,
              border: "1px solid var(--border)", background: "var(--bg-card)",
              color: "var(--text)", fontSize: 15, transition: "border-color 0.2s",
            }}
          />
          <button onClick={analyze} disabled={loading} style={{
            padding: "13px 26px", borderRadius: 12, border: "none",
            background: loading ? "var(--bg-deep)" : "#3b82f6",
            color: loading ? "var(--text-muted)" : "white",
            fontWeight: 600, fontSize: 15, cursor: loading ? "not-allowed" : "pointer",
            minWidth: 110, display: "flex", alignItems: "center", justifyContent: "center",
            transition: "background 0.2s",
          }}>
            {loading ? <><Spinner />Scanning…</> : "Analyze"}
          </button>
        </div>

        {/* Progress */}
        <StatusBanner status={status} />

        {/* Error */}
        {error && (
          <div className="fade" style={{
            background: "#fef2f2", border: "1px solid #fecaca",
            borderRadius: 12, padding: "14px 18px", color: "#b91c1c", marginBottom: 24,
          }}>
            {error}
          </div>
        )}

        {/* Results */}
        {report && scan && (
          <div className="fade" style={{ display: "flex", flexDirection: "column", gap: 16 }}>

            {/* Score + Meta */}
            <div style={{ display: "grid", gridTemplateColumns: "160px 1fr", gap: 16 }}>
              {/* Light mode score card */}
              <div className="score-card-light card" style={{
                background: scoreBg(report.score),
                border: `1px solid ${scoreColor(report.score)}30`,
                borderRadius: 16, padding: 24, textAlign: "center",
              }}>
                <div style={{ color: scoreColor(report.score), fontSize: 72, fontWeight: 800, lineHeight: 1 }}>{scoreGrade(report.score)}</div>
                <div style={{ color: scoreColor(report.score), fontSize: 13, marginTop: 6, fontWeight: 600 }}>{scoreLabel(report.score)}</div>
              </div>
              {/* Dark mode score card */}
              <div className="score-card-dark" style={{
                background: scoreDark(report.score),
                border: `1px solid ${scoreColor(report.score)}40`,
                borderRadius: 16, padding: 24, textAlign: "center",
              }}>
                <div style={{ color: scoreColor(report.score), fontSize: 72, fontWeight: 800, lineHeight: 1 }}>{scoreGrade(report.score)}</div>
                <div style={{ color: scoreColor(report.score), fontSize: 13, marginTop: 6, fontWeight: 600 }}>{scoreLabel(report.score)}</div>
              </div>

              <div className="card" style={{ borderRadius: 16, padding: 24, display: "flex", flexDirection: "column", justifyContent: "center" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6, flexWrap: "wrap" }}>
                  <span style={{ fontSize: 20, fontWeight: 700 }}>{report.slug}</span>
                  {scan.version && (
                    <span style={{ fontSize: 13, color: "var(--text-muted)", fontFamily: "monospace" }}>v{scan.version}</span>
                  )}
                  {fromCache && (
                    <span style={{ fontSize: 11, fontWeight: 600, color: "#15803d", background: "#f0fdf4", border: "1px solid #bbf7d0", borderRadius: 20, padding: "2px 10px" }}>
                      cached
                    </span>
                  )}
                </div>
                <div className="text-muted" style={{ fontSize: 13 }}>
                  {scan.files_scanned} PHP · {scan.js_files_scanned} JS · min PHP {scan.min_php_version}
                </div>
              </div>
            </div>

            {/* AI Summary */}
            <AISummary summary={report.summary} />

            {/* Stats */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 12 }}>
              <StatCard label="PHP files"           value={scan.files_scanned} />
              <StatCard label="JS files"            value={scan.js_files_scanned} />
              <StatCard label="External HTTP calls" value={scan.external_calls} warn={scan.external_calls > 3} />
              <StatCard label="Direct DB access"    value={scan.direct_db_access ? "Yes" : "No"} warn={scan.direct_db_access} />
              <StatCard label="Missing i18n"        value={scan.missing_i18n_samples.length} warn={scan.missing_i18n_samples.length > 0} />
            </div>

            {/* Security flags + Deprecated */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
              <div className="card" style={{ borderRadius: 16, padding: 24 }}>
                <div style={{ fontSize: 13, fontWeight: 600, color: "#dc2626", textTransform: "uppercase", letterSpacing: 1, marginBottom: 12 }}>Security Flags</div>
                {scan.security_flags.length === 0
                  ? <span style={{ color: "#16a34a", fontSize: 14 }}>✓ None found</span>
                  : scan.security_flags.map(f => <Pill key={f} label={f} color="#dc2626" />)
                }
              </div>
              <div className="card" style={{ borderRadius: 16, padding: 24 }}>
                <div style={{ fontSize: 13, fontWeight: 600, color: "#d97706", textTransform: "uppercase", letterSpacing: 1, marginBottom: 12 }}>Deprecated Functions</div>
                {scan.deprecated_functions.length === 0
                  ? <span style={{ color: "#16a34a", fontSize: 14 }}>✓ None found</span>
                  : scan.deprecated_functions.map(f => <Pill key={f} label={f} color="#d97706" />)
                }
              </div>
            </div>

            {/* Known CVEs */}
            <Collapsible title="Known CVEs" count={scan.cve_findings?.length ?? 0} color="#dc2626">
              {(scan.cve_findings?.length ?? 0) === 0
                ? <span style={{ color: "#16a34a", fontSize: 14 }}>✓ No known CVEs affecting this version</span>
                : <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                    {scan.cve_findings.map(c => {
                      const col = c.cvss_score >= 9 ? "#dc2626" : c.cvss_score >= 7 ? "#ea580c" : "#d97706";
                      const label = c.cvss_score >= 9 ? "CRITICAL" : c.cvss_score >= 7 ? "HIGH" : c.cvss_score >= 4 ? "MEDIUM" : "LOW";
                      return (
                        <div key={c.uuid} className="card-deep" style={{ borderRadius: 10, padding: "12px 16px", border: `1px solid ${col}20` }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
                            <span style={{ background: col + "18", color: col, border: `1px solid ${col}30`, borderRadius: 6, padding: "2px 8px", fontSize: 11, fontWeight: 700 }}>{label} {c.cvss_score.toFixed(1)}</span>
                            <span style={{ fontWeight: 600, fontSize: 14 }}>{c.title}</span>
                          </div>
                          <div className="text-muted" style={{ fontSize: 13, marginTop: 6 }}>
                            {c.unfixed
                              ? <span style={{ color: "#dc2626" }}>No fix available</span>
                              : c.fixed_in ? <>Fixed in <code style={{ fontFamily: "monospace", fontSize: 12 }}>{c.fixed_in}</code></> : null
                            }
                            {c.references && c.references.length > 0 && (
                              <span style={{ marginLeft: 12 }}>
                                {c.references.map((ref, i) => (
                                  <a key={i} href={ref} target="_blank" rel="noreferrer" style={{ marginRight: 8, fontSize: 12 }}>Reference {i + 1} →</a>
                                ))}
                              </span>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
              }
            </Collapsible>

            {/* Vulnerable Dependencies */}
            <Collapsible title="Vulnerable Dependencies" count={scan.dep_vulns?.length ?? 0} color="#ea580c">
              {(scan.dep_vulns?.length ?? 0) === 0
                ? <span style={{ color: "#16a34a", fontSize: 14 }}>✓ No vulnerable dependencies found</span>
                : <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                    {scan.dep_vulns.map((d, i) => {
                      const col = d.severity === "critical" ? "#dc2626" : d.severity === "high" ? "#ea580c" : "#d97706";
                      return (
                        <div key={i} className="card-deep" style={{ borderRadius: 10, padding: "12px 16px", border: `1px solid ${col}20` }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
                            <span style={{ background: col + "18", color: col, border: `1px solid ${col}30`, borderRadius: 6, padding: "2px 8px", fontSize: 11, fontWeight: 700 }}>{d.severity.toUpperCase()}</span>
                            <span style={{ fontFamily: "monospace", fontWeight: 600, fontSize: 13 }}>{d.package}@{d.version}</span>
                            {d.cve && <span style={{ fontSize: 12, color: "var(--text-muted)" }}>{d.cve}</span>}
                          </div>
                          {d.summary && <div className="text-muted" style={{ fontSize: 13, marginTop: 6 }}>{d.summary}</div>}
                          {d.fixed_in && d.fixed_in.length > 0 && (
                            <div style={{ fontSize: 12, marginTop: 4, color: "#16a34a" }}>
                              Fix: upgrade to {d.fixed_in.join(", ")}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
              }
            </Collapsible>

            {/* Findings */}
            <Collapsible title="Semgrep" count={scan.semgrep_findings?.length ?? 0} color="#dc2626">
              <FindingsTable findings={scan.semgrep_findings ?? []} color="#dc2626" />
            </Collapsible>
            <Collapsible title="PHPCS" count={scan.phpcs_findings?.length ?? 0} color="#d97706">
              <FindingsTable findings={scan.phpcs_findings ?? []} color="#d97706" />
            </Collapsible>

          </div>
        )}

      </div>
    </>
  );
}

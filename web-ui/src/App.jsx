import { useCallback, useEffect, useState } from "react";
import {
  AlertTriangle,
  Bot,
  CheckCircle2,
  Circle,
  Download,
  Eye,
  FileText,
  Globe2,
  LoaderCircle,
  LockKeyhole,
  Play,
  RotateCcw,
  Shield,
  X,
} from "lucide-react";
import { download, request } from "./api.js";

function Spinner({ size = 15 }) {
  return <LoaderCircle className="spin" size={size} />;
}

function Card({ title, icon: Icon, children, actions }) {
  return (
    <section className="card">
      <div className="card-head">
        {Icon && <span className="card-icon"><Icon size={16} /></span>}
        <h2>{title}</h2>
        {actions && <div className="card-actions">{actions}</div>}
      </div>
      {children}
    </section>
  );
}

function StepIcon({ status }) {
  if (status === "done") return <CheckCircle2 size={15} className="ok" />;
  if (status === "running") return <Spinner size={15} />;
  return <Circle size={15} className="muted" />;
}

function App() {
  const [state, setState] = useState(null);
  const [target, setTarget] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [busy, setBusy] = useState("");
  const [notice, setNotice] = useState(null);
  const [offline, setOffline] = useState(false);

  const refresh = useCallback(async () => {
    try {
      setState(await request("/api/status"));
      setOffline(false);
    } catch {
      setOffline(true);
    }
  }, []);

  useEffect(() => {
    refresh();
    const timer = window.setInterval(refresh, 1000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  useEffect(() => {
    if (!notice) return undefined;
    const timer = window.setTimeout(() => setNotice(null), 6000);
    return () => window.clearTimeout(timer);
  }, [notice]);

  async function act(name, fn) {
    setBusy(name);
    try { await fn(); await refresh(); } catch (error) { setNotice({ kind: "error", text: error.message }); } finally { setBusy(""); }
  }

  const start = (event) => {
    event.preventDefault();
    act("start", () => request("/api/assess", { target, authorized }));
  };
  const analyze = () => act("analyze", () => request("/api/analyze", {}));
  const reset = () => act("reset", async () => {
    await request("/api/reset", {});
    setAuthorized(false);
  });
  const exportReport = (format) => act(format, () => download(`/api/report?format=${format}`));

  const running = state?.status === "running";
  const scan = state?.scan;
  const analysis = state?.analysis;

  return (
    <div className="single">
      <header className="app-header">
        <div className="brand"><span className="brand-mark"><Shield size={20} strokeWidth={2.2} /></span><span className="brand-copy"><strong>security<span>ops</span></strong><small>WEBSITE SECURITY ASSESSMENT</small></span></div>
        <div className="header-pills">
          <span className="pill"><Bot size={12} /> AI: {state?.provider ?? "…"}</span>
          <span className="pill green"><LockKeyhole size={11} /> Runs locally</span>
        </div>
      </header>

      {offline && <div className="alert">The local server is not responding. Start it with <code>python -m securityops</code>, then refresh.</div>}

      <Card title="1. Information gathering" icon={Globe2} actions={scan && !running && <button className="btn ghost" onClick={reset} disabled={busy === "reset" || state?.analyzing}><RotateCcw size={14} />New assessment</button>}>
        <form className="target-form" onSubmit={start}>
          <input value={target} onChange={(e) => setTarget(e.target.value)} maxLength={300} placeholder="example.com, https://example.com or 127.0.0.1:8080" aria-label="Target domain" disabled={running} required />
          <button className="btn primary" disabled={!authorized || !target.trim() || running || busy === "start"}>{running || busy === "start" ? <Spinner /> : <Play size={15} fill="currentColor" />}Start Assessment</button>
        </form>
        <label className="consent"><input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} disabled={running} /><span>I own this target or have explicit permission to assess it. Only non-destructive checks are performed.</span></label>

        {state?.steps?.length > 0 && (
          <div className="progress" aria-live="polite">
            <div className="progress-head"><strong>{running ? `Assessing ${state.target}…` : state.status === "error" ? "Assessment failed" : `Assessment of ${state.target} complete`}</strong><span>{state.steps.filter((s) => s.status === "done").length} / {state.steps.length}</span></div>
            <div className="bar"><i style={{ width: `${(100 * state.steps.filter((s) => s.status === "done").length) / state.steps.length}%` }} /></div>
            <ul className="steps">{state.steps.map((step) => <li key={step.name} className={step.status}><StepIcon status={step.status} />{step.name}</li>)}</ul>
          </div>
        )}
        {state?.error && <div className="alert">{state.error}</div>}
      </Card>

      {scan && <Results scan={scan} />}

      {scan && (
        <Card title="2. AI security analysis" icon={Bot} actions={<button className="btn primary" onClick={analyze} disabled={state.analyzing || busy === "analyze"}>{state.analyzing ? <Spinner /> : <Bot size={15} />}{analysis ? "Re-run AI Analysis" : "Run AI Analysis"}</button>}>
          {state.analyzing && <p className="muted">Sending the collected results to {state.provider}. The model only receives text; it cannot run commands.</p>}
          {!analysis && !state.analyzing && <p className="muted">The analysis interprets the results above, rates each finding, explains the evidence and recommends fixes.</p>}
          {analysis && <AnalysisView analysis={analysis} />}
        </Card>
      )}

      {scan && (
        <Card title="3. Report" icon={FileText}>
          <p className="muted">Includes target, date, scope, executive summary, findings with evidence and severity, remediation, and limitations. {analysis ? "" : "Run the AI analysis first for the full report; otherwise rule-based findings are used."}</p>
          <div className="row">
            <button className="btn primary" onClick={() => exportReport("html")} disabled={busy === "html"}>{busy === "html" ? <Spinner /> : <Download size={15} />}Export HTML Report</button>
            <button className="btn" onClick={() => exportReport("pdf")} disabled={busy === "pdf"}>{busy === "pdf" ? <Spinner /> : <Download size={15} />}Export PDF</button>
            <a className="btn ghost" href="/api/report?format=html&inline=1" target="_blank" rel="noreferrer"><Eye size={15} />Preview</a>
          </div>
        </Card>
      )}

      <footer className="foot">For authorized, non-destructive assessment only · nothing runs without your confirmation</footer>
      {notice && <div className={`toast ${notice.kind}`} role="status"><AlertTriangle size={16} />{notice.text}<button aria-label="Dismiss" onClick={() => setNotice(null)}><X size={14} /></button></div>}
    </div>
  );
}

function Results({ scan }) {
  const headers = scan.headers.filter((h) => h.applicable);
  return (
    <Card title="Results" icon={CheckCircle2}>
      <p className="summary">{scan.summary}</p>
      <div className="grid">
        <div className="block">
          <h3>DNS records</h3>
          {Object.keys(scan.dns).length ? (
            <table><tbody>{Object.entries(scan.dns).map(([type, values]) => <tr key={type}><th>{type}</th><td><code>{values.join(", ")}</code></td></tr>)}</tbody></table>
          ) : <p className="muted">No DNS records found.</p>}
        </div>
        <div className="block">
          <h3>HTTP / HTTPS</h3>
          {Object.keys(scan.http).length ? (
            <table><tbody>{Object.entries(scan.http).map(([scheme, r]) => <tr key={scheme}><th>{scheme.toUpperCase()}</th><td><strong>{r.status} {r.reason}</strong> · {r.response_ms} ms<br /><code>{r.final_url}</code>{r.title && <><br /><span className="muted">“{r.title}”</span></>}</td></tr>)}</tbody></table>
          ) : <p className="muted">No web server responded.</p>}
        </div>
        <div className="block">
          <h3>TLS certificate</h3>
          {scan.tls.valid ? (
            <table><tbody>
              <tr><th>Issuer</th><td>{scan.tls.issuer}</td></tr>
              <tr><th>Subject</th><td>{scan.tls.subject}</td></tr>
              <tr><th>Expires</th><td className={scan.tls.days_remaining < 30 ? "bad" : ""}>{scan.tls.not_after} ({scan.tls.days_remaining} days)</td></tr>
              <tr><th>Protocol</th><td>{scan.tls.protocol}</td></tr>
            </tbody></table>
          ) : <p className="bad">{scan.tls.error || "Not checked."}</p>}
        </div>
        <div className="block">
          <h3>Technologies</h3>
          {scan.technologies.length ? (
            <table><tbody>{scan.technologies.map((t) => <tr key={t.name}><th>{t.name}</th><td className="muted">{t.evidence}</td></tr>)}</tbody></table>
          ) : <p className="muted">No technology hints observed.</p>}
        </div>
        <div className="block wide">
          <h3>Security headers</h3>
          {headers.length ? (
            <table><tbody>{headers.map((h) => <tr key={h.name}><th>{h.name}</th><td>{h.present ? <span className="ok">Present</span> : <span className="bad">Missing</span>}{h.value && <> · <code>{h.value}</code></>}<br /><span className="muted">{h.purpose}</span></td></tr>)}</tbody></table>
          ) : <p className="muted">Not checked (no web response).</p>}
        </div>
      </div>
      {scan.errors.length > 0 && <div className="note">Some checks could not complete: {scan.errors.join("; ")}</div>}
    </Card>
  );
}

function AnalysisView({ analysis }) {
  return (
    <>
      {analysis.error && <div className="note">{analysis.error}</div>}
      <div className="exec"><span className="tag">{analysis.source === "ai" ? `AI · ${analysis.provider}` : "Rule-based"}</span><p>{analysis.executive_summary}</p></div>
      <p className="legend"><strong>Confirmed</strong> = directly observed in the evidence. <strong>Potential risk</strong> = inferred, verify manually.</p>
      <div className="findings">
        {analysis.findings.length === 0 && <p className="muted">No issues were identified in the areas checked.</p>}
        {analysis.findings.map((f) => (
          <article key={f.id} className={`finding ${f.severity.toLowerCase()}`}>
            <div className="finding-head"><span className={`sev ${f.severity.toLowerCase()}`}>{f.severity}</span><strong>{f.title}</strong><span className={`status ${f.status === "Confirmed" ? "confirmed" : "potential"}`}>{f.status}</span></div>
            <dl>
              <dt>Evidence</dt><dd><code>{f.evidence}</code></dd>
              <dt>Why it matters</dt><dd>{f.why_it_matters}</dd>
              <dt>Remediation</dt><dd>{f.remediation}</dd>
            </dl>
          </article>
        ))}
      </div>
    </>
  );
}

export default App;

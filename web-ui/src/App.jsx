import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  ArrowDown,
  ArrowUpRight,
  Check,
  CheckCircle2,
  ChevronRight,
  CircleHelp,
  Clock3,
  Command,
  FileCheck2,
  Globe2,
  LoaderCircle,
  LockKeyhole,
  Play,
  Radio,
  RefreshCw,
  ScanLine,
  Shield,
  ShieldCheck,
  Square,
  Terminal,
  Wrench,
  X,
} from "lucide-react";

async function request(path, body) {
  const response = await fetch(path, body ? {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  } : { cache: "no-store" });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}

function StatusBadge({ status }) {
  const style = status.toLowerCase();
  return <span className={`status-badge ${style}`}><i />{status}</span>;
}

function App() {
  const [state, setState] = useState(null);
  const [connectionError, setConnectionError] = useState("");
  const [projectName, setProjectName] = useState("");
  const [target, setTarget] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [goal, setGoal] = useState("");
  const [selectedSteps, setSelectedSteps] = useState([]);
  const [busy, setBusy] = useState("");
  const [notice, setNotice] = useState(null);
  const [activeNav, setActiveNav] = useState("workspace");

  const refresh = useCallback(async () => {
    try {
      setState(await request("/api/state"));
      setConnectionError("");
    } catch (error) {
      setConnectionError(error.message);
    }
  }, []);

  useEffect(() => {
    refresh();
    const timer = window.setInterval(refresh, 1500);
    return () => window.clearInterval(timer);
  }, [refresh]);

  useEffect(() => {
    const pending = state?.plan?.steps
      ?.filter((step) => step.status === "Pending")
      .map((step) => step.index) ?? [];
    setSelectedSteps((current) => current.filter((index) => pending.includes(index)));
  }, [state?.plan]);

  const installedTools = useMemo(
    () => state?.tools?.filter((tool) => tool.installed) ?? [],
    [state],
  );
  const pendingSteps = state?.plan?.steps?.filter((step) => step.status === "Pending") ?? [];

  function showNotice(message, kind = "info") {
    setNotice({ message, kind });
    window.setTimeout(() => setNotice(null), 5200);
  }

  async function handleProject(event) {
    event.preventDefault();
    setBusy("project");
    try {
      await request("/api/project", { name: projectName, target, authorized });
      setProjectName("");
      setTarget("");
      setAuthorized(false);
      setGoal("");
      setSelectedSteps([]);
      await refresh();
      showNotice("Authorized engagement saved locally.", "success");
    } catch (error) {
      showNotice(error.message, "error");
    } finally {
      setBusy("");
    }
  }

  async function handlePlan(event) {
    event.preventDefault();
    setBusy("plan");
    try {
      await request("/api/plan", { goal });
      await refresh();
      showNotice("Plan ready. Review every command before approval.", "success");
    } catch (error) {
      showNotice(error.message, "error");
    } finally {
      setBusy("");
    }
  }

  async function handleRun() {
    if (!selectedSteps.length) return;
    const steps = state?.plan?.steps.filter((step) => selectedSteps.includes(step.index)) ?? [];
    const commandList = steps.map((step) => step.command).join("\n\n");
    if (!window.confirm(`Approve and run ${steps.length} selected step(s)?\n\n${commandList}\n\nOnly proceed against targets you are authorized to assess.`)) {
      return;
    }
    setBusy("run");
    try {
      await request("/api/run", { steps: selectedSteps });
      await refresh();
      showNotice("Approved steps are running in the background.", "success");
    } catch (error) {
      showNotice(error.message, "error");
    } finally {
      setBusy("");
    }
  }

  async function handleCancel() {
    setBusy("cancel");
    try {
      await request("/api/cancel", {});
      await refresh();
      showNotice("Cancellation requested. The current command will stop.", "info");
    } catch (error) {
      showNotice(error.message, "error");
    } finally {
      setBusy("");
    }
  }

  function goTo(section) {
    setActiveNav(section);
    document.getElementById(section)?.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  const plan = state?.plan;
  const project = state?.project;
  const completeCount = state?.scans?.length ?? 0;

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="#workspace" onClick={(event) => { event.preventDefault(); goTo("workspace"); }}>
          <span className="brand-mark"><Shield size={20} strokeWidth={2.2} /></span>
          <span className="brand-copy"><strong>security<span>ops</span></strong><small>LOCAL WORKSPACE</small></span>
        </a>
        <div className="side-label">WORKSPACE</div>
        <nav className="side-nav" aria-label="Workspace sections">
          <button className={activeNav === "workspace" ? "active" : ""} onClick={() => goTo("workspace")}><Command size={17} />Overview</button>
          <button className={activeNav === "engagement" ? "active" : ""} onClick={() => goTo("engagement")}><Globe2 size={17} />Engagement</button>
          <button className={activeNav === "workflow" ? "active" : ""} onClick={() => goTo("workflow")}><ScanLine size={17} />Assessment plan</button>
          <button className={activeNav === "activity" ? "active" : ""} onClick={() => goTo("activity")}><Activity size={17} />Activity &amp; history</button>
        </nav>
        <div className="sidebar-spacer" />
        <div className="privacy-card">
          <div className="privacy-icon"><LockKeyhole size={16} /></div>
          <strong>Your data stays here</strong>
          <p>Runs on this machine. Nothing is sent to a cloud service.</p>
        </div>
        <div className="sidebar-footer"><span className="online-dot" />Loopback only <span>·</span> 127.0.0.1</div>
      </aside>

      <main className="main-content" id="workspace">
        <header className="topbar">
          <div className="breadcrumb"><span>SecurityOps</span><ChevronRight size={14} /><strong>Workspace</strong></div>
          <div className="topbar-right">
            <span className="local-pill"><span className="online-dot" />LOCAL ONLY</span>
            <button className="icon-button" aria-label="Refresh state" onClick={refresh}><RefreshCw size={16} /></button>
            <div className="avatar">SO</div>
          </div>
        </header>

        {connectionError && <div className="connection-banner"><CircleHelp size={17} /><span><strong>Backend unavailable</strong> — {connectionError}. Start the SecurityOps local server, then refresh.</span><button onClick={refresh}><RefreshCw size={15} /> Retry</button></div>}

        <section className="page-heading">
          <div>
            <div className="eyebrow"><span className="eyebrow-mark"><Command size={12} /></span> SECURITY ASSESSMENT WORKSPACE</div>
            <h1>Good to see you<span className="heading-period">.</span></h1>
            <p>Set your scope, build a reviewable plan, and stay in control at every step.</p>
          </div>
          <div className="heading-status"><div className={`pulse ${state?.running ? "running" : ""}`} /><span>{state?.running ? "Assessment in progress" : "Workspace ready"}</span><span className="heading-divider" />Updated live</div>
        </section>

        <section className="metrics-grid" aria-label="Workspace summary">
          <article className="metric-card"><div className="metric-icon blue"><Wrench size={18} /></div><div className="metric-top"><span>TOOLS AVAILABLE</span><ArrowUpRight size={15} /></div><div className="metric-value">{state ? installedTools.length : "—"}<small> / {state?.tools?.length ?? "—"}</small></div><div className="metric-foot">Detected on this machine</div></article>
          <article className="metric-card"><div className="metric-icon green"><FileCheck2 size={18} /></div><div className="metric-top"><span>RECORDED RUNS</span><ArrowUpRight size={15} /></div><div className="metric-value">{completeCount.toString().padStart(2, "0")}</div><div className="metric-foot">Saved to the local audit history</div></article>
          <article className="metric-card"><div className="metric-icon violet"><ShieldCheck size={18} /></div><div className="metric-top"><span>ACTIVE ENGAGEMENT</span><ArrowUpRight size={15} /></div><div className="metric-value metric-project">{project ? project.name : "Not set"}</div><div className="metric-foot">{project ? `In scope · ${project.target}` : "Create an authorized project to begin"}</div></article>
        </section>

        <section className="engagement-card section-anchor" id="engagement">
          <div className="section-title-row">
            <div className="section-title-icon"><Globe2 size={18} /></div>
            <div><div className="section-kicker">STEP 01 <span>·</span> ENGAGEMENT</div><h2>{project ? "Current engagement" : "Set up your engagement"}</h2></div>
            {project && <span className="scope-tag"><ShieldCheck size={13} /> Authorized · In scope</span>}
          </div>
          {project ? (
            <div className="active-project">
              <div className="project-target-icon"><Globe2 size={19} /></div>
              <div className="project-details"><strong>{project.name}</strong><span>{project.target}</span></div>
              <div className="project-state"><span className="online-dot" />Scope verified</div>
              <div className="project-shield"><ShieldCheck size={19} /></div>
            </div>
          ) : (
            <form onSubmit={handleProject}>
              <div className="form-grid">
                <label>Project name<input value={projectName} onChange={(event) => setProjectName(event.target.value)} maxLength={120} required placeholder="e.g. Internal web assessment" /></label>
                <label>Authorized target<input value={target} onChange={(event) => setTarget(event.target.value)} maxLength={500} required placeholder="https://example.com or 192.0.2.10" /></label>
              </div>
              <label className="consent-row"><input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} required /><span>I own this target or have explicit written permission to assess it.</span></label>
              <div className="form-actions"><span className="form-hint"><LockKeyhole size={13} /> Target is stored locally and must remain in scope.</span><button className="button-primary" disabled={busy === "project" || !authorized}>{busy === "project" ? <LoaderCircle className="spin" size={16} /> : <ShieldCheck size={16} />}Save authorized project<ArrowUpRight size={14} /></button></div>
            </form>
          )}
        </section>

        <div className="workspace-grid">
          <section className="panel section-anchor" id="workflow">
            <div className="panel-header">
              <div className="section-title-icon blue"><ScanLine size={18} /></div>
              <div className="panel-heading"><div className="section-kicker">STEP 02 <span>·</span> PLAN &amp; REVIEW</div><h2>Assessment workflow</h2><p>Commands are proposed for review. Nothing runs without approval.</p></div>
            </div>
            {!plan && (
              <form className="goal-form" onSubmit={handlePlan}>
                <label htmlFor="goal">What do you want to assess?</label>
                <textarea id="goal" value={goal} onChange={(event) => setGoal(event.target.value)} maxLength={2000} required disabled={!project || state?.running} placeholder="Describe an authorized, non-destructive assessment goal…" />
                <div className="goal-footer"><span><LockKeyhole size={13} /> Local planning · harmful requests are refused</span><button className="button-primary" disabled={!project || state?.running || busy === "plan" || !goal.trim()}>{busy === "plan" ? <LoaderCircle className="spin" size={16} /> : <Command size={16} />}Generate plan<ChevronRight size={15} /></button></div>
              </form>
            )}
            {plan && (
              <div className="plan-content">
                {plan.refused ? (
                  <div className="refusal"><Shield size={19} /><div><strong>Request not accepted</strong><p>{plan.refusal_reason}</p></div></div>
                ) : (
                  <>
                    <div className="plan-summary"><div className="summary-icon"><CheckCircle2 size={17} /></div><div><strong>Plan ready for your review</strong><p>{plan.summary}</p></div><button className="text-button" onClick={() => { setGoal(""); setSelectedSteps([]); setState((current) => current ? { ...current, plan: null } : current); }}>New plan</button></div>
                    <div className="step-list">
                      {plan.steps.map((step) => (
                        <article className={`workflow-step ${step.status.toLowerCase()}`} key={step.index}>
                          <div className="step-header">
                            <label className="step-select" aria-label={`Approve ${step.title}`}>
                              <input type="checkbox" checked={selectedSteps.includes(step.index)} disabled={state?.running || step.status !== "Pending"} onChange={(event) => setSelectedSteps((current) => event.target.checked ? [...current, step.index] : current.filter((index) => index !== step.index))} />
                              <span className="custom-check"><Check size={12} /></span>
                            </label>
                            <div className="step-number">{String(step.index + 1).padStart(2, "0")}</div>
                            <div className="step-name"><strong>{step.title}</strong><span>{step.rationale}</span></div>
                            <StatusBadge status={step.status} />
                          </div>
                          <div className="command-box"><Terminal size={14} /><code>{step.command}</code><span>REVIEW COMMAND</span></div>
                          {step.warning && <div className="step-warning"><CircleHelp size={14} />{step.warning}</div>}
                          {step.output && <pre className="step-output">{step.output.slice(-1800)}</pre>}
                        </article>
                      ))}
                    </div>
                    {plan.steps.length === 0 && <div className="empty-plan"><Wrench size={19} /><span>No suitable installed tools were found for this plan.</span></div>}
                    {!state?.running && pendingSteps.length > 0 && <div className="run-controls"><span><LockKeyhole size={13} /> {selectedSteps.length} of {pendingSteps.length} steps selected</span><button className="button-primary" onClick={handleRun} disabled={!selectedSteps.length || busy === "run"}>{busy === "run" ? <LoaderCircle className="spin" size={16} /> : <Play size={15} fill="currentColor" />}Approve &amp; run<ArrowUpRight size={14} /></button></div>}
                    {state?.running && <div className="running-banner"><div className="pulse running" /><span>Workflow is running in the background. Output updates live.</span><button className="button-danger" onClick={handleCancel} disabled={busy === "cancel"}>{busy === "cancel" ? <LoaderCircle className="spin" size={15} /> : <Square size={13} fill="currentColor" />}Stop run</button></div>}
                    {plan.steps.length > 0 && pendingSteps.length === 0 && !state?.running && <div className="complete-banner"><CheckCircle2 size={16} />All planned steps have finished. Review the saved activity below.</div>}
                  </>
                )}
              </div>
            )}
          </section>

          <aside className="right-column">
            <section className="panel tools-panel">
              <div className="small-panel-header"><div className="section-title-icon green"><Wrench size={17} /></div><div><h2>Tool inventory</h2><p>{installedTools.length} detected · {state?.tools?.length ?? 0} in catalog</p></div><ArrowDown size={15} /></div>
              <div className="tool-list">{state?.tools?.map((tool) => <div className={`tool-row ${tool.installed ? "" : "unavailable"}`} key={tool.key}><span className={`tool-icon ${tool.installed ? "available" : ""}`}><Wrench size={14} /></span><span className="tool-name">{tool.name}<small>{tool.category}</small></span><span className="tool-state">{tool.installed ? "Ready" : "Missing"}</span></div>)}</div>
              <div className="panel-footnote"><LockKeyhole size={12} />Interactive tools are excluded from automated plans.</div>
            </section>
            <section className="panel activity-panel section-anchor" id="activity">
              <div className="small-panel-header"><div className="section-title-icon violet"><Activity size={17} /></div><div><h2>Live activity</h2><p>{state?.running ? "Streaming current workflow" : "Recent local activity"}</p></div><span className={`activity-indicator ${state?.running ? "live" : ""}`} /></div>
              <div className="activity-feed">{state?.log?.length ? state.log.slice(-14).map((line, index) => <div className="activity-line" key={`${index}-${line}`}><span className="activity-bullet" /><span>{line}</span></div>) : <div className="activity-empty"><Radio size={18} /><span>When a workflow runs, live output will appear here.</span></div>}</div>
              <div className="small-panel-header history-heading"><div className="section-title-icon amber"><Clock3 size={16} /></div><div><h2>Run history</h2><p>Saved to this machine</p></div></div>
              <div className="history-list">{state?.scans?.length ? state.scans.map((scan, index) => <div className="history-row" key={`${scan.tool}-${index}`}><div className="history-icon"><Terminal size={14} /></div><div className="history-copy"><strong>{scan.tool}</strong><span title={scan.command}>{scan.command}</span></div><StatusBadge status={scan.status} /></div>) : <div className="history-empty"><Clock3 size={16} />No runs recorded yet.</div>}</div>
            </section>
          </aside>
        </div>
        <footer className="page-footer"><span><ShieldCheck size={14} /> Authorized assessments only</span><span>All activity is local <span className="footer-dot">·</span> Commands are reviewed before execution</span></footer>
      </main>
      {notice && <div className={`toast ${notice.kind}`} role="status"><span>{notice.kind === "error" ? <X size={16} /> : <CheckCircle2 size={16} />}</span>{notice.message}<button aria-label="Dismiss notification" onClick={() => setNotice(null)}><X size={15} /></button></div>}
    </div>
  );
}

export default App;

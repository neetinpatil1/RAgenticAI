import { useEffect, useRef, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend,
} from "recharts";
import {
  ChevronDown, ChevronUp, RotateCcw, ShieldAlert, ExternalLink,
  FileCode, Wrench, BookOpen, TrendingUp, Brain, Zap, Code2, AlertTriangle,
  CheckCircle2, Loader2, PlayCircle, Key, Package, CheckCheck, Network,
} from "lucide-react";
import {
  getFindings, getScanStatus, triggerCodeReview, getCodeReview,
  getCodeReviewProgress, getSecretFindings, getDependencyFindings,
  getFpChallengeProgress,
} from "../lib/api";
import type {
  Finding, ScanStatus, CodeReviewFinding, CodeReviewSummary,
  ReviewCategory, SecretFinding, SecretSummary, DependencyFinding, DependencySummary,
} from "../types";
import { SeverityBadge } from "./SeverityBadge";
import { CodeBlock } from "./CodeBlock";
import { CodeGraph } from "./CodeGraph";

const SEV_COLORS: Record<string, string> = {
  CRITICAL: "#ef4444",
  HIGH:     "#f97316",
  MEDIUM:   "#eab308",
  LOW:      "#3b82f6",
  INFO:     "#6b7280",
};

interface Props {
  runId: string;
  scanPath?: string;
  onNewScan: () => void;
}

const CAT_ICONS: Record<ReviewCategory, React.ReactNode> = {
  SECURITY:       <ShieldAlert   className="w-3.5 h-3.5" />,
  PERFORMANCE:    <Zap           className="w-3.5 h-3.5" />,
  CODE_QUALITY:   <Code2         className="w-3.5 h-3.5" />,
  ERROR_HANDLING: <AlertTriangle className="w-3.5 h-3.5" />,
  BEST_PRACTICES: <CheckCircle2  className="w-3.5 h-3.5" />,
};

const CAT_COLORS: Record<ReviewCategory, string> = {
  SECURITY:       "text-red-400 bg-red-500/10 border-red-500/30",
  PERFORMANCE:    "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
  CODE_QUALITY:   "text-purple-400 bg-purple-500/10 border-purple-500/30",
  ERROR_HANDLING: "text-orange-400 bg-orange-500/10 border-orange-500/30",
  BEST_PRACTICES: "text-green-400 bg-green-500/10 border-green-500/30",
};

export function ScanResults({ runId, scanPath, onNewScan }: Props) {
  const [findings,  setFindings]  = useState<Finding[]>([]);
  const [status,    setStatus]    = useState<ScanStatus | null>(null);
  const [expanded,  setExpanded]  = useState<Set<string>>(new Set());
  const [loading,   setLoading]   = useState(true);
  const [sevFilter, setSevFilter] = useState<string>("ALL");
  const [activeTab, setActiveTab] = useState<"sast" | "review" | "secrets" | "deps">("sast");
  // True only after workflow_runs.state = "completed" — i.e. Semgrep + FP pipeline both done
  const [sastDone,  setSastDone]  = useState(false);

  // Code review state — starts as "loading" like secrets/SCA, no separate detection needed
  const [crFindings,   setCrFindings]   = useState<CodeReviewFinding[]>([]);
  const [crSummary,    setCrSummary]    = useState<CodeReviewSummary | null>(null);
  const [crLoading,    setCrLoading]    = useState(true);   // true by default — poll until done
  const [crTriggered,  setCrTriggered]  = useState(true);   // true by default — always show spinner
  const [crCompleted,  setCrCompleted]  = useState(false);
  const [crError,      setCrError]      = useState<string | null>(null);
  const [crCatFilter,  setCrCatFilter]  = useState<string>("ALL");
  const [crExpanded,   setCrExpanded]   = useState<Set<string>>(new Set());
  const [crProgress,   setCrProgress]   = useState<{
    pct: number; files_done: number; total_files: number;
    current_file: string | null; findings_count: number;
  } | null>(null);
  const [crQueued,     setCrQueued]     = useState(true);  // true = waiting for SAST/Secrets/SCA
  const crPollRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // FP Challenger state
  const [fpLoading,    setFpLoading]    = useState(false);
  const [fpTriggered,  setFpTriggered]  = useState(false);
  const [fpCompleted,  setFpCompleted]  = useState(false);
  const [fpError,      setFpError]      = useState<string | null>(null);
  const [fpProgress,   setFpProgress]   = useState<{
    pct: number; findings_done: number; findings_total: number;
    fp_found: number; current_finding: string | null;
  } | null>(null);

  // Secrets state
  const [secretFindings,  setSecretFindings]  = useState<SecretFinding[]>([]);
  const [secretSummary,   setSecretSummary]   = useState<SecretSummary | null>(null);
  const [secretExpanded,  setSecretExpanded]  = useState<Set<string>>(new Set());
  const [secretScanning,  setSecretScanning]  = useState(true);

  // Dependencies state
  const [depFindings,  setDepFindings]  = useState<DependencyFinding[]>([]);
  const [depSummary,   setDepSummary]   = useState<DependencySummary | null>(null);
  const [depEcoFilter, setDepEcoFilter] = useState<string>("ALL");
  const [depExpanded,  setDepExpanded]  = useState<Set<string>>(new Set());
  const [depScanning,  setDepScanning]  = useState(true);

  // Code Knowledge Graph build state (fires at scan start in parallel)
  const [graphBuildStatus,  setGraphBuildStatus]  = useState<"idle" | "building" | "done" | "failed">("idle");
  const [graphBuildError,   setGraphBuildError]   = useState<string | null>(null);
  const [graphBuildElapsed, setGraphBuildElapsed] = useState(0);
  const graphPollRef    = useRef<ReturnType<typeof setInterval> | null>(null);
  const graphElapsedRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // ---------------------------------------------------------------------------
  // Data loading — initial fetch + polling for parallel agents
  // ---------------------------------------------------------------------------
  useEffect(() => {
    // Reset ALL agent state for the new runId
    setSastDone(false);
    setSecretScanning(true);
    setDepScanning(true);
    setSecretFindings([]);
    setDepFindings([]);
    setCrFindings([]);
    setCrSummary(null);
    setCrLoading(true);      // Always start loading — same as secrets/SCA
    setCrTriggered(true);    // Always show spinner — don't wait for "detection"
    setCrCompleted(false);
    setCrError(null);
    setCrProgress(null);
    setCrQueued(true);
    setFindings([]);
    setGraphBuildStatus("idle");
    setGraphBuildError(null);
    setGraphBuildElapsed(0);
    setFpTriggered(false);
    setFpCompleted(false);
    setFpLoading(false);
    setFpError(null);
    setFpProgress(null);

    // ── Code review polling ──────────────────────────────────────────────────
    // Polls every 5s. Status responses:
    //   "not_started" → SAST still running, keep waiting (spinner stays)
    //   "running"     → update progress bar
    //   "completed"   → fetch findings, mark done
    //   "failed"      → show error + retry button
    // After 20 min of "not_started" with no change → show manual trigger button.
    let crStalled = 0;
    const MAX_CR_STALLED = 240; // 240 × 5s = 20 min

    async function pollCr(): Promise<void> {
      try {
        const prog = await getCodeReviewProgress(runId);

        if (prog.status === "running") {
          crStalled = 0;
          setCrQueued(false);
          setCrProgress({
            pct: prog.pct, files_done: prog.files_done,
            total_files: prog.total_files, current_file: prog.current_file,
            findings_count: prog.findings_count,
          });
          crPollRef.current = setTimeout(pollCr, 5_000);
          return;
        }

        if (prog.status === "completed") {
          const cr = await getCodeReview(runId);
          if (cr.count > 0) { setCrFindings(cr.findings); setCrSummary(cr.summary); }
          setCrQueued(false);
          setCrCompleted(true);
          setCrLoading(false);
          waitForFpToStart();
          return;
        }

        if (prog.status === "failed") {
          setCrQueued(false);
          setCrError("Code review failed on the server. Check /tmp/app.log.");
          setCrLoading(false);
          return;
        }

        // "not_started" — SAST/Secrets/SCA still running, keep waiting
        setCrQueued(true);
        crStalled++;
        if (crStalled >= MAX_CR_STALLED) {
          // Something is genuinely wrong — let user trigger manually
          setCrTriggered(false);
          setCrLoading(false);
          return;
        }
        crPollRef.current = setTimeout(pollCr, 5_000);
      } catch {
        crPollRef.current = setTimeout(pollCr, 8_000);
      }
    }

    async function load() {
      const [f, s] = await Promise.all([getFindings(runId), getScanStatus(runId)]);
      setFindings(f);
      setStatus(s);
      setLoading(false);

      // Mark SAST done immediately if the workflow_run is already completed
      // (workflow_runs.state = 'completed' is set AFTER Semgrep + FP pipeline both finish)
      if (s.status === "completed" || s.status === "failed") {
        setSastDone(true);
      } else {
        // Poll until SAST workflow completes — updates findings count and files_scanned too
        pollSastStatus();
      }

      // Check FP Challenger status
      try {
        const fp = await getFpChallengeProgress(runId);
        if (fp.status === "completed") {
          setFpTriggered(true);
          setFpCompleted(true);
          setFpProgress(fp);
          const refreshed = await getFindings(runId);
          setFindings(refreshed);
        } else if (fp.status === "running") {
          startFpPolling();
        } else if (fp.status === "failed") {
          setFpTriggered(true);
          setFpError("FP challenge failed. Check server logs.");
        }
      } catch { /* not started yet */ }

      loadSecrets(0, s);
      loadDeps(0, s);
      startGraphBuildPolling(s.scan_path);

      // Start code review polling immediately — same as secrets/SCA
      pollCr();
    }

    // Poll workflow_runs.state every 10s until SAST (including FP pipeline) is done.
    // The response also carries per-agent completion flags (agents.secrets_done / sca_done)
    // written by each workflow independently — so we can stop those spinners without
    // waiting for the full SAST pipeline to finish.
    async function pollSastStatus(retries = 0) {
      const MAX_RETRIES = 120; // 120 × 10s = 20 min
      if (retries >= MAX_RETRIES) {
        setSastDone(true);
        setSecretScanning(false);
        setDepScanning(false);
        return;
      }
      try {
        const s = await getScanStatus(runId);
        setStatus(s);

        // Stop individual agent spinners as soon as their workflow writes completed_at
        // to workflow_runs.metadata — happens within seconds of each agent finishing,
        // independent of the SAST FP pipeline which can run for 30+ minutes.
        if (s.agents?.secrets_done) setSecretScanning(false);
        if (s.agents?.sca_done)     setDepScanning(false);
        if (s.agents?.reachability_done) {
          // Refresh deps to pick up reachability verdicts
          try {
            const dep = await getDependencyFindings(runId);
            if (dep.count > 0) { setDepFindings(dep.findings); setDepSummary(dep.summary); }
          } catch { /* ignore */ }
        }

        if (s.status === "completed" || s.status === "failed") {
          setSastDone(true);
          // Refresh SAST findings — the final count is now accurate
          const refreshed = await getFindings(runId);
          setFindings(refreshed);
          // Final check for any late-arriving secrets/deps findings
          try {
            const sec = await getSecretFindings(runId);
            if (sec.count > 0) { setSecretFindings(sec.findings); setSecretSummary(sec.summary); }
          } catch { /* ignore */ }
          setSecretScanning(false);
          try {
            const dep = await getDependencyFindings(runId);
            if (dep.count > 0) { setDepFindings(dep.findings); setDepSummary(dep.summary); }
          } catch { /* ignore */ }
          setDepScanning(false);

          // Reachability runs in parallel and may still be in progress when SAST
          // completes. Keep polling until reachability_done is also true.
          if (!s.agents?.reachability_done) {
            setTimeout(() => pollSastStatus(retries + 1), 10_000);
          }
          return;
        }
      } catch { /* ignore transient errors */ }
      setTimeout(() => pollSastStatus(retries + 1), 10_000);
    }

    // -------------------------------------------------------------------------
    // Graph build polling — tracks the background build fired at scan start
    // -------------------------------------------------------------------------
    async function startGraphBuildPolling(fallbackPath?: string) {
      const path: string | undefined = scanPath || fallbackPath;
      if (!path) return;

      const MAX_POLLS = 60; // 60 × 4s = 4 minutes max, then give up
      let polls = 0;

      async function checkStatus() {
        try {
          const r = await fetch(
            `/api/v1/graph/build/status?scan_path=${encodeURIComponent(path as string)}`
          );
          if (!r.ok) return;
          const d = await r.json();

          if (d.status === "building") {
            // Start elapsed ticker once we confirm build is actually running
            setGraphBuildStatus("building");
            if (!graphElapsedRef.current) {
              graphElapsedRef.current = setInterval(
                () => setGraphBuildElapsed(s => s + 1), 1000
              );
            }
          } else if (d.status === "done" || (d.status === "idle" && d.graph_exists)) {
            stopGraphPolling();
            setGraphBuildStatus("done");
          } else if (d.status === "failed") {
            stopGraphPolling();
            setGraphBuildStatus("failed");
            setGraphBuildError(d.error ?? "Graph build failed — check server logs.");
          } else {
            // idle + no graph: build not started or server restarted
            // keep waiting up to MAX_POLLS, then stop silently (show nothing)
            polls++;
            if (polls >= MAX_POLLS) stopGraphPolling();
          }
        } catch { /* network blip — keep polling */ }
      }

      // Check immediately, then every 4s
      await checkStatus();
      graphPollRef.current = setInterval(checkStatus, 4000);
    }

    function stopGraphPolling() {
      if (graphPollRef.current)    { clearInterval(graphPollRef.current);    graphPollRef.current    = null; }
      if (graphElapsedRef.current) { clearInterval(graphElapsedRef.current); graphElapsedRef.current = null; }
    }

    async function loadSecrets(retries = 0, scanState?: ScanStatus) {
      // Secrets runs in parallel with SCA/Code Review AFTER SAST completes.
      // For historical scans (completed_at > 5 min ago) all agents are long done —
      // stop immediately if there are no findings instead of spinning for 150s.
      const MAX_RETRIES = 30; // 30 × 5s = 150s absolute max for live scans
      try {
        const sec = await getSecretFindings(runId);
        if (sec.count > 0) {
          setSecretFindings(sec.findings);
          setSecretSummary(sec.summary);
          setSecretScanning(false);
          return;
        }
        // On first check: if this is a historical scan, stop immediately
        if (retries === 0 && scanState?.completed_at) {
          const ageMs = Date.now() - new Date(scanState.completed_at).getTime();
          if (ageMs > 5 * 60 * 1000) { // > 5 min old → historical scan, agents done
            setSecretScanning(false);
            return;
          }
        }
        if (retries < MAX_RETRIES) {
          setTimeout(() => loadSecrets(retries + 1, scanState), 5000);
        } else {
          setSecretScanning(false);  // give up — no secrets found
        }
      } catch {
        if (retries < MAX_RETRIES) {
          setTimeout(() => loadSecrets(retries + 1, scanState), 5000);
        } else {
          setSecretScanning(false);
        }
      }
    }

    async function loadDeps(retries = 0, scanState?: ScanStatus) {
      // SCA runs in parallel with Secrets/Code Review AFTER SAST completes.
      // For historical scans (completed_at > 5 min ago) all agents are long done —
      // stop immediately if there are no findings instead of spinning for 150s.
      const MAX_RETRIES = 30; // 30 × 5s = 150s absolute max for live scans
      try {
        const dep = await getDependencyFindings(runId);
        if (dep.count > 0) {
          setDepFindings(dep.findings);
          setDepSummary(dep.summary);
          setDepScanning(false);
          return;
        }
        // On first check: if this is a historical scan, stop immediately
        if (retries === 0 && scanState?.completed_at) {
          const ageMs = Date.now() - new Date(scanState.completed_at).getTime();
          if (ageMs > 5 * 60 * 1000) { // > 5 min old → historical scan, agents done
            setDepScanning(false);
            return;
          }
        }
        if (retries < MAX_RETRIES) {
          setTimeout(() => loadDeps(retries + 1, scanState), 5000);
        } else {
          setDepScanning(false);
        }
      } catch {
        if (retries < MAX_RETRIES) {
          setTimeout(() => loadDeps(retries + 1, scanState), 5000);
        } else {
          setDepScanning(false);
        }
      }
    }

    load();

    return () => {
      if (graphPollRef.current)    clearInterval(graphPollRef.current);
      if (graphElapsedRef.current) clearInterval(graphElapsedRef.current);
      if (crPollRef.current)       clearTimeout(crPollRef.current);
    };
  }, [runId]);

  // ---------------------------------------------------------------------------
  // Code review trigger + progress polling
  // ---------------------------------------------------------------------------
  // Manual re-trigger (shown only after 20 min of no activity, or on error retry)
  async function handleRunCodeReview() {
    setCrError(null);
    setCrCompleted(false);
    setCrProgress(null);
    setCrLoading(true);
    setCrTriggered(true);
    if (crPollRef.current) clearTimeout(crPollRef.current);
    try {
      await triggerCodeReview(runId);
    } catch (err) {
      setCrError(`Failed to start code review: ${err instanceof Error ? err.message : "server error"}. Is the server running?`);
      setCrLoading(false);
      return;
    }
    // Let the existing pollCr loop in useEffect handle progress — but since
    // that loop already exited (stalled), schedule one more immediate check
    // by reloading the page state — simplest: just re-trigger the poll via ref
    setTimeout(async () => {
      try {
        const prog = await getCodeReviewProgress(runId);
        if (prog.status === "running" || prog.status === "not_started") {
          // Back to normal polling — reload the component will restart useEffect
          // For now just update state
        }
      } catch { /* ignore */ }
    }, 2000);
  }

  // ---------------------------------------------------------------------------
  // FP Challenger progress polling
  // ---------------------------------------------------------------------------
  async function waitForFpToStart(retries = 0) {
    const MAX_FP_WAIT = 18; // 18 × 10s = 3 minutes
    if (retries >= MAX_FP_WAIT) return;
    try {
      const fp = await getFpChallengeProgress(runId);
      if (fp.status === "running")   { startFpPolling(); return; }
      if (fp.status === "completed") { setFpTriggered(true); setFpCompleted(true); setFpProgress(fp); getFindings(runId).then(setFindings).catch(() => {}); return; }
      if (fp.status === "failed")    { setFpTriggered(true); setFpError("FP challenge failed. Check /tmp/app.log."); return; }
    } catch { /* not started yet */ }
    setTimeout(() => waitForFpToStart(retries + 1), 10_000);
  }

  function startFpPolling() {
    setFpLoading(true);
    setFpTriggered(true);
    let stalePct = -1;
    let staleCount = 0;
    const MAX_STALE_POLLS = 20;

    const poll = async () => {
      try {
        const prog = await getFpChallengeProgress(runId);
        setFpProgress({ pct: prog.pct, findings_done: prog.findings_done,
          findings_total: prog.findings_total, fp_found: prog.fp_found,
          current_finding: prog.current_finding });

        if (prog.status === "completed") {
          setFpCompleted(true);
          setFpLoading(false);
          // Reload SAST findings — verdict/fp_category/reasoning are now populated
          getFindings(runId).then(setFindings).catch(() => {});
          return;
        }
        if (prog.status === "failed") {
          setFpError("FP challenge failed on the server. Check /tmp/app.log.");
          setFpLoading(false);
          return;
        }
        if (prog.pct === stalePct) { staleCount++; } else { stalePct = prog.pct; staleCount = 0; }
        if (staleCount >= MAX_STALE_POLLS) {
          setFpError(`FP challenge appears stuck at ${prog.pct}%. Check /tmp/app.log.`);
          setFpLoading(false);
          return;
        }
        setTimeout(poll, 6000);
      } catch { setTimeout(poll, 8000); }
    };
    setTimeout(poll, 4000);
  }

  // ---------------------------------------------------------------------------
  // Derived data — combined counts from ALL agents for chart + filter
  // ---------------------------------------------------------------------------
  const allSevCounts: Record<string, number> = {};
  for (const f of findings)       allSevCounts[f.severity] = (allSevCounts[f.severity] ?? 0) + 1;
  for (const f of depFindings)    allSevCounts[f.severity] = (allSevCounts[f.severity] ?? 0) + 1;
  for (const f of secretFindings) allSevCounts[f.severity] = (allSevCounts[f.severity] ?? 0) + 1;
  for (const f of crFindings)     allSevCounts[f.severity] = (allSevCounts[f.severity] ?? 0) + 1;

  const totalAllFindings =
    findings.length + depFindings.length + secretFindings.length + crFindings.length;

  const pieData = Object.entries(allSevCounts).map(([name, value]) => ({ name, value }));

  // Severity filter applies to whichever tab is active
  const filteredSast    = sevFilter === "ALL" ? findings       : findings.filter(f       => f.severity === sevFilter);
  const filteredSecrets = sevFilter === "ALL" ? secretFindings : secretFindings.filter(f => f.severity === sevFilter);
  const filteredDeps    = sevFilter === "ALL" ? depFindings    : depFindings.filter(f    => f.severity === sevFilter);
  const filteredCr      = sevFilter === "ALL" ? crFindings     : crFindings.filter(f     => f.severity === sevFilter);

  // Secondary filters within tabs
  const filteredDepsFinal = depEcoFilter === "ALL" ? filteredDeps : filteredDeps.filter(f => f.ecosystem === depEcoFilter);
  const filteredCrFinal   = crCatFilter  === "ALL" ? filteredCr  : filteredCr.filter(f  => f.category  === crCatFilter);

  // Count for filter buttons — reflect active tab's data
  function tabSevCount(sev: string): number {
    if (sev === "ALL") {
      if (activeTab === "sast")    return findings.length;
      if (activeTab === "secrets") return secretFindings.length;
      if (activeTab === "deps")    return depFindings.length;
      if (activeTab === "review")  return crFindings.length;
    }
    if (activeTab === "sast")    return findings.filter(f       => f.severity === sev).length;
    if (activeTab === "secrets") return secretFindings.filter(f => f.severity === sev).length;
    if (activeTab === "deps")    return depFindings.filter(f    => f.severity === sev).length;
    if (activeTab === "review")  return crFindings.filter(f     => f.severity === sev).length;
    return 0;
  }

  function toggleExpand(id: string) {
    setExpanded(p => { const n = new Set(p); n.has(id) ? n.delete(id) : n.add(id); return n; });
  }
  function toggleCrExpand(id: string) {
    setCrExpanded(p => { const n = new Set(p); n.has(id) ? n.delete(id) : n.add(id); return n; });
  }

  const cov = status?.scan_coverage;

  // Are any parallel agents still running?
  const agentsRunning = depScanning || secretScanning || graphBuildStatus === "building"
    || crLoading || (fpTriggered && !fpCompleted && !fpError);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center text-gray-500">
        <span className="animate-pulse">Loading results…</span>
      </div>
    );
  }

  return (
    <div className="min-h-screen p-6 max-w-7xl mx-auto space-y-6">

      {/* ── Header ── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-white">Scan Results</h1>
          <p className="text-xs text-gray-500 mt-0.5 truncate max-w-xl">{status?.scan_path}</p>
        </div>
        <motion.button
          onClick={onNewScan}
          whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}
          className="flex items-center gap-2 px-4 py-2 rounded-lg border border-gray-700
                     text-sm text-gray-300 hover:text-white hover:border-gray-500 transition-colors"
        >
          <RotateCcw className="w-4 h-4" /> New Scan
        </motion.button>
      </div>

      {/* ── Agent status panel — always visible once results load ── */}
      {!loading && (
        <div className="rounded-xl bg-gray-900 border border-gray-700/60 p-5">
          <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-1 flex items-center gap-2">
            {agentsRunning
              ? <><Loader2 className="w-3.5 h-3.5 animate-spin text-brand-500" /> Security Pipeline in Progress</>
              : <><CheckCheck className="w-3.5 h-3.5 text-green-400" /> Security Pipeline Complete</>
            }
          </p>
          <p className="text-xs text-gray-600 mb-4">Click an agent to view its findings</p>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-4">

            {/* SAST */}
            <AgentStatusCard
              label="SAST Scanner"
              icon={<ShieldAlert className="w-4 h-4" />}
              color="text-orange-400"
              done={sastDone}
              count={findings.length}
              unit="findings"
              skills={["SQL Injection", "XSS", "Path Traversal", "CSRF", "Deserialization", "Weak Crypto"]}
              active={activeTab === "sast"}
              onClick={() => setActiveTab("sast")}
            />

            {/* Secret Scanner */}
            <AgentStatusCard
              label="Secret Scanner"
              icon={<Key className="w-4 h-4" />}
              color="text-yellow-400"
              done={!secretScanning}
              count={secretFindings.length}
              unit="secrets"
              skills={["API Keys", "Private Keys", "Tokens", "Passwords", "Certificates"]}
              active={activeTab === "secrets"}
              onClick={() => setActiveTab("secrets")}
            />

            {/* SCA */}
            <AgentStatusCard
              label="SCA (Dependencies)"
              icon={<Package className="w-4 h-4" />}
              color="text-red-400"
              done={!depScanning}
              count={depFindings.length}
              unit="CVEs"
              skills={["Known CVEs", "Outdated Packages", "License Risks", "Supply Chain"]}
              active={activeTab === "deps"}
              onClick={() => setActiveTab("deps")}
            />

            {/* Reachability */}
            <AgentStatusCard
              label="Reachability"
              icon={<Network className="w-4 h-4" />}
              color="text-cyan-400"
              done={!!status?.agents?.reachability_done}
              count={depFindings.filter(f => f.reachability && f.reachability !== 'UNKNOWN').length}
              unit="analysed"
              skills={["Import Scan", "JAR Bytecode", "Transitive Chain", "LLM Verdict"]}
              notStarted={!status?.agents?.sca_done}
              active={activeTab === "deps"}
              onClick={() => setActiveTab("deps")}
            />

            {/* Code Review */}
            <AgentStatusCard
              label="Code Review"
              icon={<Brain className="w-4 h-4" />}
              color="text-purple-400"
              done={crCompleted && !crError}
              count={crFindings.length}
              unit="issues"
              skills={["Logic Flaws", "Auth Gaps", "N+1 Queries", "Resource Leaks", "Error Handling"]}
              notStarted={crQueued}
              progress={crLoading && !crQueued && crProgress ? crProgress.pct : undefined}
              error={!!crError}
              active={activeTab === "review"}
              onClick={() => setActiveTab("review")}
            />

            {/* FP Challenger */}
            <AgentStatusCard
              label="FP Challenger"
              icon={<CheckCheck className="w-4 h-4" />}
              color="text-emerald-400"
              done={fpCompleted && !fpError}
              count={fpProgress?.fp_found ?? 0}
              unit="FPs found"
              subtitle={fpCompleted && fpProgress ? `${fpProgress.findings_total} reviewed` : undefined}
              skills={["FP Detection", "Confidence Scoring", "Context Analysis", "Verdict Re-evaluation"]}
              notStarted={!fpTriggered}
              progress={fpLoading ? fpProgress?.pct : undefined}
              error={!!fpError}
              active={false}
              onClick={() => {}}
            />

            {/* Code Knowledge Graph */}
            <GraphBuildCard
              status={graphBuildStatus}
              elapsed={graphBuildElapsed}
              error={graphBuildError}
            />
          </div>
        </div>
      )}

      {/* ── Unified summary cards ── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <SummaryCard label="Files Scanned"    value={cov?.files_scanned ?? 0}          color="text-brand-500" />
        <SummaryCard label="SAST Findings"    value={findings.length}                   color="text-orange-400" />
        <SummaryCard label="Vulnerable Deps"  value={depSummary?.total ?? depFindings.length}
          color={depFindings.length > 0 ? "text-red-400" : "text-gray-500"}
          loading={depScanning} />
        <SummaryCard label="Secrets Found"    value={secretSummary?.total ?? secretFindings.length}
          color={secretFindings.length > 0 ? "text-yellow-400" : "text-gray-500"}
          loading={secretScanning} />
      </div>

      {/* ── Chart + filter row ── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

        {/* Pie chart — all agents combined */}
        <div className="rounded-xl bg-gray-900 border border-gray-700/60 p-5 lg:col-span-1">
          <h3 className="text-sm font-medium text-gray-400 mb-1 flex items-center gap-2">
            <ShieldAlert className="w-4 h-4" /> All Findings by Severity
          </h3>
          <p className="text-xs text-gray-600 mb-4">
            SAST + Secrets + Dependencies + Code Review ({totalAllFindings} total)
          </p>
          {pieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%" cy="50%"
                  innerRadius={50} outerRadius={80}
                  paddingAngle={3} dataKey="value"
                >
                  {pieData.map((entry) => (
                    <Cell key={entry.name} fill={SEV_COLORS[entry.name] ?? "#6b7280"} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ background: "#111827", border: "1px solid #374151", borderRadius: 8 }}
                  labelStyle={{ color: "#f3f4f6" }}
                  itemStyle={{ color: "#d1d5db" }}
                />
                <Legend iconType="circle" iconSize={8} wrapperStyle={{ fontSize: 12, color: "#9ca3af" }} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <p className="text-center text-gray-600 text-sm py-10">No findings yet</p>
          )}
        </div>

        {/* Severity filter + scan meta */}
        <div className="lg:col-span-2 space-y-4">
          <div className="rounded-xl bg-gray-900 border border-gray-700/60 p-5">
            <h3 className="text-sm font-medium text-gray-400 mb-1">Filter by Severity</h3>
            <p className="text-xs text-gray-600 mb-3">
              Filters the active tab — counts show findings in current tab
            </p>
            <div className="flex flex-wrap gap-2">
              {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => {
                const count = tabSevCount(s);
                const active = sevFilter === s;
                return (
                  <button
                    key={s}
                    onClick={() => setSevFilter(s)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all ${
                      active
                        ? "bg-brand-600 border-brand-500 text-white"
                        : "bg-gray-800 border-gray-700 text-gray-400 hover:border-gray-500"
                    }`}
                  >
                    {s} ({count})
                  </button>
                );
              })}
            </div>

            {/* Per-severity breakdown from all agents */}
            {totalAllFindings > 0 && (
              <div className="mt-4 grid grid-cols-4 gap-2">
                {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map(sev => {
                  const n = allSevCounts[sev] ?? 0;
                  if (n === 0) return null;
                  return (
                    <button
                      key={sev}
                      onClick={() => setSevFilter(sev)}
                      className={`rounded-lg px-2 py-1.5 text-center border transition-all ${
                        sevFilter === sev ? "border-brand-500" : "border-gray-700/60 hover:border-gray-500"
                      }`}
                      style={{ background: (SEV_COLORS[sev] ?? "#6b7280") + "18" }}
                    >
                      <p className="text-xs font-semibold" style={{ color: SEV_COLORS[sev] }}>{sev}</p>
                      <p className="text-lg font-bold text-white tabular-nums">{n}</p>
                      <p className="text-xs text-gray-500">all agents</p>
                    </button>
                  );
                })}
              </div>
            )}
          </div>

          {/* Scan meta */}
          {cov && (
            <div className="rounded-xl bg-gray-900 border border-gray-700/60 p-5 grid grid-cols-2 gap-3 text-xs">
              <div className="text-gray-500">Scan duration</div>
              <div className="text-gray-300 text-right">
                {cov.scan_duration_ms > 0 ? `${(cov.scan_duration_ms / 1000).toFixed(1)}s` : "—"}
              </div>
              <div className="text-gray-500">Files skipped</div>
              <div className="text-gray-300 text-right">{cov.files_skipped}</div>
              <div className="text-gray-500">Run ID</div>
              <div className="text-gray-400 text-right font-mono truncate">{runId}</div>
            </div>
          )}
        </div>
      </div>

      {/* ══════════════════════════════════════════════════
          TAB CONTENT
      ══════════════════════════════════════════════════ */}

      {/* SAST Findings tab */}
      {activeTab === "sast" && (
        <div className="space-y-3">
          <h2 className="text-sm font-medium text-gray-400 uppercase tracking-wide">
            SAST Findings — {filteredSast.length}
            {sevFilter !== "ALL" && <span className="text-gray-600 normal-case ml-1">(filtered: {sevFilter})</span>}
          </h2>
          {filteredSast.length === 0 && (
            <div className="rounded-xl bg-gray-900 border border-gray-700/60 p-10 text-center text-gray-600">
              No findings match the current filter.
            </div>
          )}
          {filteredSast.map((f) => {
            const open = expanded.has(f.id);
            return (
              <motion.div key={f.id} layout initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
                className="rounded-xl bg-gray-900 border border-gray-700/60 overflow-hidden">
                <button
                  className="w-full text-left px-5 py-4 flex items-start gap-4 hover:bg-gray-800/40 transition-colors"
                  onClick={() => toggleExpand(f.id)}
                >
                  <div className="mt-0.5 shrink-0"><SeverityBadge severity={f.severity} /></div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm font-medium text-white truncate">{f.rule_id}</span>
                      {f.cwe_id && (
                        <span className="text-xs text-gray-500 bg-gray-800 border border-gray-700 px-1.5 py-0.5 rounded">
                          {f.cwe_id}
                        </span>
                      )}
                      {f.owasp_category && (
                        <span className="text-xs text-purple-400 bg-purple-900/20 border border-purple-700/40 px-1.5 py-0.5 rounded">
                          {f.owasp_category}
                        </span>
                      )}
                      {(f.blast_radius ?? 0) > 0 && (
                        <span className="text-xs text-orange-300 bg-orange-500/10 border border-orange-500/40 px-1.5 py-0.5 rounded flex items-center gap-1">
                          <TrendingUp className="w-3 h-3" />
                          Called by {f.blast_radius} file{f.blast_radius === 1 ? "" : "s"}
                        </span>
                      )}
                      {/* AI verdict badge — shown as soon as data available, from SAST L3 or FP Challenger */}
                      {f.verdict === "FP" && (
                        <span className="text-xs text-emerald-300 bg-emerald-500/10 border border-emerald-500/40 px-1.5 py-0.5 rounded flex items-center gap-1"
                          title={f.reasoning ?? undefined}>
                          <CheckCheck className="w-3 h-3" />
                          False Positive{f.fp_category ? ` · ${f.fp_category}` : ""}
                        </span>
                      )}
                      {f.verdict === "REAL" && (
                        <span className="text-xs text-red-300 bg-red-500/10 border border-red-500/40 px-1.5 py-0.5 rounded flex items-center gap-1"
                          title={f.reasoning ?? undefined}>
                          <ShieldAlert className="w-3 h-3" />
                          Confirmed Real
                          {f.confidence != null && <span className="opacity-60">· {Math.round(f.confidence * 100)}%</span>}
                        </span>
                      )}
                      {f.verdict === "ESCALATED" && (
                        <span className="text-xs text-yellow-300 bg-yellow-500/10 border border-yellow-500/40 px-1.5 py-0.5 rounded flex items-center gap-1">
                          <AlertTriangle className="w-3 h-3" />
                          Needs Review
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-gray-400 mt-1 line-clamp-2">{f.message}</p>
                    <div className="flex items-center gap-3 mt-1.5 text-xs text-gray-600">
                      <span className="flex items-center gap-1">
                        <FileCode className="w-3 h-3" />
                        {f.file_path.split("/").slice(-2).join("/")}:{f.line_start}
                      </span>
                      {f.class_name  && <span>Class: <span className="text-gray-400">{f.class_name}</span></span>}
                      {f.method_name && <span>Method: <span className="text-gray-400">{f.method_name}()</span></span>}
                    </div>
                  </div>
                  <div className="shrink-0 text-gray-600 mt-1">
                    {open ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                  </div>
                </button>
                <AnimatePresence initial={false}>
                  {open && (
                    <motion.div key="detail" initial={{ height: 0, opacity: 0 }} animate={{ height: "auto", opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.2 }} className="overflow-hidden">
                      <div className="px-5 pb-5 border-t border-gray-700/60 pt-4 space-y-4">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                          <div>
                            <p className="text-gray-500 uppercase tracking-wide mb-1">File</p>
                            <p className="text-gray-300 font-mono break-all">{f.file_path}</p>
                            <p className="text-gray-500 mt-1">
                              Lines {f.line_start}{f.line_end && f.line_end !== f.line_start ? `–${f.line_end}` : ""}
                            </p>
                          </div>
                          <div className="grid grid-cols-2 gap-3">
                            {f.likelihood && (
                              <div>
                                <p className="text-gray-500 flex items-center gap-1"><TrendingUp className="w-3 h-3" /> Likelihood</p>
                                <p className="text-gray-300 mt-1">{f.likelihood}</p>
                              </div>
                            )}
                            {f.impact && (
                              <div>
                                <p className="text-gray-500">Impact</p>
                                <p className="text-gray-300 mt-1">{f.impact}</p>
                              </div>
                            )}
                            {(f.blast_radius ?? 0) > 0 && (
                              <div>
                                <p className="text-gray-500 flex items-center gap-1"><TrendingUp className="w-3 h-3 text-orange-400" /> Blast Radius</p>
                                <p className="text-orange-300 mt-1 font-semibold">{f.blast_radius} caller{f.blast_radius === 1 ? "" : "s"}</p>
                                <p className="text-gray-600 mt-0.5">files that call into this file</p>
                              </div>
                            )}
                            {f.framework && f.framework !== "unknown" && (
                              <div>
                                <p className="text-gray-500">Framework</p>
                                <p className="text-gray-300 mt-1">{f.framework}</p>
                              </div>
                            )}
                          </div>
                        </div>
                        {f.code_snippet && (
                          <div>
                            <p className="text-xs text-gray-500 uppercase tracking-wide mb-2 flex items-center gap-1">
                              <FileCode className="w-3 h-3" /> Vulnerable Code
                            </p>
                            <CodeBlock snippet={f.code_snippet} />
                          </div>
                        )}
                        {f.fix_suggestion && (
                          <div>
                            <p className="text-xs text-gray-500 uppercase tracking-wide mb-2 flex items-center gap-1">
                              <Wrench className="w-3 h-3" /> How to Fix
                            </p>
                            <div className="rounded-lg bg-green-950/30 border border-green-800/40 px-4 py-3 text-sm text-green-300">
                              {f.fix_suggestion}
                            </div>
                          </div>
                        )}
                        {/* AI verdict detail panel */}
                        {f.verdict && (
                          <div className={`rounded-lg border px-4 py-3 text-sm ${
                            f.verdict === "FP"
                              ? "bg-emerald-950/30 border-emerald-700/40 text-emerald-300"
                              : f.verdict === "REAL"
                              ? "bg-red-950/20 border-red-700/40 text-red-300"
                              : "bg-yellow-950/20 border-yellow-700/40 text-yellow-300"
                          }`}>
                            <p className="flex items-center gap-1.5 font-medium mb-1 flex-wrap">
                              <Brain className="w-3.5 h-3.5 shrink-0" />
                              <span className="opacity-60 text-xs font-normal">
                                {f.fp_source === "fp_challenger" ? "FP Challenger" : "AI Analysis"}
                              </span>
                              <span>→</span>
                              <span className="font-semibold">{f.verdict}</span>
                              {f.fp_category && <span className="font-normal text-xs opacity-75">· {f.fp_category}</span>}
                              {f.confidence != null && (
                                <span className="ml-auto text-xs opacity-60">
                                  confidence {Math.round(f.confidence * 100)}%
                                </span>
                              )}
                            </p>
                            {f.reasoning && <p className="text-xs opacity-80 mt-1 leading-relaxed">{f.reasoning}</p>}
                          </div>
                        )}

                        {Array.isArray(f.ref_urls) && f.ref_urls.length > 0 && (
                          <div>
                            <p className="text-xs text-gray-500 uppercase tracking-wide mb-2 flex items-center gap-1">
                              <BookOpen className="w-3 h-3" /> References
                            </p>
                            <div className="flex flex-wrap gap-2">
                              {f.ref_urls.map((url) => (
                                <a key={url} href={url} target="_blank" rel="noopener noreferrer"
                                  className="flex items-center gap-1 text-xs text-brand-500 hover:text-brand-400
                                             bg-gray-800 border border-gray-700 px-2 py-1 rounded transition-colors">
                                  <ExternalLink className="w-3 h-3" />
                                  {url.replace(/^https?:\/\/(www\.)?/, "").split("/")[0]}
                                </a>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </motion.div>
            );
          })}
        </div>
      )}

      {/* Secrets tab */}
      {activeTab === "secrets" && (
        <div className="space-y-4">
          {secretScanning && secretFindings.length === 0 ? (
            <AgentInProgress label="Secret Scanner" color="yellow" description="Scanning source files for hardcoded credentials, tokens, and high-entropy strings…" />
          ) : secretFindings.length === 0 ? (
            <div className="rounded-xl bg-gray-900 border border-gray-700/60 p-10 text-center">
              <Key className="w-8 h-8 text-gray-600 mx-auto mb-3" />
              <p className="text-gray-500 text-sm">No secrets detected in this scan.</p>
              <p className="text-gray-600 text-xs mt-1">Secret scanning runs automatically with each scan.</p>
            </div>
          ) : (
            <>
              {secretSummary && (
                <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
                  {[
                    { label: "Total",    value: secretSummary.total,              color: "text-white" },
                    { label: "Critical", value: secretSummary.critical,           color: "text-red-400" },
                    { label: "High",     value: secretSummary.high,               color: "text-orange-400" },
                    { label: "Medium",   value: secretSummary.medium,             color: "text-yellow-400" },
                    { label: "Files",    value: secretSummary.files_with_secrets, color: "text-purple-400" },
                  ].map(({ label, value, color }) => (
                    <div key={label} className="rounded-lg bg-gray-900 border border-gray-700/60 px-4 py-3">
                      <p className="text-xs text-gray-500 uppercase tracking-wide">{label}</p>
                      <p className={`text-2xl font-bold tabular-nums ${color}`}>{value}</p>
                    </div>
                  ))}
                </div>
              )}
              <div className="space-y-2">
                <h2 className="text-sm font-medium text-gray-400 uppercase tracking-wide">
                  Secrets — {filteredSecrets.length}
                  {sevFilter !== "ALL" && <span className="text-gray-600 normal-case ml-1">(filtered: {sevFilter})</span>}
                </h2>
                {filteredSecrets.length === 0 && (
                  <div className="rounded-xl bg-gray-900 border border-gray-700/60 p-6 text-center text-gray-600 text-sm">
                    No secrets at {sevFilter} severity.
                  </div>
                )}
                {filteredSecrets.map((f) => {
                  const open = secretExpanded.has(f.id);
                  return (
                    <motion.div key={f.id} layout initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }}
                      className="rounded-xl bg-gray-900 border border-gray-700/60 overflow-hidden">
                      <button
                        className="w-full text-left px-5 py-4 flex items-start gap-4 hover:bg-gray-800/40 transition-colors"
                        onClick={() => setSecretExpanded(p => { const n = new Set(p); n.has(f.id) ? n.delete(f.id) : n.add(f.id); return n; })}
                      >
                        <div className="mt-0.5 shrink-0"><SeverityBadge severity={f.severity} /></div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="text-sm font-medium text-white">
                              {f.secret_type.replace(/-/g, " ").replace(/\b\w/g, c => c.toUpperCase())}
                            </span>
                            {f.entropy !== null && (
                              <span className="text-xs text-gray-500 bg-gray-800 border border-gray-700 px-1.5 py-0.5 rounded">
                                entropy {f.entropy}
                              </span>
                            )}
                          </div>
                          <p className="text-xs text-gray-400 mt-1">{f.description}</p>
                          <div className="flex items-center gap-3 mt-1.5 text-xs text-gray-600">
                            <span className="flex items-center gap-1">
                              <FileCode className="w-3 h-3" />
                              {f.file_path.split("/").slice(-2).join("/")}{f.line_start ? `:${f.line_start}` : ""}
                            </span>
                          </div>
                        </div>
                        <div className="shrink-0 text-gray-600 mt-1">
                          {open ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                        </div>
                      </button>
                      <AnimatePresence initial={false}>
                        {open && (
                          <motion.div key="sec-detail" initial={{ height: 0, opacity: 0 }} animate={{ height: "auto", opacity: 1 }}
                            exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.2 }} className="overflow-hidden">
                            <div className="px-5 pb-5 border-t border-gray-700/60 pt-4 space-y-3 text-sm">
                              <div>
                                <p className="text-xs text-gray-500 uppercase tracking-wide mb-1">File</p>
                                <p className="text-gray-300 font-mono break-all text-xs">
                                  {f.file_path}{f.line_start ? `:${f.line_start}` : ""}
                                </p>
                              </div>
                              {f.match_preview && (
                                <div>
                                  <p className="text-xs text-gray-500 uppercase tracking-wide mb-1">Match (redacted)</p>
                                  <code className="text-xs text-red-300 bg-red-950/30 border border-red-800/40 px-3 py-1.5 rounded block">
                                    {f.match_preview}
                                  </code>
                                </div>
                              )}
                              {f.context_line && (
                                <div>
                                  <p className="text-xs text-gray-500 uppercase tracking-wide mb-1">Context</p>
                                  <code className="text-xs text-gray-300 bg-gray-800 px-3 py-1.5 rounded block break-all">
                                    {f.context_line}
                                  </code>
                                </div>
                              )}
                              <div className="rounded-lg bg-amber-950/30 border border-amber-800/40 px-4 py-3 text-xs text-amber-300">
                                Rotate this credential immediately. Remove from source code and use environment variables or a secrets manager (Vault, AWS Secrets Manager).
                              </div>
                            </div>
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </motion.div>
                  );
                })}
              </div>
            </>
          )}
        </div>
      )}

      {/* Dependencies tab */}
      {activeTab === "deps" && (
        <div className="space-y-4">
          {depScanning && depFindings.length === 0 ? (
            <AgentInProgress label="SCA Agent" color="red" description="Scanning requirements.txt, package.json, and pom.xml against the OSV vulnerability database…" />
          ) : depFindings.length === 0 ? (
            <div className="rounded-xl bg-gray-900 border border-gray-700/60 p-10 text-center">
              <Package className="w-8 h-8 text-gray-600 mx-auto mb-3" />
              <p className="text-gray-500 text-sm">No vulnerable dependencies found.</p>
              <p className="text-gray-600 text-xs mt-1">SCA scans requirements.txt, package.json, and pom.xml automatically.</p>
            </div>
          ) : (
            <>
              {depSummary && (
                <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                  {[
                    { label: "Total CVEs", value: depSummary.total,    color: "text-white" },
                    { label: "Critical",   value: depSummary.critical, color: "text-red-400" },
                    { label: "High",       value: depSummary.high,     color: "text-orange-400" },
                    { label: "Medium",     value: depSummary.medium,   color: "text-yellow-400" },
                  ].map(({ label, value, color }) => (
                    <div key={label} className="rounded-lg bg-gray-900 border border-gray-700/60 px-4 py-3">
                      <p className="text-xs text-gray-500 uppercase tracking-wide">{label}</p>
                      <p className={`text-2xl font-bold tabular-nums ${color}`}>{value}</p>
                    </div>
                  ))}
                </div>
              )}
              {/* Ecosystem filter */}
              <div className="flex gap-2 flex-wrap">
                {(["ALL", "python", "npm", "maven"] as const).map((eco) => {
                  const count = eco === "ALL" ? depFindings.length : depFindings.filter(f => f.ecosystem === eco).length;
                  const active = depEcoFilter === eco;
                  return (
                    <button key={eco} onClick={() => setDepEcoFilter(eco)}
                      className={`px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all ${
                        active ? "bg-brand-600 border-brand-500 text-white" : "bg-gray-800 border-gray-700 text-gray-400 hover:border-gray-500"
                      }`}>
                      {eco.toUpperCase()} ({count})
                    </button>
                  );
                })}
              </div>
              <div className="space-y-2">
                <h2 className="text-sm font-medium text-gray-400 uppercase tracking-wide">
                  Dependencies — {filteredDepsFinal.length}
                  {sevFilter !== "ALL" && <span className="text-gray-600 normal-case ml-1">(filtered: {sevFilter})</span>}
                </h2>
                {filteredDepsFinal.length === 0 && (
                  <div className="rounded-xl bg-gray-900 border border-gray-700/60 p-6 text-center text-gray-600 text-sm">
                    No vulnerable dependencies at {sevFilter} severity.
                  </div>
                )}
                {filteredDepsFinal.map((f) => {
                  const open = depExpanded.has(f.id);
                  return (
                    <motion.div key={f.id} layout initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }}
                      className="rounded-xl bg-gray-900 border border-gray-700/60 overflow-hidden">
                      <button
                        className="w-full text-left px-5 py-4 flex items-start gap-4 hover:bg-gray-800/40 transition-colors"
                        onClick={() => setDepExpanded(p => { const n = new Set(p); n.has(f.id) ? n.delete(f.id) : n.add(f.id); return n; })}
                      >
                        <div className="mt-0.5 shrink-0"><SeverityBadge severity={f.severity} /></div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="text-sm font-medium text-white font-mono">{f.package_name}</span>
                            <span className="text-xs text-gray-500 bg-gray-800 border border-gray-700 px-1.5 py-0.5 rounded">{f.ecosystem}</span>
                            <span className="text-xs text-red-400 bg-red-900/20 border border-red-700/40 px-1.5 py-0.5 rounded">{f.vulnerability_id}</span>
                            {f.reachability && (
                              <span className={`text-xs font-medium px-1.5 py-0.5 rounded border flex items-center gap-1 ${
                                f.reachability === 'REACHABLE' || f.reachability === 'LIKELY_REACHABLE'
                                  ? 'text-red-300 bg-red-500/10 border-red-500/30'
                                  : f.reachability === 'NOT_REACHABLE' || f.reachability === 'LIKELY_NOT_REACHABLE'
                                  ? 'text-green-300 bg-green-500/10 border-green-500/30'
                                  : 'text-gray-400 bg-gray-500/10 border-gray-500/30'
                              }`}>
                                {f.reachability === 'REACHABLE' ? '⚡ Reachable' :
                                 f.reachability === 'NOT_REACHABLE' ? '✓ Not Reachable' :
                                 f.reachability === 'LIKELY_REACHABLE' ? '~ Likely Reachable' :
                                 f.reachability === 'LIKELY_NOT_REACHABLE' ? '~ Likely Safe' : '? Unknown'}
                              </span>
                            )}
                          </div>
                          <p className="text-xs text-gray-400 mt-1 line-clamp-2">{f.description || "No description available."}</p>
                          <div className="flex items-center gap-3 mt-1.5 text-xs text-gray-600">
                            {f.installed_version && <span>Installed: <span className="text-red-400">{f.installed_version}</span></span>}
                            {f.fixed_version     && <span>Fix: <span className="text-green-400">{f.fixed_version}</span></span>}
                            {f.file_path         && <span className="flex items-center gap-1"><FileCode className="w-3 h-3" />{f.file_path}</span>}
                          </div>
                        </div>
                        <div className="shrink-0 text-gray-600 mt-1">
                          {open ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                        </div>
                      </button>
                      <AnimatePresence initial={false}>
                        {open && (
                          <motion.div key="dep-detail" initial={{ height: 0, opacity: 0 }} animate={{ height: "auto", opacity: 1 }}
                            exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.2 }} className="overflow-hidden">
                            <div className="px-5 pb-5 border-t border-gray-700/60 pt-4 space-y-3 text-sm">
                              <div className="grid grid-cols-2 gap-4 text-xs">
                                <div><p className="text-gray-500 mb-1">Package</p><p className="text-gray-300 font-mono">{f.package_name}</p></div>
                                <div><p className="text-gray-500 mb-1">Vulnerability ID</p><p className="text-red-400 font-mono">{f.vulnerability_id}</p></div>
                                {f.installed_version && <div><p className="text-gray-500 mb-1">Installed Version</p><p className="text-red-300">{f.installed_version}</p></div>}
                                {f.fixed_version     && <div><p className="text-gray-500 mb-1">Fixed In</p><p className="text-green-400">{f.fixed_version}</p></div>}
                              </div>
                              <div>
                                <p className="text-xs text-gray-500 uppercase tracking-wide mb-1">Description</p>
                                <p className="text-gray-300 text-sm leading-relaxed">
                                  {f.description || <span className="text-gray-600 italic">No description stored — see advisory link below.</span>}
                                </p>
                              </div>
                              {/* Advisory link — always show so user can get full CVE details */}
                              <div className="flex items-center gap-3 flex-wrap">
                                <a
                                  href={`https://osv.dev/vulnerability/${f.vulnerability_id}`}
                                  target="_blank" rel="noopener noreferrer"
                                  className="text-xs text-brand-400 hover:text-brand-300 underline flex items-center gap-1"
                                >
                                  View on OSV.dev ↗
                                </a>
                                {f.vulnerability_id.startsWith("CVE-") && (
                                  <a
                                    href={`https://nvd.nist.gov/vuln/detail/${f.vulnerability_id}`}
                                    target="_blank" rel="noopener noreferrer"
                                    className="text-xs text-brand-400 hover:text-brand-300 underline flex items-center gap-1"
                                  >
                                    View on NVD ↗
                                  </a>
                                )}
                                {f.vulnerability_id.startsWith("GHSA-") && (
                                  <a
                                    href={`https://github.com/advisories/${f.vulnerability_id}`}
                                    target="_blank" rel="noopener noreferrer"
                                    className="text-xs text-brand-400 hover:text-brand-300 underline flex items-center gap-1"
                                  >
                                    View on GitHub Advisory ↗
                                  </a>
                                )}
                              </div>
                              {f.fixed_version && (
                                <div className="rounded-lg bg-green-950/30 border border-green-800/40 px-4 py-3 text-xs text-green-300">
                                  <span className="font-semibold">Remediation:</span> Update <span className="font-mono">{f.package_name}</span> to version <span className="font-mono font-semibold">{f.fixed_version}</span> or later to fix this vulnerability.
                                </div>
                              )}
                              {!f.fixed_version && (
                                <div className="rounded-lg bg-yellow-950/20 border border-yellow-800/30 px-4 py-3 text-xs text-yellow-400">
                                  No fixed version available. Check the advisory for workarounds or consider replacing this dependency.
                                </div>
                              )}
                              {f.reach_evidence && (
                                <div>
                                  <p className="text-xs text-gray-500 uppercase tracking-wide mb-1">Reachability Evidence</p>
                                  <pre className="text-xs text-gray-300 bg-gray-800 rounded p-3 whitespace-pre-wrap leading-relaxed font-mono">
                                    {f.reach_evidence}
                                  </pre>
                                  {f.reach_source && (
                                    <p className="text-xs text-gray-600 mt-1">Source: {f.reach_source} · confidence {Math.round((f.reach_confidence ?? 0) * 100)}%</p>
                                  )}
                                </div>
                              )}
                            </div>
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </motion.div>
                  );
                })}
              </div>
            </>
          )}
        </div>
      )}

      {/* Code Review tab */}
      {activeTab === "review" && (
        <div className="space-y-4">
          {!crTriggered && (
            <div className="rounded-xl bg-gray-900 border border-gray-700/60 p-12 flex flex-col items-center gap-4">
              <div className="w-14 h-14 rounded-full bg-purple-500/10 border border-purple-500/30 flex items-center justify-center">
                <Brain className="w-7 h-7 text-purple-400" />
              </div>
              <div className="text-center">
                <h3 className="text-base font-semibold text-white">LLM Code Review</h3>
                <p className="text-sm text-gray-500 mt-1 max-w-md">
                  llama3.2:3b reviews every source file for security issues, performance problems,
                  code quality, error handling, and best practices beyond what Semgrep detects.
                </p>
              </div>
              <motion.button
                onClick={handleRunCodeReview}
                whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}
                className="flex items-center gap-2 px-6 py-2.5 rounded-lg bg-purple-600 hover:bg-purple-500
                           text-white text-sm font-medium transition-colors"
              >
                <PlayCircle className="w-4 h-4" /> Run Code Review
              </motion.button>
            </div>
          )}

          {/* Error state */}
          {crError && (
            <div className="rounded-xl bg-red-950/20 border border-red-700/40 p-5 flex items-start gap-3">
              <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
              <div className="flex-1 min-w-0">
                <p className="text-sm font-semibold text-red-300">Code Review Failed</p>
                <p className="text-xs text-gray-400 mt-1">{crError}</p>
                <p className="text-xs text-gray-600 mt-1">
                  Run <code className="text-gray-400 bg-gray-800 px-1 rounded">tail -f /tmp/app.log</code> in a terminal to see live logs.
                </p>
              </div>
              <button
                onClick={handleRunCodeReview}
                className="shrink-0 flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs
                           bg-gray-800 border border-gray-700 text-gray-300 hover:text-white
                           hover:border-gray-500 transition-colors"
              >
                <RotateCcw className="w-3 h-3" /> Retry
              </button>
            </div>
          )}

          {crTriggered && crLoading && crQueued && (
            <div className="rounded-xl bg-gray-900 border border-gray-700/60 p-8 space-y-3">
              <div className="flex items-center gap-3">
                <div className="w-2.5 h-2.5 rounded-full bg-purple-400/50 animate-pulse" />
                <p className="text-sm font-medium text-gray-400">Code Review queued</p>
              </div>
              <p className="text-xs text-gray-500">
                Waiting for SAST, Secrets and SCA agents to complete before starting file review…
              </p>
            </div>
          )}

          {crTriggered && crLoading && !crQueued && (
            <div className="rounded-xl bg-gray-900 border border-gray-700/60 p-8 space-y-5">
              <div className="flex items-center gap-3">
                <div className="w-2.5 h-2.5 rounded-full bg-purple-400 animate-pulse" />
                <p className="text-sm font-medium text-white">llama3.2:3b — reviewing files</p>
              </div>
              <div className="space-y-2">
                <div className="flex justify-between text-xs text-gray-500">
                  <span>{crProgress ? `${crProgress.files_done} / ${crProgress.total_files} files` : "Starting…"}</span>
                  <span>{crProgress?.pct ?? 0}%</span>
                </div>
                <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
                  <motion.div
                    className="h-full bg-purple-500 rounded-full"
                    initial={{ width: "0%" }}
                    animate={{ width: `${crProgress?.pct ?? 0}%` }}
                    transition={{ duration: 0.4 }}
                  />
                </div>
              </div>
              {crProgress?.current_file && (
                <div className="flex items-center gap-2 text-xs text-gray-500">
                  <Loader2 className="w-3.5 h-3.5 text-purple-400 animate-spin shrink-0" />
                  <span className="font-mono truncate">{crProgress.current_file}</span>
                </div>
              )}
              {crProgress && crProgress.findings_count > 0 && (
                <p className="text-xs text-gray-500">
                  Found <span className="text-purple-400 font-semibold">{crProgress.findings_count}</span> issues so far
                </p>
              )}
              <p className="text-xs text-gray-600">
                Reviewing {crProgress?.total_files ?? "…"} files (2 concurrently) with llama3.2:3b.
                {crProgress?.total_files && crProgress.total_files <= 20
                  ? " Small project — est. ~10 min."
                  : crProgress?.total_files && crProgress.total_files <= 25
                  ? " Medium project — est. ~18 min."
                  : crProgress?.total_files
                  ? " Large project — reviewing top most-critical files only."
                  : ""}
              </p>
            </div>
          )}

          {/* Completed with no findings */}
          {crCompleted && !crLoading && !crError && crFindings.length === 0 && (
            <div className="rounded-xl bg-gray-900 border border-gray-700/60 p-10 text-center">
              <CheckCircle2 className="w-8 h-8 text-green-400 mx-auto mb-3" />
              <p className="text-gray-300 text-sm font-medium">No issues found by Code Review</p>
              <p className="text-gray-600 text-xs mt-1">
                llama3.2:3b reviewed the source files and found no security, performance, or quality issues.
              </p>
              <button
                onClick={handleRunCodeReview}
                className="mt-4 flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs mx-auto
                           bg-gray-800 border border-gray-700 text-gray-400 hover:text-white
                           hover:border-gray-500 transition-colors"
              >
                <RotateCcw className="w-3 h-3" /> Re-run Review
              </button>
            </div>
          )}

          {crTriggered && !crLoading && !crError && crFindings.length > 0 && (
            <>
              {crSummary && (
                <div className="grid grid-cols-3 lg:grid-cols-5 gap-3">
                  {(["SECURITY", "PERFORMANCE", "CODE_QUALITY", "ERROR_HANDLING", "BEST_PRACTICES"] as ReviewCategory[]).map((cat) => {
                    const key = cat.toLowerCase() as keyof CodeReviewSummary;
                    const count = (crSummary[key] as number) ?? 0;
                    return (
                      <div key={cat} className={`rounded-lg border px-4 py-3 ${CAT_COLORS[cat]}`}>
                        <div className="flex items-center gap-1.5 mb-1">
                          {CAT_ICONS[cat]}
                          <span className="text-xs font-semibold uppercase tracking-wide">{cat.replace("_", " ")}</span>
                        </div>
                        <p className="text-2xl font-bold tabular-nums">{count}</p>
                      </div>
                    );
                  })}
                </div>
              )}
              <div className="flex flex-wrap gap-2">
                {(["ALL", "SECURITY", "PERFORMANCE", "CODE_QUALITY", "ERROR_HANDLING", "BEST_PRACTICES"] as const).map((cat) => {
                  const count = cat === "ALL" ? filteredCr.length : filteredCr.filter(f => f.category === cat).length;
                  const active = crCatFilter === cat;
                  return (
                    <button key={cat} onClick={() => setCrCatFilter(cat)}
                      className={`px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all ${
                        active ? "bg-purple-600 border-purple-500 text-white" : "bg-gray-800 border-gray-700 text-gray-400 hover:border-gray-500"
                      }`}>
                      {cat.replace("_", " ")} ({count})
                    </button>
                  );
                })}
              </div>
              <div className="space-y-2">
                <h2 className="text-sm font-medium text-gray-400 uppercase tracking-wide">
                  Code Review — {filteredCrFinal.length}
                  {sevFilter !== "ALL" && <span className="text-gray-600 normal-case ml-1">(filtered: {sevFilter})</span>}
                </h2>
                {filteredCrFinal.length === 0 && (
                  <div className="rounded-xl bg-gray-900 border border-gray-700/60 p-6 text-center text-gray-600 text-sm">
                    No code review findings at {sevFilter} severity / {crCatFilter} category.
                  </div>
                )}
                {filteredCrFinal.map((f) => {
                  const open = crExpanded.has(f.id);
                  return (
                    <motion.div key={f.id} layout initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }}
                      className="rounded-xl bg-gray-900 border border-gray-700/60 overflow-hidden">
                      <button
                        className="w-full text-left px-5 py-4 flex items-start gap-4 hover:bg-gray-800/40 transition-colors"
                        onClick={() => toggleCrExpand(f.id)}
                      >
                        <span className={`shrink-0 mt-0.5 flex items-center gap-1 text-xs font-semibold border px-2 py-1 rounded ${CAT_COLORS[f.category as ReviewCategory]}`}>
                          {CAT_ICONS[f.category as ReviewCategory]}
                          {f.category.replace("_", " ")}
                        </span>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="text-sm font-medium text-white">{f.title}</span>
                            <SeverityBadge severity={f.severity} />
                          </div>
                          <p className="text-xs text-gray-400 mt-1 line-clamp-2">{f.description}</p>
                          <div className="flex items-center gap-3 mt-1.5 text-xs text-gray-600">
                            <span className="flex items-center gap-1">
                              <FileCode className="w-3 h-3" />
                              {f.file_path.split("/").slice(-2).join("/")}{f.line_start ? `:${f.line_start}` : ""}
                            </span>
                            <span className="text-gray-700">Confidence: {Math.round((f.confidence ?? 0) * 100)}%</span>
                          </div>
                        </div>
                        <div className="shrink-0 text-gray-600 mt-1">
                          {open ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                        </div>
                      </button>
                      <AnimatePresence initial={false}>
                        {open && (
                          <motion.div key="cr-detail" initial={{ height: 0, opacity: 0 }} animate={{ height: "auto", opacity: 1 }}
                            exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.2 }} className="overflow-hidden">
                            <div className="px-5 pb-5 border-t border-gray-700/60 pt-4 space-y-4 text-sm">
                              <div>
                                <p className="text-xs text-gray-500 uppercase tracking-wide mb-1">File</p>
                                <p className="text-gray-300 font-mono break-all text-xs">{f.file_path}</p>
                                {f.line_start && (
                                  <p className="text-gray-600 text-xs mt-1">
                                    Lines {f.line_start}{f.line_end && f.line_end !== f.line_start ? `–${f.line_end}` : ""}
                                  </p>
                                )}
                              </div>
                              <div>
                                <p className="text-xs text-gray-500 uppercase tracking-wide mb-1">Description</p>
                                <p className="text-gray-300 text-sm leading-relaxed">{f.description}</p>
                              </div>
                              <div>
                                <p className="text-xs text-gray-500 uppercase tracking-wide mb-1 flex items-center gap-1">
                                  <Wrench className="w-3 h-3" /> Recommendation
                                </p>
                                <div className="rounded-lg bg-green-950/30 border border-green-800/40 px-4 py-3 text-sm text-green-300">
                                  {f.recommendation}
                                </div>
                              </div>
                            </div>
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </motion.div>
                  );
                })}
              </div>
            </>
          )}
        </div>
      )}

      {/* ── Code Knowledge Graph — shown when scanPath is known ── */}
      {!loading && scanPath && (
        <CodeGraph scanPath={scanPath} />
      )}

    </div>
  );
}

// ── Small helper components ──────────────────────────────────────────────────

function SummaryCard({
  label, value, color, loading = false,
}: { label: string; value: number; color: string; loading?: boolean }) {
  return (
    <div className="rounded-lg bg-gray-900 border border-gray-700/60 px-5 py-4">
      <p className="text-xs text-gray-500 uppercase tracking-wide">{label}</p>
      {loading ? (
        <div className="flex items-center gap-2 mt-2">
          <Loader2 className="w-4 h-4 animate-spin text-gray-600" />
          <span className="text-sm text-gray-600">scanning…</span>
        </div>
      ) : (
        <p className={`text-2xl font-bold mt-1 tabular-nums ${color}`}>{value.toLocaleString()}</p>
      )}
    </div>
  );
}

function AgentStatusCard({
  label, icon, color, done, count, unit, subtitle, skills, notStarted = false, progress, error = false, active = false, onClick,
}: {
  label: string; icon: React.ReactNode; color: string;
  done: boolean; count: number; unit: string; subtitle?: string; skills?: string[];
  notStarted?: boolean; progress?: number; error?: boolean;
  active?: boolean; onClick?: () => void;
}) {
  return (
    <div
      onClick={onClick}
      className={`rounded-lg px-4 py-3 space-y-2 transition-all cursor-pointer
        ${active
          ? "bg-gray-700/80 border-2 border-brand-500/70 shadow-lg shadow-brand-500/10"
          : error
            ? "bg-red-950/20 border border-red-700/40 hover:border-red-500/60"
            : "bg-gray-800/60 border border-gray-700/40 hover:border-gray-500/60 hover:bg-gray-800"
        }`}
    >
      <div className="flex items-center justify-between">
        <div className={`flex items-center gap-2 text-xs font-semibold ${color}`}>
          {icon} {label}
        </div>
        {error ? (
          <AlertTriangle className="w-4 h-4 text-red-400" />
        ) : done ? (
          <CheckCheck className="w-4 h-4 text-green-400" />
        ) : notStarted ? (
          <span className="text-xs text-gray-600">not started</span>
        ) : (
          <Loader2 className="w-3.5 h-3.5 animate-spin text-gray-500" />
        )}
      </div>

      {/* Indeterminate progress bar while running */}
      {!done && !notStarted && !error && progress === undefined && (
        <div className="h-1 bg-gray-700 rounded-full overflow-hidden">
          <motion.div
            className="h-full w-1/3 rounded-full"
            style={{ background: "currentColor" }}
            animate={{ x: ["−100%", "300%"] }}
            transition={{ duration: 1.5, repeat: Infinity, ease: "linear" }}
          />
        </div>
      )}

      {/* Determinate progress bar (code review) */}
      {progress !== undefined && !done && !error && (
        <div className="space-y-1">
          <div className="h-1.5 bg-gray-700 rounded-full overflow-hidden">
            <motion.div
              className="h-full bg-purple-500 rounded-full"
              animate={{ width: `${progress}%` }}
              transition={{ duration: 0.4 }}
            />
          </div>
          <p className="text-xs text-gray-500 text-right">{progress}%</p>
        </div>
      )}

      <p className={`text-sm font-bold tabular-nums ${error ? "text-red-400" : done ? color : "text-gray-500"}`}>
        {error ? "failed" : done ? `${count} ${unit}` : notStarted ? "—" : "running…"}
      </p>
      {done && subtitle && (
        <p className="text-xs text-gray-500 -mt-1">{subtitle}</p>
      )}
      {skills && skills.length > 0 && (
        <div className="pt-1.5 border-t border-gray-700/50 mt-1">
          <p className="text-[9px] uppercase tracking-widest text-gray-600 mb-1">Skills</p>
          <div className="flex flex-wrap gap-1">
            {skills.map(s => (
              <span key={s} className={`text-[10px] font-medium px-1.5 py-0.5 rounded border ${color.replace("text-", "border-").replace("400", "500/40")} ${color.replace("text-", "bg-").replace("400", "500/10")} ${color}`}>{s}</span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

const GRAPH_STAGES: Array<[number, string]> = [
  [0,  "Starting build…"],
  [8,  "Parsing files…"],
  [20, "Resolving imports…"],
  [40, "Computing hub scores…"],
  [60, "Building communities…"],
  [80, "Finalising graph…"],
];

function graphStageLabel(elapsed: number): string {
  let label = GRAPH_STAGES[0][1];
  for (const [t, msg] of GRAPH_STAGES) {
    if (elapsed >= t) label = msg;
  }
  return label;
}

function GraphBuildCard({
  status, elapsed, error,
}: {
  status: "idle" | "building" | "done" | "failed";
  elapsed: number;
  error: string | null;
}) {
  const isBuilding = status === "building";
  const isDone     = status === "done";
  const isFailed   = status === "failed";

  return (
    <div className={`rounded-lg px-4 py-3 space-y-2 transition-all
      ${isFailed
        ? "bg-red-950/20 border border-red-700/40"
        : isDone
          ? "bg-gray-800/60 border border-gray-700/40"
          : isBuilding
            ? "bg-brand-950/20 border border-brand-700/40"
            : "bg-gray-800/60 border border-gray-700/40 opacity-50"
      }`}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-xs font-semibold text-brand-400">
          <Network className="w-4 h-4" /> Code Graph
        </div>
        {isFailed ? (
          <AlertTriangle className="w-4 h-4 text-red-400" />
        ) : isDone ? (
          <CheckCheck className="w-4 h-4 text-green-400" />
        ) : isBuilding ? (
          <Loader2 className="w-3.5 h-3.5 animate-spin text-brand-400" />
        ) : (
          <span className="text-xs text-gray-600">—</span>
        )}
      </div>

      {/* Progress bar while building */}
      {isBuilding && (
        <div className="space-y-1">
          <div className="h-1.5 bg-gray-800 rounded-full overflow-hidden">
            <motion.div
              className="h-full bg-brand-500 rounded-full transition-all duration-1000"
              animate={{ width: `${Math.min(92, (elapsed / 90) * 100)}%` }}
              transition={{ duration: 1 }}
            />
          </div>
          <p className="text-xs text-gray-500">{graphStageLabel(elapsed)}</p>
        </div>
      )}

      <p className={`text-sm font-bold tabular-nums
        ${isFailed ? "text-red-400" : isDone ? "text-green-400" : isBuilding ? "text-brand-400" : "text-gray-600"}`}>
        {isFailed
          ? <span title={error ?? ""}>failed</span>
          : isDone    ? "ready"
          : isBuilding ? `${elapsed}s elapsed`
          : "not started"}
      </p>
    </div>
  );
}

function AgentInProgress({
  label, color, description,
}: { label: string; color: "yellow" | "red" | "purple"; description: string }) {
  const colorMap = {
    yellow: "text-yellow-400 border-yellow-700/40 bg-yellow-900/10",
    red:    "text-red-400 border-red-700/40 bg-red-900/10",
    purple: "text-purple-400 border-purple-700/40 bg-purple-900/10",
  };
  return (
    <div className={`rounded-xl border p-8 flex flex-col items-center gap-4 ${colorMap[color]}`}>
      <Loader2 className={`w-8 h-8 animate-spin ${colorMap[color].split(" ")[0]}`} />
      <div className="text-center">
        <p className="text-sm font-semibold text-white">{label} Running</p>
        <p className="text-xs text-gray-400 mt-1 max-w-sm">{description}</p>
      </div>
      <div className="w-full max-w-xs h-1.5 bg-gray-800 rounded-full overflow-hidden">
        <motion.div
          className="h-full w-2/5 rounded-full bg-current"
          animate={{ x: ["-100%", "250%"] }}
          transition={{ duration: 1.8, repeat: Infinity, ease: "linear" }}
        />
      </div>
    </div>
  );
}

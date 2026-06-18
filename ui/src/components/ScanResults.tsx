import { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend,
} from "recharts";
import {
  ChevronDown, ChevronUp, RotateCcw, ShieldAlert, ExternalLink,
  FileCode, Wrench, BookOpen, TrendingUp, Brain, Zap, Code2, AlertTriangle,
  CheckCircle2, Loader2, PlayCircle, Key, Package, CheckCheck,
} from "lucide-react";
import {
  getFindings, getScanStatus, triggerCodeReview, getCodeReview,
  getCodeReviewProgress, getSecretFindings, getDependencyFindings,
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

  // Code review state
  const [crFindings,   setCrFindings]   = useState<CodeReviewFinding[]>([]);
  const [crSummary,    setCrSummary]    = useState<CodeReviewSummary | null>(null);
  const [crLoading,    setCrLoading]    = useState(false);
  const [crTriggered,  setCrTriggered]  = useState(false);
  const [crCompleted,  setCrCompleted]  = useState(false);
  const [crError,      setCrError]      = useState<string | null>(null);
  const [crCatFilter,  setCrCatFilter]  = useState<string>("ALL");
  const [crExpanded,   setCrExpanded]   = useState<Set<string>>(new Set());
  const [crProgress,   setCrProgress]   = useState<{
    pct: number; files_done: number; total_files: number;
    current_file: string | null; findings_count: number;
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

  // ---------------------------------------------------------------------------
  // Data loading — initial fetch + polling for parallel agents
  // ---------------------------------------------------------------------------
  useEffect(() => {
    // Reset scanning flags for new runId
    setSecretScanning(true);
    setDepScanning(true);
    setSecretFindings([]);
    setDepFindings([]);
    setCrFindings([]);
    setFindings([]);

    async function load() {
      const [f, s] = await Promise.all([getFindings(runId), getScanStatus(runId)]);
      setFindings(f);
      setStatus(s);
      setLoading(false);
      try {
        // Also check progress status — might be "completed" (0 findings) or "failed"
        const [cr, prog] = await Promise.allSettled([
          getCodeReview(runId),
          getCodeReviewProgress(runId),
        ]);
        if (cr.status === "fulfilled" && cr.value.count > 0) {
          setCrFindings(cr.value.findings);
          setCrSummary(cr.value.summary);
          setCrTriggered(true);
          setCrCompleted(true);
        } else if (prog.status === "fulfilled" && prog.value.status === "completed") {
          // Completed but found nothing
          setCrTriggered(true);
          setCrCompleted(true);
        } else if (prog.status === "fulfilled" && prog.value.status === "failed") {
          setCrTriggered(true);
          setCrError("Code review failed. Check logs or try again.");
        }
      } catch { /* not yet */ }
      loadSecrets();
      loadDeps();
    }

    async function loadSecrets(retries = 0) {
      // Max ~2.5 minutes of polling (30 attempts × 5s). After that assume scan
      // completed with no secrets — stop the spinner rather than loop forever.
      const MAX_RETRIES = 30;
      try {
        const sec = await getSecretFindings(runId);
        if (sec.count > 0) {
          setSecretFindings(sec.findings);
          setSecretSummary(sec.summary);
          setSecretScanning(false);
          return;
        }
        // Check if the overall scan has already finished — if so, no more secrets coming
        const scanState = await getScanStatus(runId);
        if (scanState.status === "completed" || scanState.status === "failed") {
          setSecretScanning(false);
          return;
        }
        if (retries < MAX_RETRIES) {
          setTimeout(() => loadSecrets(retries + 1), 5000);
        } else {
          setSecretScanning(false);  // give up after timeout
        }
      } catch {
        if (retries < MAX_RETRIES) {
          setTimeout(() => loadSecrets(retries + 1), 5000);
        } else {
          setSecretScanning(false);
        }
      }
    }

    async function loadDeps(retries = 0) {
      const MAX_RETRIES = 30;
      try {
        const dep = await getDependencyFindings(runId);
        if (dep.count > 0) {
          setDepFindings(dep.findings);
          setDepSummary(dep.summary);
          setDepScanning(false);
          return;
        }
        const scanState = await getScanStatus(runId);
        if (scanState.status === "completed" || scanState.status === "failed") {
          setDepScanning(false);
          return;
        }
        if (retries < MAX_RETRIES) {
          setTimeout(() => loadDeps(retries + 1), 5000);
        } else {
          setDepScanning(false);
        }
      } catch {
        if (retries < MAX_RETRIES) {
          setTimeout(() => loadDeps(retries + 1), 5000);
        } else {
          setDepScanning(false);
        }
      }
    }

    load();
  }, [runId]);

  // ---------------------------------------------------------------------------
  // Code review trigger + progress polling
  // ---------------------------------------------------------------------------
  async function handleRunCodeReview() {
    setCrLoading(true);
    setCrTriggered(true);
    setCrError(null);
    setCrCompleted(false);
    setCrProgress(null);
    try {
      await triggerCodeReview(runId);
    } catch (err) {
      setCrLoading(false);
      setCrError(`Failed to start code review: ${err instanceof Error ? err.message : "server error"}. Is the server running?`);
      return;
    }

    // Poll for progress — stop on completed/failed or after 20 min
    let stalePct = -1;
    let staleCount = 0;
    const MAX_STALE_POLLS = 20; // 20 × 6s = 2 min with no change → stuck

    const poll = async () => {
      try {
        const prog = await getCodeReviewProgress(runId);
        setCrProgress({
          pct: prog.pct, files_done: prog.files_done,
          total_files: prog.total_files, current_file: prog.current_file,
          findings_count: prog.findings_count,
        });

        if (prog.status === "completed") {
          const cr = await getCodeReview(runId);
          if (cr.count > 0) {
            setCrFindings(cr.findings);
            setCrSummary(cr.summary);
          }
          setCrCompleted(true);
          setCrLoading(false);
          return;
        }

        if (prog.status === "failed") {
          setCrError("Code review failed on the server. Check /tmp/app.log for details.");
          setCrLoading(false);
          return;
        }

        // Stale detection — if pct hasn't moved in MAX_STALE_POLLS, warn
        if (prog.pct === stalePct) {
          staleCount++;
        } else {
          stalePct = prog.pct;
          staleCount = 0;
        }
        if (staleCount >= MAX_STALE_POLLS) {
          setCrError(`Code review appears stuck at ${prog.pct}%. Ollama may be overloaded. Check /tmp/app.log.`);
          setCrLoading(false);
          return;
        }

        setTimeout(poll, 6000);
      } catch {
        setTimeout(poll, 8000);
      }
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
  const agentsRunning = depScanning || secretScanning;

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
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">

            {/* SAST */}
            <AgentStatusCard
              label="SAST Scanner"
              icon={<ShieldAlert className="w-4 h-4" />}
              color="text-orange-400"
              done={true}
              count={findings.length}
              unit="findings"
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
              notStarted={!crTriggered}
              progress={crLoading ? crProgress?.pct : undefined}
              error={!!crError}
              active={activeTab === "review"}
              onClick={() => setActiveTab("review")}
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
                              {f.description && (
                                <div>
                                  <p className="text-xs text-gray-500 uppercase tracking-wide mb-1">Description</p>
                                  <p className="text-gray-300 text-sm leading-relaxed">{f.description}</p>
                                </div>
                              )}
                              {f.fixed_version && (
                                <div className="rounded-lg bg-green-950/30 border border-green-800/40 px-4 py-3 text-xs text-green-300">
                                  Update {f.package_name} to version {f.fixed_version} or later to remediate this vulnerability.
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

          {crTriggered && crLoading && (
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
              <p className="text-xs text-gray-600">Reviewing 2 files concurrently with llama3.2:3b.</p>
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
  label, icon, color, done, count, unit, notStarted = false, progress, error = false, active = false, onClick,
}: {
  label: string; icon: React.ReactNode; color: string;
  done: boolean; count: number; unit: string;
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

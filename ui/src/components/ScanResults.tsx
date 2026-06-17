import { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend,
} from "recharts";
import {
  ChevronDown, ChevronUp, RotateCcw, ShieldAlert, ExternalLink,
  FileCode, Wrench, BookOpen, TrendingUp,
} from "lucide-react";
import { getFindings, getScanStatus } from "../lib/api";
import type { Finding, ScanStatus } from "../types";
import { SeverityBadge } from "./SeverityBadge";
import { CodeBlock } from "./CodeBlock";

const SEV_COLORS: Record<string, string> = {
  CRITICAL: "#ef4444",
  HIGH:     "#f97316",
  MEDIUM:   "#eab308",
  LOW:      "#3b82f6",
  INFO:     "#6b7280",
};

interface Props {
  runId: string;
  onNewScan: () => void;
}

export function ScanResults({ runId, onNewScan }: Props) {
  const [findings,  setFindings]  = useState<Finding[]>([]);
  const [status,    setStatus]    = useState<ScanStatus | null>(null);
  const [expanded,  setExpanded]  = useState<Set<string>>(new Set());
  const [loading,   setLoading]   = useState(true);
  const [sevFilter, setSevFilter] = useState<string>("ALL");

  useEffect(() => {
    async function load() {
      const [f, s] = await Promise.all([
        getFindings(runId),
        getScanStatus(runId),
      ]);
      setFindings(f);
      setStatus(s);
      setLoading(false);
    }
    load();
  }, [runId]);

  function toggleExpand(id: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }

  // Build pie data from findings
  const sevCounts: Record<string, number> = {};
  for (const f of findings) {
    sevCounts[f.severity] = (sevCounts[f.severity] ?? 0) + 1;
  }
  const pieData = Object.entries(sevCounts).map(([name, value]) => ({ name, value }));

  const filtered =
    sevFilter === "ALL" ? findings : findings.filter((f) => f.severity === sevFilter);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center text-gray-500">
        <span className="animate-pulse">Loading results…</span>
      </div>
    );
  }

  const cov = status?.scan_coverage;

  return (
    <div className="min-h-screen p-6 max-w-7xl mx-auto space-y-6">
      {/* Header bar */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-white">Scan Results</h1>
          <p className="text-xs text-gray-500 mt-0.5 truncate max-w-xl">{status?.scan_path}</p>
        </div>
        <motion.button
          onClick={onNewScan}
          whileHover={{ scale: 1.03 }}
          whileTap={{ scale: 0.97 }}
          className="flex items-center gap-2 px-4 py-2 rounded-lg border border-gray-700
                     text-sm text-gray-300 hover:text-white hover:border-gray-500 transition-colors"
        >
          <RotateCcw className="w-4 h-4" />
          New Scan
        </motion.button>
      </div>

      {/* Coverage + severity summary row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: "Files Scanned",     value: cov?.files_scanned     ?? 0, color: "text-brand-500" },
          { label: "Files with Issues", value: cov?.files_with_findings ?? 0, color: "text-orange-400" },
          { label: "Clean Files",       value: cov?.files_clean        ?? 0, color: "text-green-400" },
          { label: "Packages",          value: cov?.packages_total     ?? 0, color: "text-purple-400" },
        ].map(({ label, value, color }) => (
          <div
            key={label}
            className="rounded-lg bg-gray-900 border border-gray-700/60 px-5 py-4"
          >
            <p className="text-xs text-gray-500 uppercase tracking-wide">{label}</p>
            <p className={`text-2xl font-bold mt-1 tabular-nums ${color}`}>
              {value.toLocaleString()}
            </p>
          </div>
        ))}
      </div>

      {/* Chart + severity filter row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Pie chart */}
        <div className="rounded-xl bg-gray-900 border border-gray-700/60 p-5 lg:col-span-1">
          <h3 className="text-sm font-medium text-gray-400 mb-4 flex items-center gap-2">
            <ShieldAlert className="w-4 h-4" /> Finding Distribution
          </h3>
          {pieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={80}
                  paddingAngle={3}
                  dataKey="value"
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
                <Legend
                  iconType="circle"
                  iconSize={8}
                  wrapperStyle={{ fontSize: 12, color: "#9ca3af" }}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <p className="text-center text-gray-600 text-sm py-10">No findings</p>
          )}
        </div>

        {/* Severity filter buttons + scan stats */}
        <div className="lg:col-span-2 space-y-4">
          <div className="rounded-xl bg-gray-900 border border-gray-700/60 p-5">
            <h3 className="text-sm font-medium text-gray-400 mb-4">Filter by Severity</h3>
            <div className="flex flex-wrap gap-2">
              {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => {
                const count = s === "ALL" ? findings.length : (sevCounts[s] ?? 0);
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
          </div>

          {/* Scan meta */}
          {cov && (
            <div className="rounded-xl bg-gray-900 border border-gray-700/60 p-5 grid grid-cols-2 gap-3 text-xs">
              <div className="text-gray-500">Scan duration</div>
              <div className="text-gray-300 text-right">
                {cov.scan_duration_ms > 0
                  ? `${(cov.scan_duration_ms / 1000).toFixed(1)}s`
                  : "—"}
              </div>
              <div className="text-gray-500">Files skipped</div>
              <div className="text-gray-300 text-right">{cov.files_skipped}</div>
              <div className="text-gray-500">Run ID</div>
              <div className="text-gray-400 text-right font-mono truncate">{runId}</div>
            </div>
          )}
        </div>
      </div>

      {/* Findings table */}
      <div className="space-y-3">
        <h2 className="text-sm font-medium text-gray-400 uppercase tracking-wide">
          Findings — {filtered.length}
        </h2>
        {filtered.length === 0 && (
          <div className="rounded-xl bg-gray-900 border border-gray-700/60 p-10 text-center text-gray-600">
            No findings match the current filter.
          </div>
        )}
        {filtered.map((f) => {
          const open = expanded.has(f.id);
          return (
            <motion.div
              key={f.id}
              layout
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              className="rounded-xl bg-gray-900 border border-gray-700/60 overflow-hidden"
            >
              {/* Row header — always visible */}
              <button
                className="w-full text-left px-5 py-4 flex items-start gap-4 hover:bg-gray-800/40 transition-colors"
                onClick={() => toggleExpand(f.id)}
              >
                <div className="mt-0.5 shrink-0">
                  <SeverityBadge severity={f.severity} />
                </div>
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
                  </div>
                  <p className="text-xs text-gray-400 mt-1 line-clamp-2">{f.message}</p>
                  <div className="flex items-center gap-3 mt-1.5 text-xs text-gray-600">
                    <span className="flex items-center gap-1">
                      <FileCode className="w-3 h-3" />
                      {f.file_path.split("/").slice(-2).join("/")}:{f.line_start}
                    </span>
                    {f.class_name && <span>Class: <span className="text-gray-400">{f.class_name}</span></span>}
                    {f.method_name && <span>Method: <span className="text-gray-400">{f.method_name}()</span></span>}
                  </div>
                </div>
                <div className="shrink-0 text-gray-600 mt-1">
                  {open ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                </div>
              </button>

              {/* Expandable detail section */}
              <AnimatePresence initial={false}>
                {open && (
                  <motion.div
                    key="detail"
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: "auto", opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    transition={{ duration: 0.2 }}
                    className="overflow-hidden"
                  >
                    <div className="px-5 pb-5 border-t border-gray-700/60 pt-4 space-y-4">
                      {/* Full file path + location */}
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                        <div>
                          <p className="text-gray-500 uppercase tracking-wide mb-1">File</p>
                          <p className="text-gray-300 font-mono break-all">{f.file_path}</p>
                          <p className="text-gray-500 mt-1">
                            Lines {f.line_start}
                            {f.line_end && f.line_end !== f.line_start ? `–${f.line_end}` : ""}
                          </p>
                        </div>
                        <div className="grid grid-cols-2 gap-3">
                          {f.likelihood && (
                            <div>
                              <p className="text-gray-500 flex items-center gap-1">
                                <TrendingUp className="w-3 h-3" /> Likelihood
                              </p>
                              <p className="text-gray-300 mt-1">{f.likelihood}</p>
                            </div>
                          )}
                          {f.impact && (
                            <div>
                              <p className="text-gray-500">Impact</p>
                              <p className="text-gray-300 mt-1">{f.impact}</p>
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

                      {/* Code snippet */}
                      {f.code_snippet && (
                        <div>
                          <p className="text-xs text-gray-500 uppercase tracking-wide mb-2 flex items-center gap-1">
                            <FileCode className="w-3 h-3" /> Vulnerable Code
                          </p>
                          <CodeBlock snippet={f.code_snippet} />
                        </div>
                      )}

                      {/* Fix suggestion */}
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

                      {/* References */}
                      {Array.isArray(f.ref_urls) && f.ref_urls.length > 0 && (
                        <div>
                          <p className="text-xs text-gray-500 uppercase tracking-wide mb-2 flex items-center gap-1">
                            <BookOpen className="w-3 h-3" /> References
                          </p>
                          <div className="flex flex-wrap gap-2">
                            {f.ref_urls.map((url) => (
                              <a
                                key={url}
                                href={url}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="flex items-center gap-1 text-xs text-brand-500 hover:text-brand-400
                                           bg-gray-800 border border-gray-700 px-2 py-1 rounded transition-colors"
                              >
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
    </div>
  );
}

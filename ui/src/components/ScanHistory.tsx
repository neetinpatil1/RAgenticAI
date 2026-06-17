import { useEffect, useState, useMemo } from "react";
import { motion } from "framer-motion";
import { Search, FolderOpen, Clock, CheckCircle2, XCircle, Loader2, ChevronRight } from "lucide-react";
import { getRuns } from "../lib/api";
import type { RunSummary } from "../types";

interface Props {
  onViewResults: (runId: string) => void;
}

const SEV_COLORS = {
  critical: "text-red-400 bg-red-500/10 border-red-500/30",
  high:     "text-orange-400 bg-orange-500/10 border-orange-500/30",
  medium:   "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
  low:      "text-blue-400 bg-blue-500/10 border-blue-500/30",
};

function SeverityPill({ label, count, color }: { label: string; count: number; color: string }) {
  if (count === 0) return null;
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border text-xs font-semibold ${color}`}>
      {label[0].toUpperCase()}{label.slice(1, 4).toUpperCase()}: {count}
    </span>
  );
}

function StateIcon({ state }: { state: string }) {
  if (state === "completed") return <CheckCircle2 className="w-4 h-4 text-green-400" />;
  if (state === "failed")    return <XCircle      className="w-4 h-4 text-red-400" />;
  return <Loader2 className="w-4 h-4 text-brand-500 animate-spin" />;
}

function formatDate(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, {
    month: "short", day: "numeric", year: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

function formatDuration(ms: number): string {
  if (!ms) return "—";
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.floor(ms / 60_000)}m ${Math.floor((ms % 60_000) / 1000)}s`;
}

export function ScanHistory({ onViewResults }: Props) {
  const [runs,    setRuns]    = useState<RunSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState<string | null>(null);
  const [search,  setSearch]  = useState("");

  useEffect(() => {
    getRuns(100)
      .then(setRuns)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return runs;
    return runs.filter(
      (r) =>
        r.project_name.toLowerCase().includes(q) ||
        r.scan_path.toLowerCase().includes(q)
    );
  }, [runs, search]);

  return (
    <div className="max-w-5xl mx-auto px-6 py-8 space-y-6">
      {/* Header + search */}
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-xl font-semibold text-white">Scan History</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            {runs.length} scan{runs.length !== 1 ? "s" : ""} on record
          </p>
        </div>

        <div className="relative w-72">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter by project name…"
            className="w-full bg-gray-800 border border-gray-700 rounded-lg pl-9 pr-4 py-2 text-sm
                       text-gray-100 placeholder-gray-600 focus:outline-none focus:border-brand-500
                       focus:ring-1 focus:ring-brand-500/50 transition-colors"
          />
        </div>
      </div>

      {/* Loading */}
      {loading && (
        <div className="flex items-center justify-center py-20 text-gray-500 gap-2">
          <Loader2 className="w-5 h-5 animate-spin" />
          <span>Loading scan history…</span>
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="rounded-xl bg-red-950/30 border border-red-800/40 p-5 text-red-400 text-sm">
          Failed to load history: {error}
        </div>
      )}

      {/* Empty state */}
      {!loading && !error && filtered.length === 0 && (
        <div className="rounded-xl bg-gray-900 border border-gray-700/60 p-12 text-center text-gray-500">
          {search ? `No scans matching "${search}"` : "No scans yet — run your first scan."}
        </div>
      )}

      {/* Scan list */}
      <div className="space-y-3">
        {filtered.map((run, i) => (
          <motion.div
            key={run.run_id}
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.03 }}
            className="rounded-xl bg-gray-900 border border-gray-700/60 hover:border-gray-600
                       transition-colors group"
          >
            <div className="px-5 py-4 flex items-center gap-4">
              {/* State icon */}
              <div className="shrink-0 mt-0.5">
                <StateIcon state={run.state} />
              </div>

              {/* Main info */}
              <div className="flex-1 min-w-0 space-y-1.5">
                {/* Project name + state badge */}
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-semibold text-white text-sm">{run.project_name}</span>
                  <span className={`text-xs px-1.5 py-0.5 rounded border font-medium
                    ${run.state === "completed" ? "text-green-400 bg-green-500/10 border-green-500/30"
                    : run.state === "failed"    ? "text-red-400 bg-red-500/10 border-red-500/30"
                    :                             "text-brand-500 bg-brand-500/10 border-brand-500/30"}`}>
                    {run.state}
                  </span>
                </div>

                {/* Severity pills */}
                {run.severity.total > 0 ? (
                  <div className="flex flex-wrap gap-1.5">
                    <SeverityPill label="critical" count={run.severity.critical} color={SEV_COLORS.critical} />
                    <SeverityPill label="high"     count={run.severity.high}     color={SEV_COLORS.high} />
                    <SeverityPill label="medium"   count={run.severity.medium}   color={SEV_COLORS.medium} />
                    <SeverityPill label="low"      count={run.severity.low}      color={SEV_COLORS.low} />
                    <span className="text-xs text-gray-500 self-center">
                      ({run.severity.total} total)
                    </span>
                  </div>
                ) : (
                  <span className="text-xs text-green-500">No findings</span>
                )}

                {/* Path + timing */}
                <div className="flex items-center gap-4 text-xs text-gray-600 flex-wrap">
                  <span className="flex items-center gap-1 truncate max-w-sm">
                    <FolderOpen className="w-3 h-3 shrink-0" />
                    <span className="truncate">{run.scan_path}</span>
                  </span>
                  <span className="flex items-center gap-1 shrink-0">
                    <Clock className="w-3 h-3" />
                    {formatDate(run.created_at)}
                  </span>
                  {run.duration_ms > 0 && (
                    <span className="text-gray-600 shrink-0">
                      Duration: {formatDuration(run.duration_ms)}
                    </span>
                  )}
                </div>
              </div>

              {/* View results button */}
              {run.state === "completed" && (
                <button
                  onClick={() => onViewResults(run.run_id)}
                  className="shrink-0 flex items-center gap-1.5 px-3 py-1.5 rounded-lg
                             bg-gray-800 border border-gray-700 text-sm text-gray-300
                             hover:text-white hover:border-gray-500 transition-colors
                             opacity-0 group-hover:opacity-100"
                >
                  View
                  <ChevronRight className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </motion.div>
        ))}
      </div>
    </div>
  );
}

import { useEffect, useRef, useState } from "react";
import {
  Network, FileCode, GitBranch, ExternalLink, RefreshCw,
  AlertCircle, Layers, Share2, CheckCircle2, Loader2, XCircle,
} from "lucide-react";

interface GraphStatus {
  available: boolean;
  nodes?: number;
  edges?: number;
  files?: number;
  languages?: string;
  last_updated?: string;
  branch?: string;
  commit?: string;
}

interface BuildStatus {
  status: "idle" | "building" | "done" | "failed";
  error?: string | null;
  elapsed_sec?: number;
  graph_exists?: boolean;
}

interface Props {
  scanPath: string;
}

// Approximate build stage labels shown to the user while elapsed time increases
const STAGE_LABELS: Array<[number, string]> = [
  [0,  "Initialising build…"],
  [8,  "Parsing source files…"],
  [20, "Resolving imports & call graphs…"],
  [40, "Computing communities & hub scores…"],
  [60, "Persisting graph to SQLite…"],
  [80, "Almost done — finalising…"],
];

function stageLabel(elapsed: number): string {
  let label = STAGE_LABELS[0][1];
  for (const [t, msg] of STAGE_LABELS) {
    if (elapsed >= t) label = msg;
  }
  return label;
}

export function CodeGraph({ scanPath }: Props) {
  const [status,     setStatus]     = useState<GraphStatus | null>(null);
  const [loading,    setLoading]    = useState(true);
  const [error,      setError]      = useState<string | null>(null);

  // Build state
  const [buildPhase, setBuildPhase] = useState<"idle" | "building" | "done" | "failed">("idle");
  const [buildError, setBuildError] = useState<string | null>(null);
  const [elapsed,    setElapsed]    = useState(0);
  const pollRef    = useRef<ReturnType<typeof setInterval> | null>(null);
  const elapsedRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const pollCount  = useRef(0);

  // -------------------------------------------------------------------------
  // Graph status
  // -------------------------------------------------------------------------
  async function fetchStatus(path: string) {
    setLoading(true);
    setError(null);
    try {
      const r = await fetch(`/api/v1/graph/status?scan_path=${encodeURIComponent(path)}`);
      if (!r.ok) throw new Error(`Server returned ${r.status}`);
      setStatus(await r.json());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch graph status");
      setStatus({ available: false });
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (scanPath) fetchStatus(scanPath);
    return () => stopPolling();
  }, [scanPath]);

  // -------------------------------------------------------------------------
  // Build polling helpers
  // -------------------------------------------------------------------------
  function stopPolling() {
    if (pollRef.current)    { clearInterval(pollRef.current);    pollRef.current    = null; }
    if (elapsedRef.current) { clearInterval(elapsedRef.current); elapsedRef.current = null; }
  }

  function startElapsedTicker() {
    setElapsed(0);
    elapsedRef.current = setInterval(() => setElapsed(s => s + 1), 1000);
  }

  async function pollBuildStatus() {
    pollCount.current += 1;
    // Safety cap: 80 polls × 3s = 4 minutes max
    if (pollCount.current > 80) {
      stopPolling();
      setBuildPhase("failed");
      setBuildError("Build is taking too long. Check server logs for details.");
      return;
    }
    try {
      const r = await fetch(`/api/v1/graph/build/status?scan_path=${encodeURIComponent(scanPath)}`);
      if (!r.ok) return; // transient — keep polling
      const d: BuildStatus = await r.json();

      if (d.status === "done" || (d.status === "idle" && d.graph_exists)) {
        stopPolling();
        setBuildPhase("done");
        await fetchStatus(scanPath); // refresh node/edge counts
      } else if (d.status === "failed") {
        stopPolling();
        setBuildPhase("failed");
        setBuildError(d.error ?? "Build failed — check server logs for details.");
      }
      // "building" or "idle" (not yet written) → keep polling
    } catch { /* network blip — keep polling */ }
  }

  // -------------------------------------------------------------------------
  // Trigger build
  // -------------------------------------------------------------------------
  async function triggerBuild() {
    stopPolling();
    pollCount.current = 0;
    setBuildPhase("building");
    setBuildError(null);
    setError(null);
    startElapsedTicker();

    try {
      const r = await fetch(
        `/api/v1/graph/build?scan_path=${encodeURIComponent(scanPath)}`,
        { method: "POST" }
      );
      const body = await r.json().catch(() => ({ detail: r.statusText }));
      if (!r.ok) {
        stopPolling();
        setBuildPhase("failed");
        setBuildError(body.detail ?? `Server error ${r.status}`);
        return;
      }
      // 200 → build started in background; poll for completion
      pollRef.current = setInterval(pollBuildStatus, 3000);
    } catch (err) {
      stopPolling();
      setBuildPhase("failed");
      setBuildError(err instanceof Error ? err.message : "Could not reach the server.");
    }
  }

  function openGraph(mode: "file" | "full" | "community" = "file") {
    window.open(
      `/api/v1/graph/visualization?scan_path=${encodeURIComponent(scanPath)}&mode=${mode}`,
      "_blank",
      "noopener,noreferrer"
    );
  }

  // -------------------------------------------------------------------------
  // Render helpers
  // -------------------------------------------------------------------------
  const langs = status?.languages?.split(",").map(l => l.trim()).filter(Boolean) ?? [];
  const isBuilding = buildPhase === "building";

  return (
    <div className="rounded-xl bg-gray-900 border border-gray-700/60 p-5 space-y-4">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Network className="w-4 h-4 text-brand-500" />
          <h3 className="text-sm font-semibold text-white">Code Knowledge Graph</h3>
          <span className="text-xs text-gray-600 font-mono truncate max-w-xs">
            {scanPath.split("/").slice(-2).join("/")}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => fetchStatus(scanPath)}
            disabled={loading || isBuilding}
            className="p-1.5 rounded-lg text-gray-500 hover:text-gray-300 hover:bg-gray-800
                       transition-colors disabled:opacity-40"
            title="Refresh stats"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
          </button>
          {status?.available && !isBuilding && (
            <div className="flex items-center gap-1">
              <span className="text-xs text-gray-600 mr-1">View:</span>
              {(["file", "full", "community"] as const).map(m => (
                <button
                  key={m}
                  onClick={() => openGraph(m)}
                  className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-medium
                             bg-gray-800 border border-gray-700 text-gray-300
                             hover:bg-brand-600 hover:border-brand-500 hover:text-white transition-colors"
                  title={
                    m === "file"      ? "File-level nodes — shows each source file as a node" :
                    m === "full"      ? "Full detail — every class & method as a node" :
                                        "Community view — grouped clusters of related files"
                  }
                >
                  <ExternalLink className="w-3 h-3" />
                  {m === "file" ? "Files" : m === "full" ? "Full" : "Groups"}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Status fetch error */}
      {error && (
        <div className="flex items-start gap-2 rounded-lg bg-red-950/20 border border-red-700/30
                        px-3 py-2.5 text-xs">
          <AlertCircle className="w-3.5 h-3.5 text-red-400 mt-0.5 shrink-0" />
          <span className="text-red-300">{error}</span>
        </div>
      )}

      {/* Build success */}
      {buildPhase === "done" && (
        <div className="flex items-center gap-2 rounded-lg bg-green-950/20 border border-green-700/30
                        px-3 py-2 text-xs">
          <CheckCircle2 className="w-3.5 h-3.5 text-green-400 shrink-0" />
          <span className="text-green-300">
            Graph built successfully in {elapsed}s — stats updated below.
          </span>
        </div>
      )}

      {/* Build error */}
      {buildPhase === "failed" && buildError && (
        <div className="rounded-lg bg-red-950/20 border border-red-700/30 px-3 py-2.5 space-y-1.5">
          <div className="flex items-start gap-2 text-xs">
            <XCircle className="w-3.5 h-3.5 text-red-400 mt-0.5 shrink-0" />
            <div className="flex-1 min-w-0">
              <p className="text-red-300 font-medium">Build failed</p>
              <p className="text-red-400/80 mt-0.5 font-mono break-all">{buildError}</p>
            </div>
          </div>
          <button
            onClick={triggerBuild}
            className="mt-1 flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs
                       bg-gray-800 border border-gray-700 text-gray-300 hover:text-white
                       hover:border-gray-500 transition-colors"
          >
            <RefreshCw className="w-3 h-3" /> Retry
          </button>
        </div>
      )}

      {/* In-progress banner */}
      {isBuilding && (
        <div className="rounded-lg bg-brand-950/20 border border-brand-700/30 px-4 py-3 space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Loader2 className="w-4 h-4 text-brand-400 animate-spin shrink-0" />
              <span className="text-sm font-medium text-brand-300">Building graph…</span>
            </div>
            <span className="text-xs text-gray-500 tabular-nums">{elapsed}s elapsed</span>
          </div>

          {/* Progress bar (indeterminate but moves with elapsed) */}
          <div className="h-1.5 rounded-full bg-gray-800 overflow-hidden">
            <div
              className="h-full rounded-full bg-brand-500 transition-all duration-1000"
              style={{ width: `${Math.min(95, (elapsed / 90) * 100)}%` }}
            />
          </div>

          <p className="text-xs text-gray-400">{stageLabel(elapsed)}</p>
          <p className="text-xs text-gray-600">
            This runs once per project — future scans reuse the graph automatically.
          </p>
        </div>
      )}

      {/* Main body */}
      {loading ? (
        <div className="grid grid-cols-3 gap-3">
          {[...Array(3)].map((_, i) => (
            <div key={i} className="h-14 rounded-lg bg-gray-800 animate-pulse" />
          ))}
        </div>
      ) : !status?.available && !isBuilding ? (
        <div className="flex items-start gap-3 rounded-lg bg-yellow-900/10 border border-yellow-700/30
                        px-4 py-3">
          <AlertCircle className="w-4 h-4 text-yellow-400 mt-0.5 shrink-0" />
          <div className="flex-1 min-w-0">
            <p className="text-xs font-medium text-yellow-300">Graph not built for this project</p>
            <p className="text-xs text-gray-500 mt-0.5">
              Click "Build Now" to analyse call relationships, hub files, and communities.
              It builds automatically on the next Code Review scan too.
            </p>
            <p className="text-xs text-gray-600 mt-1">
              Path: <code className="text-gray-500">{scanPath}</code>
            </p>
          </div>
          <button
            onClick={triggerBuild}
            disabled={isBuilding}
            className="shrink-0 flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs
                       bg-gray-800 border border-gray-700 text-gray-300 hover:text-white
                       hover:border-gray-500 transition-colors disabled:opacity-50"
          >
            <Share2 className="w-3 h-3" />
            Build Now
          </button>
        </div>
      ) : status?.available ? (
        <>
          {/* Stats grid */}
          <div className="grid grid-cols-3 gap-3">
            <div className="rounded-lg bg-gray-800/60 border border-gray-700/40 px-3 py-2.5">
              <p className="text-xs text-gray-500 flex items-center gap-1 mb-1">
                <Network className="w-3 h-3 text-brand-400" /> Nodes
              </p>
              <p className="text-lg font-bold text-brand-400 tabular-nums">
                {status.nodes?.toLocaleString()}
              </p>
            </div>
            <div className="rounded-lg bg-gray-800/60 border border-gray-700/40 px-3 py-2.5">
              <p className="text-xs text-gray-500 flex items-center gap-1 mb-1">
                <Share2 className="w-3 h-3 text-purple-400" /> Edges
              </p>
              <p className="text-lg font-bold text-purple-400 tabular-nums">
                {status.edges?.toLocaleString()}
              </p>
            </div>
            <div className="rounded-lg bg-gray-800/60 border border-gray-700/40 px-3 py-2.5">
              <p className="text-xs text-gray-500 flex items-center gap-1 mb-1">
                <FileCode className="w-3 h-3 text-orange-400" /> Files
              </p>
              <p className="text-lg font-bold text-orange-400 tabular-nums">
                {status.files?.toLocaleString()}
              </p>
            </div>
          </div>

          {/* Languages + meta */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1.5 flex-wrap">
              <Layers className="w-3.5 h-3.5 text-gray-600" />
              {langs.map(l => (
                <span key={l}
                  className="text-xs px-2 py-0.5 rounded-full bg-gray-800 text-gray-400
                             border border-gray-700">
                  {l}
                </span>
              ))}
            </div>
            <div className="flex items-center gap-3 text-xs text-gray-600">
              {status.branch && (
                <span className="flex items-center gap-1">
                  <GitBranch className="w-3 h-3" /> {status.branch}
                  {status.commit && <code className="text-gray-700">{status.commit}</code>}
                </span>
              )}
              {status.last_updated && (
                <span>{new Date(status.last_updated).toLocaleString()}</span>
              )}
            </div>
          </div>

          {/* Rebuild link */}
          <div className="flex items-center justify-between">
            <p className="text-xs text-gray-600 flex items-center gap-1.5">
              <ExternalLink className="w-3 h-3" />
              Use <span className="text-brand-400 font-medium">Files</span> view for file names,
              <span className="text-brand-400 font-medium ml-1">Full</span> for classes &amp; methods.
            </p>
            <button
              onClick={triggerBuild}
              disabled={isBuilding}
              className="flex items-center gap-1 text-xs text-gray-600 hover:text-gray-400
                         transition-colors disabled:opacity-40"
              title="Rebuild graph"
            >
              <RefreshCw className="w-3 h-3" /> Rebuild
            </button>
          </div>
        </>
      ) : null}
    </div>
  );
}

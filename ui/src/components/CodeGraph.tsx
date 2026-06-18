import { useEffect, useState } from "react";
import { Network, FileCode, GitBranch, ExternalLink, RefreshCw, AlertCircle, Layers, Share2 } from "lucide-react";

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

interface Props {
  scanPath: string;
}

export function CodeGraph({ scanPath }: Props) {
  const [status,   setStatus]   = useState<GraphStatus | null>(null);
  const [loading,  setLoading]  = useState(true);
  const [building, setBuilding] = useState(false);

  function fetchStatus(path: string) {
    setLoading(true);
    fetch(`/api/v1/graph/status?scan_path=${encodeURIComponent(path)}`)
      .then(r => r.json())
      .then(d => { setStatus(d); setLoading(false); })
      .catch(() => { setStatus({ available: false }); setLoading(false); });
  }

  useEffect(() => {
    if (scanPath) fetchStatus(scanPath);
  }, [scanPath]);

  function openGraph() {
    window.open(
      `/api/v1/graph/visualization?scan_path=${encodeURIComponent(scanPath)}`,
      "_blank",
      "noopener,noreferrer"
    );
  }

  async function triggerBuild() {
    setBuilding(true);
    // Fire build via visualization endpoint (it will build then return HTML)
    try {
      await fetch(`/api/v1/graph/visualization?scan_path=${encodeURIComponent(scanPath)}`);
    } catch { /* ignore */ }
    fetchStatus(scanPath);
    setBuilding(false);
  }

  const langs = status?.languages?.split(",").map(l => l.trim()).filter(Boolean) ?? [];

  return (
    <div className="rounded-xl bg-gray-900 border border-gray-700/60 p-5 space-y-4">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Network className="w-4 h-4 text-brand-500" />
          <h3 className="text-sm font-semibold text-white">Code Knowledge Graph</h3>
          <span className="text-xs text-gray-600 font-mono truncate max-w-xs">{scanPath.split("/").slice(-2).join("/")}</span>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => fetchStatus(scanPath)}
            className="p-1.5 rounded-lg text-gray-500 hover:text-gray-300 hover:bg-gray-800 transition-colors"
            title="Refresh stats"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
          {status?.available && (
            <button
              onClick={openGraph}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium
                         bg-brand-600 hover:bg-brand-500 text-white transition-colors"
            >
              <ExternalLink className="w-3.5 h-3.5" /> Open Graph
            </button>
          )}
        </div>
      </div>

      {/* Body */}
      {loading ? (
        <div className="grid grid-cols-3 gap-3">
          {[...Array(3)].map((_, i) => (
            <div key={i} className="h-14 rounded-lg bg-gray-800 animate-pulse" />
          ))}
        </div>
      ) : !status?.available ? (
        <div className="flex items-start gap-3 rounded-lg bg-yellow-900/10 border border-yellow-700/30 px-4 py-3">
          <AlertCircle className="w-4 h-4 text-yellow-400 mt-0.5 shrink-0" />
          <div className="flex-1 min-w-0">
            <p className="text-xs font-medium text-yellow-300">Graph not built for this project</p>
            <p className="text-xs text-gray-500 mt-0.5">
              The knowledge graph will be built automatically on the next Code Review scan.
            </p>
          </div>
          <button
            onClick={triggerBuild}
            disabled={building}
            className="shrink-0 flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs
                       bg-gray-800 border border-gray-700 text-gray-300 hover:text-white
                       hover:border-gray-500 transition-colors disabled:opacity-50"
          >
            {building ? <RefreshCw className="w-3 h-3 animate-spin" /> : <Share2 className="w-3 h-3" />}
            {building ? "Building…" : "Build Now"}
          </button>
        </div>
      ) : (
        <>
          {/* Stats */}
          <div className="grid grid-cols-3 gap-3">
            <div className="rounded-lg bg-gray-800/60 border border-gray-700/40 px-3 py-2.5">
              <p className="text-xs text-gray-500 flex items-center gap-1 mb-1">
                <Network className="w-3 h-3 text-brand-400" /> Nodes
              </p>
              <p className="text-lg font-bold text-brand-400 tabular-nums">{status.nodes?.toLocaleString()}</p>
            </div>
            <div className="rounded-lg bg-gray-800/60 border border-gray-700/40 px-3 py-2.5">
              <p className="text-xs text-gray-500 flex items-center gap-1 mb-1">
                <Share2 className="w-3 h-3 text-purple-400" /> Edges
              </p>
              <p className="text-lg font-bold text-purple-400 tabular-nums">{status.edges?.toLocaleString()}</p>
            </div>
            <div className="rounded-lg bg-gray-800/60 border border-gray-700/40 px-3 py-2.5">
              <p className="text-xs text-gray-500 flex items-center gap-1 mb-1">
                <FileCode className="w-3 h-3 text-orange-400" /> Files
              </p>
              <p className="text-lg font-bold text-orange-400 tabular-nums">{status.files?.toLocaleString()}</p>
            </div>
          </div>

          {/* Languages + meta */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1.5 flex-wrap">
              <Layers className="w-3.5 h-3.5 text-gray-600" />
              {langs.map(l => (
                <span key={l} className="text-xs px-2 py-0.5 rounded-full bg-gray-800 text-gray-400 border border-gray-700">
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

          {/* Call to action hint */}
          <p className="text-xs text-gray-600 flex items-center gap-1.5">
            <ExternalLink className="w-3 h-3" />
            Click <span className="text-brand-400 font-medium">Open Graph</span> to explore call relationships, hub files, and community clusters interactively.
          </p>
        </>
      )}
    </div>
  );
}

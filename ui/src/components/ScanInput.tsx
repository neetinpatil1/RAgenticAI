import { useState } from "react";
import { motion } from "framer-motion";
import { FolderOpen, ShieldCheck, AlertCircle } from "lucide-react";
import { submitScan } from "../lib/api";

interface Props {
  onScanStarted: (runId: string, scanPath: string) => void;
}

export function ScanInput({ onScanStarted }: Props) {
  const [path, setPath]       = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState<string | null>(null);

  async function handleScan() {
    const trimmed = path.trim();
    if (!trimmed) return;
    setError(null);
    setLoading(true);
    try {
      const { run_id } = await submitScan(trimmed);
      onScanStarted(run_id, trimmed);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-6">
      <motion.div
        className="w-full max-w-2xl"
        initial={{ opacity: 0, y: 24 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
      >
        {/* Header */}
        <div className="flex items-center gap-3 mb-8">
          <div className="p-2 rounded-lg bg-brand-500/10 border border-brand-500/20">
            <ShieldCheck className="w-7 h-7 text-brand-500" />
          </div>
          <div>
            <h1 className="text-2xl font-semibold text-white tracking-tight">
              SSDLC Security Scanner
            </h1>
            <p className="text-sm text-gray-400 mt-0.5">
              AI-powered SAST — Semgrep + Qwen2.5-Coder analysis
            </p>
          </div>
        </div>

        {/* Input card */}
        <div className="rounded-xl bg-gray-900 border border-gray-700/60 p-6 shadow-xl">
          <label className="block text-sm text-gray-400 mb-2 font-medium">
            Project Root Path
          </label>
          <div className="flex gap-3">
            <div className="flex-1 relative">
              <FolderOpen className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
              <input
                type="text"
                value={path}
                onChange={(e) => setPath(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && !loading && handleScan()}
                placeholder="/Users/me/my-project"
                className="w-full bg-gray-800 border border-gray-600 rounded-lg pl-9 pr-4 py-2.5 text-sm text-gray-100
                           placeholder-gray-600 focus:outline-none focus:border-brand-500 focus:ring-1 focus:ring-brand-500/50
                           transition-colors"
              />
            </div>
            <motion.button
              onClick={handleScan}
              disabled={loading || !path.trim()}
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
              className="px-5 py-2.5 rounded-lg bg-brand-600 hover:bg-brand-500 disabled:opacity-40
                         disabled:cursor-not-allowed text-white text-sm font-semibold transition-colors
                         flex items-center gap-2"
            >
              {loading ? (
                <>
                  <span className="animate-spin inline-block w-4 h-4 border-2 border-white/30 border-t-white rounded-full" />
                  Starting…
                </>
              ) : (
                "Scan"
              )}
            </motion.button>
          </div>

          {error && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: "auto" }}
              className="mt-3 flex items-start gap-2 text-red-400 text-sm"
            >
              <AlertCircle className="w-4 h-4 mt-0.5 shrink-0" />
              <span>{error}</span>
            </motion.div>
          )}

          <p className="mt-4 text-xs text-gray-500">
            The backend will scan all supported files (.java, .py, .js, .ts, .go …) recursively.
            Semgrep OSS rules are applied; findings are enriched by the local LLM (Qwen2.5-Coder:14b).
          </p>
        </div>
      </motion.div>
    </div>
  );
}

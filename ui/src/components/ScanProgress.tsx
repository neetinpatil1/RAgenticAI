import { useEffect, useRef, useState } from "react";
import { motion, AnimatePresence, useSpring, useTransform } from "framer-motion";
import { Network, CheckCircle2, AlertTriangle, GitBranch, Share2, Layers } from "lucide-react";
import { openSseStream } from "../lib/api";
import type { SseEvent } from "../types";

interface Props {
  runId: string;
  scanPath: string;
  onComplete: (findingsCount: number) => void;
}

// ── Graph build stage labels ──────────────────────────────────────────────────
const GRAPH_STAGES: Array<[number, string]> = [
  [0,  "Initialising build…"],
  [6,  "Parsing source files…"],
  [18, "Resolving imports & call graphs…"],
  [38, "Computing communities & hub scores…"],
  [58, "Persisting graph to SQLite…"],
  [75, "Finalising index…"],
];

function graphStageLabel(elapsed: number): string {
  let label = GRAPH_STAGES[0][1];
  for (const [t, msg] of GRAPH_STAGES) {
    if (elapsed >= t) label = msg;
  }
  return label;
}

// ── Animated pulsing nodes (graph visualisation hint) ─────────────────────────
function GraphPulse() {
  const nodes = [
    { cx: 50,  cy: 30,  r: 5,  delay: 0    },
    { cx: 20,  cy: 60,  r: 4,  delay: 0.3  },
    { cx: 80,  cy: 55,  r: 6,  delay: 0.6  },
    { cx: 50,  cy: 80,  r: 4,  delay: 0.9  },
    { cx: 30,  cy: 20,  r: 3,  delay: 1.2  },
    { cx: 75,  cy: 20,  r: 3,  delay: 0.4  },
  ];
  const edges = [
    [0, 1], [0, 2], [1, 3], [2, 3], [0, 4], [0, 5], [2, 5],
  ];

  return (
    <svg viewBox="0 0 100 100" className="w-16 h-16">
      {/* Edges */}
      {edges.map(([a, b], i) => (
        <motion.line
          key={i}
          x1={nodes[a].cx} y1={nodes[a].cy}
          x2={nodes[b].cx} y2={nodes[b].cy}
          stroke="#3b82f6" strokeWidth="0.8" strokeOpacity="0.35"
          animate={{ strokeOpacity: [0.15, 0.5, 0.15] }}
          transition={{ duration: 2.4, delay: i * 0.2, repeat: Infinity }}
        />
      ))}
      {/* Nodes */}
      {nodes.map((n, i) => (
        <motion.circle
          key={i}
          cx={n.cx} cy={n.cy} r={n.r}
          fill="#3b82f6"
          animate={{ opacity: [0.4, 1, 0.4], r: [n.r, n.r + 1.5, n.r] }}
          transition={{ duration: 1.8, delay: n.delay, repeat: Infinity }}
        />
      ))}
    </svg>
  );
}

// ── Graph build banner ────────────────────────────────────────────────────────
type GraphPhase = "building" | "done" | "failed" | "idle";

function GraphBuildBanner({
  phase, elapsed, error,
}: {
  phase: GraphPhase;
  elapsed: number;
  error: string | null;
}) {
  const pct = Math.min(92, (elapsed / 90) * 100);

  if (phase === "idle") return null;

  return (
    <AnimatePresence>
      <motion.div
        key={phase}
        initial={{ opacity: 0, y: -12 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: -8 }}
        transition={{ duration: 0.3 }}
        className={`rounded-xl border px-5 py-4 space-y-3 ${
          phase === "done"
            ? "bg-green-950/20 border-green-700/40"
            : phase === "failed"
              ? "bg-yellow-950/20 border-yellow-700/40"
              : "bg-blue-950/20 border-blue-700/40"
        }`}
      >
        {/* Header row */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            {phase === "done" ? (
              <CheckCircle2 className="w-5 h-5 text-green-400 shrink-0" />
            ) : phase === "failed" ? (
              <AlertTriangle className="w-5 h-5 text-yellow-400 shrink-0" />
            ) : (
              <GraphPulse />
            )}

            <div>
              <p className={`text-sm font-semibold ${
                phase === "done" ? "text-green-300"
                : phase === "failed" ? "text-yellow-300"
                : "text-blue-300"
              }`}>
                {phase === "done"
                  ? "Code Knowledge Graph — Ready"
                  : phase === "failed"
                    ? "Graph unavailable — scan continues"
                    : "Building Code Knowledge Graph…"}
              </p>
              <p className="text-xs text-gray-500 mt-0.5">
                {phase === "done"
                  ? `Built in ${elapsed}s · call graphs, hub scores & communities indexed`
                  : phase === "failed"
                    ? (error ?? "Build failed — code review will run without graph context")
                    : graphStageLabel(elapsed)}
              </p>
            </div>
          </div>

          {phase === "building" && (
            <span className="text-xs text-gray-500 tabular-nums shrink-0">{elapsed}s</span>
          )}
        </div>

        {/* Progress bar — only while building */}
        {phase === "building" && (
          <div className="h-1 rounded-full bg-gray-800 overflow-hidden">
            <motion.div
              className="h-full rounded-full bg-blue-500"
              animate={{ width: `${pct}%` }}
              transition={{ duration: 1, ease: "linear" }}
            />
          </div>
        )}

        {/* Stats row — only when done */}
        {phase === "done" && (
          <div className="flex items-center gap-4 text-xs text-gray-500 pt-0.5">
            <span className="flex items-center gap-1"><Network className="w-3 h-3 text-blue-400" /> Nodes indexed</span>
            <span className="flex items-center gap-1"><Share2 className="w-3 h-3 text-purple-400" /> Call edges mapped</span>
            <span className="flex items-center gap-1"><Layers className="w-3 h-3 text-orange-400" /> Communities detected</span>
            <span className="flex items-center gap-1"><GitBranch className="w-3 h-3 text-green-400" /> Hub scores computed</span>
          </div>
        )}
      </motion.div>
    </AnimatePresence>
  );
}

// ── Animated number spring ─────────────────────────────────────────────────────
function SpringNumber({ value }: { value: number }) {
  const spring = useSpring(0, { stiffness: 80, damping: 20 });
  const display = useTransform(spring, (v) => Math.round(v).toLocaleString());
  useEffect(() => { spring.set(value); }, [value, spring]);
  return <motion.span>{display}</motion.span>;
}

// ── Circular progress ring ─────────────────────────────────────────────────────
function ProgressRing({ pct, size = 160 }: { pct: number; size?: number }) {
  const stroke = 10;
  const r = (size - stroke) / 2;
  const circ = 2 * Math.PI * r;
  const offset = circ - (pct / 100) * circ;
  const color = pct < 40 ? "#0ea5e9" : pct < 80 ? "#a855f7" : "#22c55e";

  return (
    <svg width={size} height={size} className="-rotate-90">
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#1f2937" strokeWidth={stroke} />
      <motion.circle
        cx={size / 2} cy={size / 2} r={r}
        fill="none" stroke={color} strokeWidth={stroke} strokeLinecap="round"
        strokeDasharray={circ}
        animate={{ strokeDashoffset: offset }}
        transition={{ type: "spring", stiffness: 60, damping: 18 }}
      />
    </svg>
  );
}

function formatEta(seconds: number): string {
  if (seconds <= 0) return "almost done";
  if (seconds < 60) return `~${seconds}s`;
  return `~${Math.ceil(seconds / 60)}m`;
}

// ── Main component ─────────────────────────────────────────────────────────────
export function ScanProgress({ runId, scanPath, onComplete }: Props) {
  const [pct,         setPct]         = useState(0);
  const [fileIndex,   setFileIndex]   = useState(0);
  const [totalFiles,  setTotalFiles]  = useState(0);
  const [currentFile, setCurrentFile] = useState<string>("");
  const [prevFile,    setPrevFile]    = useState<string>("");
  const [eta,         setEta]         = useState(0);
  const [statusText,  setStatusText]  = useState("Waiting for graph build…");
  const esRef = useRef<EventSource | null>(null);

  // Graph build state
  const [graphPhase,   setGraphPhase]   = useState<GraphPhase>("building");
  const [graphElapsed, setGraphElapsed] = useState(0);
  const [graphError,   setGraphError]   = useState<string | null>(null);
  const graphPollRef    = useRef<ReturnType<typeof setInterval> | null>(null);
  const graphElapsedRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // ── Graph build polling ────────────────────────────────────────────────────
  useEffect(() => {
    if (!scanPath) return;

    // Tick elapsed
    graphElapsedRef.current = setInterval(
      () => setGraphElapsed(s => s + 1), 1000
    );

    let polls = 0;
    const MAX_POLLS = 70;

    async function checkGraph() {
      polls++;
      if (polls > MAX_POLLS) {
        clearInterval(graphPollRef.current!);
        clearInterval(graphElapsedRef.current!);
        setGraphPhase("failed");
        setGraphError("Build timed out — code review will run without graph context");
        return;
      }
      try {
        const r = await fetch(
          `/api/v1/graph/build/status?scan_path=${encodeURIComponent(scanPath)}`
        );
        if (!r.ok) return;
        const d = await r.json();

        if (d.status === "done" || (d.status === "idle" && d.graph_exists)) {
          clearInterval(graphPollRef.current!);
          clearInterval(graphElapsedRef.current!);
          setGraphPhase("done");
          setStatusText("Scanning files…");
        } else if (d.status === "failed") {
          clearInterval(graphPollRef.current!);
          clearInterval(graphElapsedRef.current!);
          setGraphPhase("failed");
          setGraphError(d.error ?? null);
          setStatusText("Scanning files…");
        }
        // "building" or "idle" (not yet written) → keep polling
      } catch { /* network blip */ }
    }

    checkGraph();
    graphPollRef.current = setInterval(checkGraph, 3000);

    return () => {
      clearInterval(graphPollRef.current!);
      clearInterval(graphElapsedRef.current!);
    };
  }, [scanPath]);

  // ── SSE scan progress ──────────────────────────────────────────────────────
  useEffect(() => {
    const es = openSseStream(runId);
    esRef.current = es;

    es.onmessage = (e: MessageEvent) => {
      const evt: SseEvent = JSON.parse(e.data);

      if (evt.type === "status") {
        if (evt.state === "running") setStatusText("Scanning files…");
        if (evt.total_files) setTotalFiles(evt.total_files);
        if (evt.pct !== undefined) setPct(evt.pct);
      } else if (evt.type === "file") {
        setPrevFile(currentFile);
        setCurrentFile(evt.file);
        setFileIndex(evt.index);
        setTotalFiles(evt.total);
        setPct(evt.pct);
        setEta(evt.eta_seconds);
        setStatusText("Scanning files…");
      } else if (evt.type === "done") {
        setPct(100);
        setStatusText(evt.state === "completed" ? "Scan complete" : "Scan failed");
        setFileIndex(evt.total_files);
        setTotalFiles(evt.total_files);
        setTimeout(() => onComplete(evt.findings_count), 800);
      } else if (evt.type === "error") {
        setStatusText(`Error: ${evt.message}`);
      }
    };

    es.onerror = () => { setStatusText("Connection lost — retrying…"); };
    return () => { es.close(); };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [runId]);

  const projectName = scanPath.split("/").pop() ?? scanPath;

  return (
    <div className="min-h-screen flex items-center justify-center p-6">
      <motion.div
        className="w-full max-w-xl space-y-4"
        initial={{ opacity: 0, scale: 0.97 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.35 }}
      >
        {/* ── Graph build banner ── */}
        <GraphBuildBanner
          phase={graphPhase}
          elapsed={graphElapsed}
          error={graphError}
        />

        {/* ── SAST scan card ── */}
        <div className="rounded-xl bg-gray-900 border border-gray-700/60 p-8 shadow-xl space-y-8">
          {/* Title */}
          <div className="text-center">
            <p className="text-xs text-gray-500 uppercase tracking-widest mb-1">Scanning</p>
            <h2 className="text-lg font-semibold text-white truncate">{projectName}</h2>
            <p className="text-xs text-gray-600 truncate mt-0.5">{scanPath}</p>
          </div>

          {/* Ring + counter */}
          <div className="flex flex-col items-center gap-4">
            <div className="relative">
              <ProgressRing pct={pct} size={168} />
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-3xl font-bold text-white tabular-nums">{pct}%</span>
                <span className="text-xs text-gray-500 mt-0.5">{statusText}</span>
              </div>
            </div>

            <div className="flex items-baseline gap-1 text-2xl font-semibold tabular-nums">
              <SpringNumber value={fileIndex} />
              <span className="text-gray-500 text-sm font-normal">/ {totalFiles.toLocaleString()} files</span>
            </div>
          </div>

          {/* Current filename */}
          <div className="rounded-lg bg-gray-800/60 border border-gray-700 px-4 py-3 min-h-[52px]
                          flex items-center overflow-hidden">
            <AnimatePresence mode="popLayout">
              {currentFile ? (
                <motion.p
                  key={currentFile}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -8 }}
                  transition={{ duration: 0.18 }}
                  className="text-xs font-mono text-brand-500 truncate"
                >
                  <span className="text-gray-500 mr-2">→</span>
                  {currentFile}
                </motion.p>
              ) : (
                <motion.p
                  key="waiting"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="text-xs text-gray-600"
                >
                  {graphPhase === "building"
                    ? "Waiting for graph build to complete…"
                    : "Waiting for scan to start…"}
                </motion.p>
              )}
            </AnimatePresence>
          </div>

          {/* ETA + prev file */}
          <div className="flex justify-between text-xs text-gray-600">
            <span>
              {prevFile && (
                <>Last: <span className="text-gray-500 truncate max-w-[200px] inline-block align-bottom">{prevFile}</span></>
              )}
            </span>
            <span>{eta > 0 ? `ETA: ${formatEta(eta)}` : ""}</span>
          </div>

          {/* Progress bar */}
          <div className="w-full h-1.5 rounded-full bg-gray-800">
            <motion.div
              className="h-full rounded-full bg-brand-500"
              animate={{ width: `${pct}%` }}
              transition={{ type: "spring", stiffness: 60, damping: 18 }}
            />
          </div>
        </div>
      </motion.div>
    </div>
  );
}

import { useEffect, useRef, useState } from "react";
import { motion, AnimatePresence, useSpring, useTransform } from "framer-motion";
import { openSseStream } from "../lib/api";
import type { SseEvent } from "../types";

interface Props {
  runId: string;
  scanPath: string;
  onComplete: (findingsCount: number) => void;
}

// Animated number spring
function SpringNumber({ value }: { value: number }) {
  const spring = useSpring(0, { stiffness: 80, damping: 20 });
  const display = useTransform(spring, (v) => Math.round(v).toLocaleString());

  useEffect(() => { spring.set(value); }, [value, spring]);

  return <motion.span>{display}</motion.span>;
}

// Circular progress ring
function ProgressRing({ pct, size = 160 }: { pct: number; size?: number }) {
  const stroke = 10;
  const r = (size - stroke) / 2;
  const circ = 2 * Math.PI * r;
  const offset = circ - (pct / 100) * circ;

  const color =
    pct < 40 ? "#0ea5e9" :
    pct < 80 ? "#a855f7" :
               "#22c55e";

  return (
    <svg width={size} height={size} className="-rotate-90">
      {/* Track */}
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#1f2937" strokeWidth={stroke} />
      {/* Progress */}
      <motion.circle
        cx={size / 2} cy={size / 2} r={r}
        fill="none"
        stroke={color}
        strokeWidth={stroke}
        strokeLinecap="round"
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

export function ScanProgress({ runId, scanPath, onComplete }: Props) {
  const [pct,          setPct]          = useState(0);
  const [fileIndex,    setFileIndex]    = useState(0);
  const [totalFiles,   setTotalFiles]   = useState(0);
  const [currentFile,  setCurrentFile]  = useState<string>("");
  const [prevFile,     setPrevFile]     = useState<string>("");
  const [eta,          setEta]          = useState(0);
  const [statusText,   setStatusText]   = useState("Initialising scan…");
  const esRef = useRef<EventSource | null>(null);

  useEffect(() => {
    const es = openSseStream(runId);
    esRef.current = es;

    es.onmessage = (e: MessageEvent) => {
      const evt: SseEvent = JSON.parse(e.data);

      if (evt.type === "status") {
        setStatusText(evt.state === "running" ? "Scanning…" : evt.state);
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

    es.onerror = () => {
      setStatusText("Connection lost — retrying…");
    };

    return () => { es.close(); };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [runId]);

  const projectName = scanPath.split("/").pop() ?? scanPath;

  return (
    <div className="min-h-screen flex items-center justify-center p-6">
      <motion.div
        className="w-full max-w-xl"
        initial={{ opacity: 0, scale: 0.97 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.35 }}
      >
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

            {/* File counter */}
            <div className="flex items-baseline gap-1 text-2xl font-semibold tabular-nums">
              <SpringNumber value={fileIndex} />
              <span className="text-gray-500 text-sm font-normal">/ {totalFiles.toLocaleString()} files</span>
            </div>
          </div>

          {/* Current filename with fade animation */}
          <div className="rounded-lg bg-gray-800/60 border border-gray-700 px-4 py-3 min-h-[52px]
                          flex items-center overflow-hidden">
            <AnimatePresence mode="popLayout">
              {currentFile && (
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
              )}
              {!currentFile && (
                <motion.p
                  key="waiting"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="text-xs text-gray-600"
                >
                  Waiting for scan to start…
                </motion.p>
              )}
            </AnimatePresence>
          </div>

          {/* ETA + prev file hint */}
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

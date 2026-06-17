import { useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { ScanInput } from "./components/ScanInput";
import { ScanProgress } from "./components/ScanProgress";
import { ScanResults } from "./components/ScanResults";

type Screen = "input" | "progress" | "results";

export default function App() {
  const [screen,    setScreen]    = useState<Screen>("input");
  const [runId,     setRunId]     = useState<string>("");
  const [scanPath,  setScanPath]  = useState<string>("");

  function handleScanStarted(id: string, path: string) {
    setRunId(id);
    setScanPath(path);
    setScreen("progress");
  }

  function handleScanComplete(_count: number) {
    setScreen("results");
  }

  function handleNewScan() {
    setScreen("input");
    setRunId("");
    setScanPath("");
  }

  return (
    <div className="min-h-screen bg-gray-950">
      <AnimatePresence mode="wait">
        {screen === "input" && (
          <motion.div
            key="input"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.25 }}
          >
            <ScanInput onScanStarted={handleScanStarted} />
          </motion.div>
        )}

        {screen === "progress" && (
          <motion.div
            key="progress"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.25 }}
          >
            <ScanProgress
              runId={runId}
              scanPath={scanPath}
              onComplete={handleScanComplete}
            />
          </motion.div>
        )}

        {screen === "results" && (
          <motion.div
            key="results"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.25 }}
          >
            <ScanResults runId={runId} onNewScan={handleNewScan} />
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

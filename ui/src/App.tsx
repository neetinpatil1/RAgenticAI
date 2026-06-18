import { useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { NavBar }       from "./components/NavBar";
import { ScanInput }    from "./components/ScanInput";
import { ScanProgress } from "./components/ScanProgress";
import { ScanResults }  from "./components/ScanResults";
import { ScanHistory }  from "./components/ScanHistory";
import { CodeGraph }    from "./components/CodeGraph";

type Screen = "input" | "progress" | "results" | "history" | "graph";

export default function App() {
  const [screen,   setScreen]   = useState<Screen>("input");
  const [runId,    setRunId]    = useState<string>("");
  const [scanPath, setScanPath] = useState<string>("");

  function handleScanStarted(id: string, path: string) {
    setRunId(id);
    setScanPath(path);
    setScreen("progress");
  }

  function handleScanComplete(_count: number) {
    setScreen("results");
  }

  function handleViewResults(id: string) {
    setRunId(id);
    setScreen("results");
  }

  function handleNewScan() {
    setScreen("input");
    setRunId("");
    setScanPath("");
  }

  function handleNavigate(s: Screen) {
    if (s === "input") { handleNewScan(); return; }
    setScreen(s);
  }

  // NavBar hidden during full-screen progress animation
  const showNav = screen !== "progress";
  // Active nav tab
  const activeNav: Screen = screen === "history" ? "history" : screen === "graph" ? "graph" : "input";

  return (
    <div className="min-h-screen bg-gray-950 flex flex-col">
      {showNav && <NavBar current={activeNav} onNavigate={handleNavigate} />}

      <main className="flex-1">
        <AnimatePresence mode="wait">
          {screen === "input" && (
            <motion.div key="input"
              initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              transition={{ duration: 0.2 }}
            >
              <ScanInput onScanStarted={handleScanStarted} />
            </motion.div>
          )}

          {screen === "progress" && (
            <motion.div key="progress"
              initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              transition={{ duration: 0.2 }}
            >
              <ScanProgress runId={runId} scanPath={scanPath} onComplete={handleScanComplete} />
            </motion.div>
          )}

          {screen === "results" && (
            <motion.div key={`results-${runId}`}
              initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              transition={{ duration: 0.2 }}
            >
              <ScanResults runId={runId} onNewScan={handleNewScan} />
            </motion.div>
          )}

          {screen === "history" && (
            <motion.div key="history"
              initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              transition={{ duration: 0.2 }}
            >
              <ScanHistory onViewResults={handleViewResults} />
            </motion.div>
          )}

          {screen === "graph" && (
            <motion.div key="graph"
              initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              transition={{ duration: 0.2 }}
            >
              <CodeGraph />
            </motion.div>
          )}
        </AnimatePresence>
      </main>
    </div>
  );
}

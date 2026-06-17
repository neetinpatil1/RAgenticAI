import { motion } from "framer-motion";
import { ShieldCheck, History, ScanLine } from "lucide-react";

type Screen = "input" | "progress" | "results" | "history";

interface Props {
  current: Screen;
  onNavigate: (screen: Screen) => void;
}

export function NavBar({ current, onNavigate }: Props) {
  const links: { id: Screen; label: string; icon: React.ReactNode; disabled?: boolean }[] = [
    { id: "input",   label: "New Scan",     icon: <ScanLine  className="w-4 h-4" /> },
    { id: "history", label: "Scan History", icon: <History   className="w-4 h-4" /> },
  ];

  return (
    <header className="sticky top-0 z-50 bg-gray-950/90 backdrop-blur border-b border-gray-800">
      <div className="max-w-7xl mx-auto px-6 h-14 flex items-center justify-between">
        {/* Logo */}
        <button
          onClick={() => onNavigate("input")}
          className="flex items-center gap-2.5 group"
        >
          <div className="p-1.5 rounded-lg bg-brand-500/10 border border-brand-500/20 group-hover:bg-brand-500/20 transition-colors">
            <ShieldCheck className="w-5 h-5 text-brand-500" />
          </div>
          <span className="font-semibold text-white tracking-tight text-sm">
            SSDLC Scanner
          </span>
        </button>

        {/* Nav links */}
        <nav className="flex items-center gap-1">
          {links.map((link) => {
            const active = current === link.id;
            return (
              <button
                key={link.id}
                onClick={() => !link.disabled && onNavigate(link.id)}
                disabled={link.disabled}
                className={`relative flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm font-medium
                            transition-colors disabled:opacity-40 disabled:cursor-not-allowed
                            ${active
                              ? "text-white"
                              : "text-gray-400 hover:text-white hover:bg-gray-800"
                            }`}
              >
                {link.icon}
                {link.label}
                {active && (
                  <motion.div
                    layoutId="nav-indicator"
                    className="absolute inset-0 rounded-lg bg-gray-800 -z-10"
                    transition={{ type: "spring", stiffness: 300, damping: 30 }}
                  />
                )}
              </button>
            );
          })}
        </nav>
      </div>
    </header>
  );
}

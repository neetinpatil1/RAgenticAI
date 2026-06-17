import type { Severity } from "../types";

const STYLES: Record<Severity, string> = {
  CRITICAL: "bg-red-600/20 text-red-400 border border-red-600/40",
  HIGH:     "bg-orange-600/20 text-orange-400 border border-orange-600/40",
  MEDIUM:   "bg-yellow-600/20 text-yellow-400 border border-yellow-600/40",
  LOW:      "bg-blue-600/20 text-blue-400 border border-blue-600/40",
  INFO:     "bg-gray-600/20 text-gray-400 border border-gray-600/40",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`inline-block px-2 py-0.5 rounded text-xs font-semibold tracking-wide ${STYLES[severity] ?? STYLES.INFO}`}>
      {severity}
    </span>
  );
}

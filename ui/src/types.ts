export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface Finding {
  id: string;
  run_id: string;
  rule_id: string;
  cwe_id: string | null;
  severity: Severity;
  file_path: string;
  line_start: number;
  line_end: number | null;
  code_snippet: string | null;
  message: string;
  framework: string;
  class_name: string | null;
  method_name: string | null;
  fix_suggestion: string | null;
  owasp_category: string | null;
  ref_urls: string[];
  likelihood: string | null;
  impact: string | null;
  is_baseline: boolean;
  created_at: string;
  verdict: string | null;
  confidence: number | null;
  fp_category: string | null;
  reasoning: string | null;
  label_status: string | null;
}

export interface ScanCoverage {
  files_scanned: number;
  files_with_findings: number;
  files_clean: number;
  files_skipped: number;
  packages_total: number;
  packages_by_file: { file: string; count: number; type: string }[];
  scan_duration_ms: number;
}

export interface ScanStatus {
  run_id: string;
  status: string;
  scan_path: string;
  created_at: string | null;
  completed_at: string | null;
  error: string | null;
  scan_coverage: ScanCoverage;
  findings: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    baseline: number;
    total: number;
  };
}

// SSE event shapes
export type SseEvent =
  | { type: "status";   state: string; total_files?: number; pct?: number }
  | { type: "file";     file: string;  index: number; total: number; pct: number; eta_seconds: number }
  | { type: "progress"; pct: number;   eta_seconds: number }
  | { type: "done";     state: string; findings_count: number; total_files: number }
  | { type: "error";    message: string };

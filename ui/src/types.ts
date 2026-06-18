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
  blast_radius: number | null;
  is_baseline: boolean;
  created_at: string;
  verdict: string | null;
  confidence: number | null;
  fp_category: string | null;
  reasoning: string | null;
  label_status: string | null;
  fp_source: string | null;
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

export type ReviewCategory = "SECURITY" | "PERFORMANCE" | "CODE_QUALITY" | "ERROR_HANDLING" | "BEST_PRACTICES";

export interface CodeReviewFinding {
  id: string;
  run_id: string;
  file_path: string;
  language: string;
  category: ReviewCategory;
  severity: Severity;
  line_start: number | null;
  line_end: number | null;
  title: string;
  description: string;
  recommendation: string;
  confidence: number;
  overall_file_score: number | null;
  created_at: string;
}

export interface CodeReviewSummary {
  files_reviewed: number;
  total_findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  security: number;
  performance: number;
  code_quality: number;
  error_handling: number;
  best_practices: number;
}

export interface RunSummary {
  run_id: string;
  scan_path: string;
  project_name: string;
  state: string;
  created_at: string | null;
  completed_at: string | null;
  duration_ms: number;
  error: string | null;
  severity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
}

export interface SecretFinding {
  id: string;
  run_id: string;
  file_path: string;
  line_start: number | null;
  secret_type: string;
  severity: Severity;
  description: string;
  match_preview: string;
  entropy: number | null;
  context_line: string | null;
  created_at: string;
}

export interface SecretSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  files_with_secrets: number;
}

export interface DependencyFinding {
  id: string;
  run_id: string;
  package_name: string;
  installed_version: string | null;
  fixed_version: string | null;
  vulnerability_id: string;
  severity: Severity;
  description: string;
  ecosystem: string;
  file_path: string | null;
  created_at: string;
}

export interface DependencySummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  python: number;
  npm: number;
  maven: number;
}

// SSE event shapes
export type SseEvent =
  | { type: "status";   state: string; total_files?: number; pct?: number }
  | { type: "file";     file: string;  index: number; total: number; pct: number; eta_seconds: number }
  | { type: "progress"; pct: number;   eta_seconds: number }
  | { type: "done";     state: string; findings_count: number; total_files: number }
  | { type: "error";    message: string };

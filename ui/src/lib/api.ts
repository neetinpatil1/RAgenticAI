import type { ScanStatus, Finding, RunSummary, CodeReviewFinding, CodeReviewSummary, SecretFinding, SecretSummary, DependencyFinding, DependencySummary } from "../types";

const BASE = "/api/v1";

export async function submitScan(path: string): Promise<{ run_id: string }> {
  const res = await fetch(`${BASE}/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ path }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail ?? "Failed to start scan");
  }
  return res.json();
}

export async function getScanStatus(runId: string): Promise<ScanStatus> {
  const res = await fetch(`${BASE}/scan/${runId}`);
  if (!res.ok) throw new Error(`Status fetch failed: ${res.status}`);
  return res.json();
}

export async function getFindings(runId: string): Promise<Finding[]> {
  const res = await fetch(`${BASE}/findings?run_id=${encodeURIComponent(runId)}&limit=200`);
  if (!res.ok) throw new Error(`Findings fetch failed: ${res.status}`);
  const data = await res.json();
  return data.findings ?? [];
}

export async function getRuns(limit = 50): Promise<RunSummary[]> {
  const res = await fetch(`${BASE}/runs?limit=${limit}`);
  if (!res.ok) throw new Error(`Runs fetch failed: ${res.status}`);
  const data = await res.json();
  return data.runs ?? [];
}

export async function triggerCodeReview(runId: string): Promise<{ message: string }> {
  const res = await fetch(`${BASE}/review/${runId}`, { method: "POST" });
  if (!res.ok) throw new Error(`Code review trigger failed: ${res.status}`);
  return res.json();
}

export async function getCodeReview(runId: string): Promise<{ findings: CodeReviewFinding[]; summary: CodeReviewSummary; count: number }> {
  const res = await fetch(`${BASE}/review/${runId}?limit=500`);
  if (!res.ok) throw new Error(`Code review fetch failed: ${res.status}`);
  return res.json();
}

/** Open an SSE connection for real-time scan progress. */
export function openSseStream(runId: string): EventSource {
  return new EventSource(`${BASE}/scan/${runId}/stream`);
}

export async function getCodeReviewProgress(runId: string): Promise<{
  status: string; pct: number; files_done: number; total_files: number;
  current_file: string | null; findings_count: number;
}> {
  const res = await fetch(`${BASE}/review/${runId}/progress`);
  if (!res.ok) throw new Error(`Progress fetch failed: ${res.status}`);
  return res.json();
}

export async function getSecretFindings(runId: string): Promise<{ findings: SecretFinding[]; summary: SecretSummary; count: number }> {
  const res = await fetch(`${BASE}/secrets/${runId}?limit=500`);
  if (!res.ok) throw new Error(`Secret findings fetch failed: ${res.status}`);
  return res.json();
}

export async function getDependencyFindings(runId: string): Promise<{ findings: DependencyFinding[]; summary: DependencySummary; count: number }> {
  const res = await fetch(`${BASE}/dependencies/${runId}?limit=500`);
  if (!res.ok) throw new Error(`Dependency findings fetch failed: ${res.status}`);
  return res.json();
}

export async function getFpChallengeProgress(runId: string): Promise<{
  status: string; pct: number; findings_done: number; findings_total: number;
  fp_found: number; current_finding: string | null;
}> {
  const res = await fetch(`${BASE}/fp-challenge/${runId}/progress`);
  if (!res.ok) throw new Error(`FP challenge progress fetch failed: ${res.status}`);
  return res.json();
}

export async function triggerFpChallenge(runId: string): Promise<{ message: string }> {
  const res = await fetch(`${BASE}/fp-challenge/${runId}`, { method: "POST" });
  if (!res.ok) throw new Error(`FP challenge trigger failed: ${res.status}`);
  return res.json();
}

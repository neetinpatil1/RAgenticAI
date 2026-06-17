import type { ScanStatus, Finding } from "../types";

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

/** Open an SSE connection for real-time scan progress. */
export function openSseStream(runId: string): EventSource {
  return new EventSource(`${BASE}/scan/${runId}/stream`);
}

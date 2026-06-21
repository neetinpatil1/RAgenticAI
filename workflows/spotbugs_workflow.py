"""
workflows/spotbugs_workflow.py
================================
SpotBugs + FindSecBugs workflow — Java bytecode SAST.

Runs after SAST (Step 2), in parallel with Secrets + SCA.
Inserts net-new findings (not already found by Semgrep) into findings_reports
with tool='findsecbugs' and source='findsecbugs'.

Dedup logic: skip any finding where a row already exists in findings_reports
for the same run_id with (file_path, line_start, cwe_id) to avoid doubling
issues Semgrep already caught at source level.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import asyncpg

from tools.spotbugs_tool import SpotBugsTool, SpotBugsFinding

logger = logging.getLogger(__name__)


def _read_code_context(
    abs_path: str,
    line_start: Optional[int],
    line_end: Optional[int],
    context_lines: int = 3,
) -> Optional[str]:
    """Read vulnerable lines + surrounding context from source file."""
    if not abs_path or line_start is None:
        return None
    try:
        with open(abs_path, encoding="utf-8", errors="replace") as f:
            all_lines = f.readlines()
    except (OSError, IOError):
        return None
    end = line_end or line_start
    ctx_start = max(0, line_start - 1 - context_lines)
    ctx_end   = min(len(all_lines), end + context_lines)
    output = []
    for i in range(ctx_start, ctx_end):
        lineno = i + 1
        code   = all_lines[i].rstrip()
        prefix = ">>>" if line_start <= lineno <= end else "   "
        output.append(f"{prefix} {lineno:4d} | {code}")
    return "\n".join(output) or None


async def run_spotbugs_workflow(
    run_id:    str,
    scan_path: str,
    pool:      asyncpg.Pool,
) -> None:
    """
    Entry point — called from _run_all_agents() in Step 2 (parallel with SAST/Secrets/SCA).
    """
    import time as _t
    _start = _t.time()
    logger.info("SpotBugs | START | run=%s path=%s", run_id, scan_path)

    try:
        tool = SpotBugsTool(timeout=300)
        findings = await tool.scan(scan_path)

        if not findings:
            logger.info("SpotBugs | no findings (or not a Java project) | run=%s", run_id)
            await _mark_done(pool, run_id, 0, 0)
            return

        logger.info("SpotBugs | raw findings=%d | run=%s", len(findings), run_id)

        # Dedup against existing Semgrep findings for this run
        net_new = await _dedup(findings, run_id, pool)
        logger.info("SpotBugs | net-new after dedup=%d | run=%s", len(net_new), run_id)

        inserted = await _insert_findings(net_new, run_id, scan_path, pool)
        elapsed = _t.time() - _start
        logger.info("SpotBugs | COMPLETE | inserted=%d elapsed=%.1fs | run=%s",
                    inserted, elapsed, run_id)
        await _mark_done(pool, run_id, len(findings), inserted)

    except Exception as exc:
        logger.error("SpotBugs | FATAL | run=%s error=%s", run_id, exc)
        await _mark_done(pool, run_id, 0, 0)


async def _dedup(
    findings: list[SpotBugsFinding],
    run_id:   str,
    pool:     asyncpg.Pool,
) -> list[SpotBugsFinding]:
    """
    Remove findings already reported by Semgrep for this run.
    Match on (file_path, line_start, cwe_id) — same vulnerability at same location.
    """
    try:
        async with pool.acquire() as conn:
            existing = await conn.fetch(
                """SELECT file_path, line_start, cwe_id
                   FROM findings_reports
                   WHERE run_id = $1""",
                run_id,
            )
        # Build a set of (file_path, line_start, cwe_id) tuples
        seen: set[tuple] = {
            (r["file_path"], r["line_start"], r["cwe_id"])
            for r in existing
        }
        net_new = []
        for f in findings:
            key = (f.file_path, f.line_start, f.cwe_id)
            if key not in seen:
                net_new.append(f)
        return net_new
    except Exception as exc:
        logger.warning("SpotBugs | dedup error: %s — inserting all findings", exc)
        return findings


async def _insert_findings(
    findings:  list[SpotBugsFinding],
    run_id:    str,
    scan_path: str,
    pool:      asyncpg.Pool,
) -> int:
    """Insert net-new SpotBugs/FindSecBugs findings into findings_reports."""
    if not findings:
        return 0

    inserted = 0
    root = Path(scan_path)

    async with pool.acquire() as conn:
        for f in findings:
            # Generate deterministic fingerprint
            fp_src = f"{run_id}|{f.rule_id}|{f.file_path}|{f.line_start}"
            fingerprint = hashlib.sha256(fp_src.encode()).hexdigest()[:16]

            # Read source code snippet.
            # SpotBugs file_path is a bytecode class path (e.g. org/foo/Bar.java).
            # Try candidate locations in order until the file is found on disk.
            code_snippet = None
            if f.file_path:
                candidates = [
                    root / f.file_path,                           # direct (rare)
                    root / "src" / "main" / "java" / f.file_path, # Maven standard layout
                    root / "src" / f.file_path,
                ]
                for candidate in candidates:
                    snippet = _read_code_context(str(candidate), f.line_start, f.line_end)
                    if snippet:
                        code_snippet = snippet
                        break

            try:
                await conn.execute(
                    """INSERT INTO findings_reports
                       (run_id, fingerprint, tool, rule_id, cwe_id, severity,
                        file_path, line_start, line_end, code_snippet, message, framework,
                        class_name, method_name, owasp_category,
                        ref_urls, is_baseline, created_at)
                       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
                               $12, $13, $14, $15, $16, false, $17)
                       ON CONFLICT DO NOTHING""",
                    run_id,
                    fingerprint,
                    "findsecbugs",
                    f.rule_id,
                    f.cwe_id,
                    f.severity,
                    f.file_path,
                    f.line_start,
                    f.line_end,
                    code_snippet,
                    f.message,
                    "java",
                    f.class_name,
                    f.method_name,
                    f.owasp_category,
                    json.dumps([]),
                    datetime.now(timezone.utc),
                )
                inserted += 1
            except Exception as exc:
                logger.warning("SpotBugs | insert error for %s: %s", f.file_path, exc)

    return inserted


async def _mark_done(
    pool:         asyncpg.Pool,
    run_id:       str,
    total_found:  int,
    inserted:     int,
) -> None:
    """Write spotbugs completion flag to workflow_runs.metadata (merge, not replace)."""
    try:
        async with pool.acquire() as conn:
            patch = json.dumps({
                "spotbugs": {
                    "total_found": total_found,
                    "inserted":    inserted,
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                }
            })
            await conn.execute(
                """UPDATE workflow_runs
                   SET metadata = COALESCE(metadata, '{}'::jsonb) || $1::jsonb
                   WHERE run_id = $2""",
                patch,
                run_id,
            )
    except Exception as exc:
        logger.warning("SpotBugs | _mark_done failed: %s", exc)

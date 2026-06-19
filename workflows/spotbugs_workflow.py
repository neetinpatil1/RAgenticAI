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

import asyncpg

from tools.spotbugs_tool import SpotBugsTool, SpotBugsFinding

logger = logging.getLogger(__name__)


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

            try:
                await conn.execute(
                    """INSERT INTO findings_reports
                       (run_id, fingerprint, tool, rule_id, cwe_id, severity,
                        file_path, line_start, line_end, message, framework,
                        class_name, method_name, owasp_category,
                        ref_urls, is_baseline, created_at)
                       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
                               $12, $13, $14, $15, false, $16)
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

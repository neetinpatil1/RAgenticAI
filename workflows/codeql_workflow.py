"""
workflows/codeql_workflow.py
============================
LangGraph-style workflow for the CodeQL deep SAST agent.

Triggered only when the scan is submitted with `deep=True`.
Runs after the normal SAST pipeline (Semgrep) completes so that findings
already in the DB can be used for deduplication.

Steps:
  1. Check CodeQL CLI availability — skip gracefully if absent.
  2. Run `CodeQLTool.scan(scan_path, run_id)`.
  3. Insert net-new findings into `findings_reports` (dedup by run_id + file_path
     + line_start + rule_id via ON CONFLICT DO NOTHING).
  4. Update `workflow_runs.metadata["codeql"]` with completion info.

Design notes:
  - No complex LangGraph state needed — simple async function.
  - Mirrors the INSERT pattern in workflows/sast_workflow.py exactly.
  - Every failure logs a warning and exits cleanly — never raises to caller.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

import asyncpg

from tools.codeql_tool import CodeQLTool, CodeQLStats

logger = logging.getLogger(__name__)


async def run_codeql_workflow(
    run_id: str,
    scan_path: str,
    pool: asyncpg.Pool,
) -> CodeQLStats:
    """
    Entry point for the CodeQL deep-scan workflow.

    Args:
        run_id:    Workflow run identifier (same run as the SAST scan).
        scan_path: Absolute path to the source tree being scanned.
        pool:      asyncpg connection pool.

    Returns:
        CodeQLStats with outcome details.
    """
    tool = CodeQLTool()

    # ── Step 1: availability check ────────────────────────────────────────────
    if not tool.is_available():
        logger.warning(
            "CodeQL workflow: CLI not found — skipping | run=%s", run_id
        )
        skipped_stats = CodeQLStats(
            language="unknown",
            db_created=False,
            findings_count=0,
            query_pack="",
            db_size_mb=0.0,
            duration_ms=0,
            skipped=True,
            skip_reason="codeql CLI not found",
        )
        await _write_metadata(pool, run_id, skipped_stats)
        return skipped_stats

    logger.info("CodeQL workflow: starting | run=%s path=%s", run_id, scan_path)

    # ── Step 2: run scan ──────────────────────────────────────────────────────
    try:
        findings, stats = await tool.scan(scan_path, run_id)
    except Exception as exc:
        logger.warning(
            "CodeQL workflow: scan raised unexpectedly | run=%s error=%s", run_id, exc
        )
        stats = CodeQLStats(
            language="unknown",
            db_created=False,
            findings_count=0,
            query_pack="",
            db_size_mb=0.0,
            duration_ms=0,
            skipped=True,
            skip_reason=str(exc),
        )
        await _write_metadata(pool, run_id, stats)
        return stats

    if stats.skipped:
        logger.warning(
            "CodeQL workflow: scan skipped | run=%s reason=%s", run_id, stats.skip_reason
        )
        await _write_metadata(pool, run_id, stats)
        return stats

    # ── Step 3: insert net-new findings ──────────────────────────────────────
    inserted = 0
    if findings:
        try:
            inserted = await _insert_findings(pool, run_id, findings)
        except Exception as exc:
            logger.warning(
                "CodeQL workflow: findings insert error | run=%s error=%s", run_id, exc
            )
            # Non-fatal — still update metadata with what we found

    # ── Step 4: write metadata ────────────────────────────────────────────────
    stats.findings_count = inserted  # reflect net-new (post-dedup) count
    await _write_metadata(pool, run_id, stats)

    logger.info(
        "CodeQL workflow: complete | run=%s inserted=%d lang=%s duration_ms=%d",
        run_id, inserted, stats.language, stats.duration_ms,
    )
    return stats


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

async def _insert_findings(
    pool: asyncpg.Pool,
    run_id: str,
    findings: list,
) -> int:
    """
    Insert CodeQL findings into findings_reports.

    Deduplication: ON CONFLICT DO NOTHING on (run_id, file_path, line_start, rule_id).
    This prevents duplicate rows when CodeQL and Semgrep find the same issue.

    Returns the number of rows actually inserted.
    """
    inserted = 0

    async with pool.acquire() as conn:
        for finding in findings:
            finding_id = str(uuid.uuid4())

            async with conn.transaction():
                result = await conn.execute(
                    """
                    INSERT INTO findings_reports
                        (id, run_id, fingerprint, tool, rule_id, cwe_id, severity,
                         file_path, line_start, line_end, code_snippet, message,
                         framework, is_baseline,
                         class_name, method_name, fix_suggestion,
                         owasp_category, ref_urls, likelihood, impact)
                    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,
                            $15,$16,$17,$18,$19::jsonb,$20,$21)
                    ON CONFLICT DO NOTHING
                    """,
                    finding_id,
                    run_id,
                    finding.fingerprint,
                    "codeql",                          # tool identifier
                    finding.rule_id,
                    finding.cwe_id,
                    finding.severity.value,
                    finding.file_path,
                    finding.line_start,
                    finding.line_end,
                    finding.code_snippet,
                    finding.message,
                    finding.framework.value,
                    False,                             # not baseline — CodeQL is always post-first-scan
                    finding.class_name,
                    finding.method_name,
                    finding.fix_suggestion,
                    finding.owasp_category,
                    json.dumps(finding.references),
                    finding.likelihood,
                    finding.impact,
                )

            # asyncpg returns "INSERT 0 N" — count actual inserts
            if result and result.startswith("INSERT"):
                parts = result.split()
                if len(parts) >= 3:
                    try:
                        n = int(parts[2])
                        inserted += n
                    except ValueError:
                        pass

    return inserted


async def _write_metadata(
    pool: asyncpg.Pool,
    run_id: str,
    stats: CodeQLStats,
) -> None:
    """
    Merge CodeQL outcome into workflow_runs.metadata["codeql"].

    Reads the current metadata JSON, patches the "codeql" sub-key,
    and writes it back.  Does not overwrite other metadata keys
    (e.g., "secret_scan", "sca", "files_scanned").
    """
    codeql_meta: dict = {
        "skipped":        stats.skipped,
        "skip_reason":    stats.skip_reason if stats.skipped else None,
        "language":       stats.language,
        "db_created":     stats.db_created,
        "findings_count": stats.findings_count,
        "query_pack":     stats.query_pack,
        "db_size_mb":     stats.db_size_mb,
        "duration_ms":    stats.duration_ms,
    }
    if not stats.skipped:
        codeql_meta["completed_at"] = datetime.now(timezone.utc).isoformat()

    try:
        async with pool.acquire() as conn:
            # Read existing metadata
            raw = await conn.fetchval(
                "SELECT metadata FROM workflow_runs WHERE run_id = $1", run_id
            )
            existing: dict = {}
            if raw:
                if isinstance(raw, str):
                    try:
                        existing = json.loads(raw)
                    except Exception:
                        existing = {}
                elif isinstance(raw, dict):
                    existing = raw

            existing["codeql"] = codeql_meta

            await conn.execute(
                "UPDATE workflow_runs SET metadata = $1::jsonb WHERE run_id = $2",
                json.dumps(existing),
                run_id,
            )
    except Exception as exc:
        logger.warning(
            "CodeQL workflow: metadata write failed | run=%s error=%s", run_id, exc
        )

"""
workflows/secret_scan_workflow.py
===================================
LangGraph workflow for the Secret Scanner Agent — Phase 1.

Scans every file in the project for hardcoded secrets, API keys, tokens,
and credentials using regex patterns and Shannon entropy analysis.

Workflow nodes:
  start → scan_files → write_findings → complete
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import TypedDict, Optional

import asyncpg
from langgraph.graph import StateGraph, END

from tools.secret_scanner_tool import SecretScannerTool

logger = logging.getLogger(__name__)


class SecretScanState(TypedDict):
    run_id:             str
    scan_path:          str
    findings_count:     int
    files_scanned:      int
    files_with_secrets: int
    error:              Optional[str]


async def node_start(state: SecretScanState, deps: dict) -> SecretScanState:
    logger.info("Secret scan started | run=%s path=%s", state["run_id"], state["scan_path"])
    pool: asyncpg.Pool = deps["pool"]
    async with pool.acquire() as conn:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS secret_findings (
                id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                run_id        TEXT NOT NULL,
                file_path     TEXT NOT NULL,
                line_start    INT,
                secret_type   TEXT NOT NULL,
                severity      TEXT NOT NULL,
                description   TEXT,
                match_preview TEXT,
                entropy       REAL,
                context_line  TEXT,
                created_at    TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_secrets_run ON secret_findings(run_id)"
        )
    return state


async def node_scan_files(state: SecretScanState, deps: dict) -> SecretScanState:
    scanner = SecretScannerTool()
    try:
        # Run the synchronous scanner in a thread pool so it doesn't block the
        # asyncio event loop (which would stall SAST + SCA running in parallel).
        # 5-minute hard timeout — prevents hanging on huge directories or ReDoS.
        loop = asyncio.get_event_loop()
        findings, stats = await asyncio.wait_for(
            loop.run_in_executor(None, scanner.scan, state["scan_path"]),
            timeout=300,
        )
    except asyncio.TimeoutError:
        logger.error(
            "Secret scan timed out after 5 minutes | run=%s path=%s",
            state["run_id"], state["scan_path"],
        )
        return {**state, "error": "scan_timeout", "findings_count": 0, "files_scanned": 0, "files_with_secrets": 0}
    except Exception as exc:
        logger.error("Secret scan failed | run=%s error=%s", state["run_id"], exc)
        return {**state, "error": str(exc), "findings_count": 0, "files_scanned": 0, "files_with_secrets": 0}

    pool: asyncpg.Pool = deps["pool"]
    run_id = state["run_id"]

    if findings:
        async with pool.acquire() as conn:
            for f in findings:
                await conn.execute(
                    """
                    INSERT INTO secret_findings
                        (id, run_id, file_path, line_start, secret_type, severity,
                         description, match_preview, entropy, context_line)
                    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
                    """,
                    str(uuid.uuid4()), run_id,
                    f.file_path, f.line_start,
                    f.secret_type, f.severity,
                    f.description, f.match_preview,
                    f.entropy, f.context_line,
                )

    logger.info(
        "Secret scan complete | run=%s findings=%d files_scanned=%d",
        run_id, len(findings), stats["files_scanned"],
    )
    return {
        **state,
        "findings_count":     len(findings),
        "files_scanned":      stats["files_scanned"],
        "files_with_secrets": stats["files_with_secrets"],
    }


async def node_complete(state: SecretScanState, deps: dict) -> SecretScanState:
    pool: asyncpg.Pool = deps["pool"]
    run_id = state["run_id"]
    import json
    async with pool.acquire() as conn:
        existing = await conn.fetchval(
            "SELECT metadata FROM workflow_runs WHERE run_id = $1", run_id
        )
        meta: dict = {}
        if existing:
            try:
                meta = json.loads(existing) if isinstance(existing, str) else (existing or {})
            except Exception:
                meta = {}
        meta["secret_scan"] = {
            "findings_count":     state.get("findings_count", 0),
            "files_scanned":      state.get("files_scanned", 0),
            "files_with_secrets": state.get("files_with_secrets", 0),
            "completed_at":       datetime.now(timezone.utc).isoformat(),
        }
        await conn.execute(
            "UPDATE workflow_runs SET metadata = $1::jsonb WHERE run_id = $2",
            json.dumps(meta), run_id,
        )
    logger.info("Secret scan workflow complete | run=%s", run_id)
    return state


def build_secret_scan_graph(deps: dict):
    async def start(state):    return await node_start(state, deps)
    async def scan(state):     return await node_scan_files(state, deps)
    async def complete(state): return await node_complete(state, deps)

    graph = StateGraph(SecretScanState)
    graph.add_node("start",    start)
    graph.add_node("scan",     scan)
    graph.add_node("complete", complete)
    graph.set_entry_point("start")
    graph.add_edge("start",    "scan")
    graph.add_edge("scan",     "complete")
    graph.add_edge("complete", END)
    return graph.compile()


async def run_secret_scan_workflow(run_id: str, scan_path: str, deps: dict) -> dict:
    app = build_secret_scan_graph(deps)
    initial: SecretScanState = {
        "run_id":             run_id,
        "scan_path":          scan_path,
        "findings_count":     0,
        "files_scanned":      0,
        "files_with_secrets": 0,
        "error":              None,
    }
    try:
        return await app.ainvoke(initial)
    except Exception as exc:
        logger.error("Secret scan workflow crashed | run=%s error=%s", run_id, exc, exc_info=True)
        raise

"""
workflows/sca_workflow.py
==========================
LangGraph workflow for the SCA (Software Composition Analysis) Agent — Phase 1.

Scans all dependency manifests (requirements.txt, package.json, pom.xml) and
checks for known CVEs using pip-audit, npm audit, and the OSV.dev API.

Workflow nodes:
  start → scan_dependencies → write_findings → complete
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import TypedDict, Optional

import asyncpg
from langgraph.graph import StateGraph, END

from tools.sca_tool import SCATool

logger = logging.getLogger(__name__)


class ScaWorkflowState(TypedDict):
    run_id:          str
    scan_path:       str
    findings_count:  int
    packages_total:  int
    ecosystems:      dict     # {python: N, npm: N, maven: N}
    error:           Optional[str]


async def node_start(state: ScaWorkflowState, deps: dict) -> ScaWorkflowState:
    logger.info("SCA workflow started | run=%s path=%s", state["run_id"], state["scan_path"])
    pool: asyncpg.Pool = deps["pool"]
    async with pool.acquire() as conn:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS dependency_findings (
                id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                run_id            TEXT NOT NULL,
                package_name      TEXT NOT NULL,
                installed_version TEXT,
                fixed_version     TEXT,
                vulnerability_id  TEXT NOT NULL,
                severity          TEXT NOT NULL,
                description       TEXT,
                ecosystem         TEXT NOT NULL,
                file_path         TEXT,
                created_at        TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_dep_findings_run ON dependency_findings(run_id)"
        )
    return state


async def node_scan_dependencies(state: ScaWorkflowState, deps: dict) -> ScaWorkflowState:
    tool = SCATool()
    run_id = state["run_id"]
    try:
        findings, stats = await tool.scan(state["scan_path"])
    except Exception as exc:
        logger.error("SCA scan failed | run=%s error=%s", run_id, exc)
        return {**state, "error": str(exc), "findings_count": 0, "packages_total": 0, "ecosystems": {}}

    pool: asyncpg.Pool = deps["pool"]

    if findings:
        async with pool.acquire() as conn:
            for f in findings:
                await conn.execute(
                    """
                    INSERT INTO dependency_findings
                        (id, run_id, package_name, installed_version, fixed_version,
                         vulnerability_id, severity, description, ecosystem, file_path)
                    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
                    """,
                    str(uuid.uuid4()), run_id,
                    f.package_name, f.installed_version, f.fixed_version,
                    f.vulnerability_id, f.severity,
                    f.description, f.ecosystem, f.file_path,
                )

    logger.info(
        "SCA scan complete | run=%s findings=%d total_packages=%d",
        run_id, len(findings), stats.get("total_packages", 0),
    )
    return {
        **state,
        "findings_count": len(findings),
        "packages_total": stats.get("total_packages", 0),
        "ecosystems":     {
            "python": stats.get("python", 0),
            "npm":    stats.get("npm", 0),
            "maven":  stats.get("maven", 0),
        },
    }


async def node_complete(state: ScaWorkflowState, deps: dict) -> ScaWorkflowState:
    pool: asyncpg.Pool = deps["pool"]
    run_id = state["run_id"]
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
        meta["sca"] = {
            "findings_count": state.get("findings_count", 0),
            "packages_total": state.get("packages_total", 0),
            "ecosystems":     state.get("ecosystems", {}),
            "completed_at":   datetime.now(timezone.utc).isoformat(),
        }
        await conn.execute(
            "UPDATE workflow_runs SET metadata = $1::jsonb WHERE run_id = $2",
            json.dumps(meta), run_id,
        )
    logger.info("SCA workflow complete | run=%s", run_id)
    return state


def build_sca_graph(deps: dict):
    async def start(state):    return await node_start(state, deps)
    async def scan(state):     return await node_scan_dependencies(state, deps)
    async def complete(state): return await node_complete(state, deps)

    graph = StateGraph(ScaWorkflowState)
    graph.add_node("start",    start)
    graph.add_node("scan",     scan)
    graph.add_node("complete", complete)
    graph.set_entry_point("start")
    graph.add_edge("start",    "scan")
    graph.add_edge("scan",     "complete")
    graph.add_edge("complete", END)
    return graph.compile()


async def run_sca_workflow(run_id: str, scan_path: str, deps: dict) -> dict:
    app = build_sca_graph(deps)
    initial: ScaWorkflowState = {
        "run_id":         run_id,
        "scan_path":      scan_path,
        "findings_count": 0,
        "packages_total": 0,
        "ecosystems":     {},
        "error":          None,
    }
    try:
        return await app.ainvoke(initial)
    except Exception as exc:
        logger.error("SCA workflow crashed | run=%s error=%s", run_id, exc, exc_info=True)
        raise

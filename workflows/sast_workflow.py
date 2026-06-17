"""
workflows/sast_workflow.py
===========================
LangGraph workflow for the SAST Agent — Phase 0.

Design (SSDLC_Design_v3.2.docx §8):
  - LangGraph manages INTRA-AGENT state only (tool retries, LLM calls,
    reasoning steps within this one agent).
  - INTER-AGENT state lives in PostgreSQL (pg_jobs + workflow_runs).
  - Every state write goes to PG before the next step begins.
    If this agent crashes, the watchdog detects it and can replay from PG.

Workflow nodes (Phase 0):
  start_scan → run_semgrep → write_findings → run_fp_pipeline → enqueue_next → done

State:
  SastWorkflowState — typed TypedDict passed through LangGraph nodes.
  Written to PG at each major transition via WorkflowState.

Inputs:
  run_id    — created by main.py / FastAPI before workflow starts
  scan_path — local filesystem path to scan
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import TypedDict, Optional, Annotated
import json

import asyncpg
from langgraph.graph import StateGraph, END

from core.config import settings
from core.audit_logger import AuditLogger, AuditEvent
from core.pg_job_queue import PGJobQueue, JobType
from core.prompt_manager import PromptManager
from core.state.workflow_state import WorkflowState
from core.state.vector_memory import VectorMemory
from core.output_contracts.sast_report import SASTFinding, SASTReport
from core.output_contracts.fp_decision import (
    FPDecision, FPVerdict, FPBatchResult, LabelStatus, LABEL_WEIGHT
)
from core.fp_pipeline.layer1_rules import Layer1Rules
from core.fp_pipeline.layer3_llm import Layer3LLM
from tools.semgrep_tool import SemgrepTool

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# LangGraph State — typed dict carried through all workflow nodes
# ---------------------------------------------------------------------------
class SastWorkflowState(TypedDict):
    # Inputs (set before workflow starts)
    run_id:       str
    scan_path:    str

    # Set by run_semgrep node
    raw_findings: list[dict]          # serialised SASTFinding dicts
    scan_duration_ms: int
    files_scanned: int

    # Set by write_findings node
    finding_db_ids: dict[str, str]    # fingerprint → DB UUID mapping

    # Set by run_fp_pipeline node
    fp_results:   list[dict]          # serialised FPDecision dicts
    fp_summary:   dict                # counts: real, fp, escalated, deadlock

    # Error tracking
    error:        Optional[str]


# ---------------------------------------------------------------------------
# Workflow Node Functions
# ---------------------------------------------------------------------------

async def node_start_scan(state: SastWorkflowState, deps: dict) -> SastWorkflowState:
    """
    Node 1: Mark workflow as running in PostgreSQL.
    This is the recovery checkpoint — watchdog knows the scan started.
    """
    run_id = state["run_id"]
    wf_state: WorkflowState = deps["workflow_state"]
    audit: AuditLogger = deps["audit"]

    await wf_state.set_running(run_id)
    await audit.log(
        event_type=AuditEvent.SCAN_STARTED,
        actor="sast_agent",
        run_id=run_id,
        entity_type="workflow_run",
        entity_id=run_id,
        payload={"scan_path": state["scan_path"]},
    )
    logger.info("SAST workflow started | run=%s path=%s", run_id, state["scan_path"])
    return state


async def node_run_semgrep(state: SastWorkflowState, deps: dict) -> SastWorkflowState:
    """
    Node 2: Execute Semgrep scan in Docker sandbox.
    Writes raw findings into state — not yet persisted to DB.
    """
    tool: SemgrepTool = deps["semgrep_tool"]
    audit: AuditLogger = deps["audit"]
    run_id = state["run_id"]

    start = datetime.now(timezone.utc)
    try:
        findings: list[SASTFinding] = await tool.scan(state["scan_path"])
    except Exception as exc:
        logger.error("Semgrep scan failed | run=%s error=%s", run_id, exc)
        await audit.log(
            event_type=AuditEvent.WORKFLOW_FAILED,
            actor="sast_agent",
            run_id=run_id,
            payload={"error": str(exc), "stage": "semgrep"},
        )
        return {**state, "error": str(exc), "raw_findings": []}

    elapsed_ms = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)

    # Serialise findings to dicts for state (LangGraph state must be serialisable)
    findings_dicts = [f.model_dump() for f in findings]

    logger.info(
        "Semgrep complete | run=%s findings=%d duration=%dms",
        run_id, len(findings), elapsed_ms
    )
    return {
        **state,
        "raw_findings": findings_dicts,
        "scan_duration_ms": elapsed_ms,
        "files_scanned": 0,        # populated from Semgrep output in full impl
    }


async def node_write_findings(state: SastWorkflowState, deps: dict) -> SastWorkflowState:
    """
    Node 3: Persist findings to PostgreSQL findings_reports table.

    Handles baseline detection:
      - If this is the first scan of a path, all findings are BASELINE.
      - Baseline findings don't block releases (SSDLC_Design_v3.2.docx §9.2).

    Returns mapping of fingerprint → DB UUID for FP pipeline use.
    """
    pool: asyncpg.Pool = deps["pool"]
    audit: AuditLogger = deps["audit"]
    vector_memory: VectorMemory = deps["vector_memory"]
    run_id = state["run_id"]

    findings = [SASTFinding(**f) for f in state["raw_findings"]]
    if not findings:
        return {**state, "finding_db_ids": {}}

    # Detect if this path has been scanned before (baseline detection)
    async with pool.acquire() as conn:
        existing_count = await conn.fetchval(
            """
            SELECT COUNT(*) FROM findings_reports fr
            JOIN workflow_runs wr ON wr.run_id = fr.run_id
            WHERE wr.scan_path = $1 AND wr.run_id != $2
            """,
            state["scan_path"], run_id,
        )
    is_first_scan = (existing_count == 0)

    finding_db_ids: dict[str, str] = {}

    async with pool.acquire() as conn:
        for finding in findings:
            finding_id = str(uuid.uuid4())
            embed_text = f"{finding.message}\n\n{finding.code_snippet or ''}"

            async with conn.transaction():
                # Insert finding
                await conn.execute(
                    """
                    INSERT INTO findings_reports
                        (id, run_id, fingerprint, tool, rule_id, cwe_id, severity,
                         file_path, line_start, line_end, code_snippet, message,
                         framework, is_baseline)
                    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
                    ON CONFLICT DO NOTHING
                    """,
                    finding_id, run_id, finding.fingerprint, "semgrep",
                    finding.rule_id, finding.cwe_id, finding.severity.value,
                    finding.file_path, finding.line_start, finding.line_end,
                    finding.code_snippet, finding.message,
                    finding.framework.value, is_first_scan,
                )

            finding_db_ids[finding.fingerprint] = finding_id

            # Generate and store embedding for Layer 3 retrieval (fire-and-forget)
            try:
                await vector_memory.store_finding_embedding(
                    finding_id=finding_id,
                    text=embed_text,
                )
            except Exception as exc:
                # Embedding failure must not block the pipeline
                logger.warning("Embedding failed | finding=%s error=%s", finding_id, exc)

            # Audit: baseline findings are logged separately
            event = AuditEvent.FINDING_BASELINE if is_first_scan else AuditEvent.FINDING_CREATED
            await audit.log(
                event_type=event,
                actor="sast_agent",
                run_id=run_id,
                entity_type="finding",
                entity_id=finding_id,
                payload={
                    "rule_id": finding.rule_id,
                    "severity": finding.severity.value,
                    "is_baseline": is_first_scan,
                },
            )

    logger.info(
        "Findings written | run=%s count=%d baseline=%s",
        run_id, len(findings), is_first_scan
    )
    return {**state, "finding_db_ids": finding_db_ids}


async def node_run_fp_pipeline(state: SastWorkflowState, deps: dict) -> SastWorkflowState:
    """
    Node 4: Run 3-layer FP pipeline on all findings.

    Layer 1 → fast YAML rules (<5ms each)
    Layer 3 → LLM analysis for unresolved findings (2–8s each)

    Layer 2 (CodeBERT) is disabled in Phase 0 — activates in Phase 1
    once ≥150 human-confirmed labels exist per segment.
    """
    layer1: Layer1Rules = deps["layer1_rules"]
    layer3: Layer3LLM = deps["layer3_llm"]
    pool: asyncpg.Pool = deps["pool"]
    audit: AuditLogger = deps["audit"]
    run_id = state["run_id"]
    finding_db_ids = state["finding_db_ids"]

    findings = [SASTFinding(**f) for f in state["raw_findings"]]
    decisions: list[FPDecision] = []
    counters = {"real": 0, "fp": 0, "escalated": 0, "deadlock": 0}

    for finding in findings:
        db_id = finding_db_ids.get(finding.fingerprint, finding.fingerprint)

        # --- Layer 1: YAML rule-based filter ---
        l1_decision = layer1.evaluate(finding, run_id)
        if l1_decision:
            # Layer 1 resolved — update finding_id to actual DB ID
            l1_decision = l1_decision.model_copy(update={"finding_id": db_id})
            decisions.append(l1_decision)
            counters["fp"] += 1
            await audit.log(
                event_type=AuditEvent.FP_LAYER1_RESOLVED,
                actor="sast_agent",
                run_id=run_id,
                entity_type="finding",
                entity_id=db_id,
                payload={"fp_category": l1_decision.fp_category},
            )
            continue

        # --- Layer 3: LLM + pgvector (no Layer 2 in Phase 0) ---
        try:
            l3_decision = await layer3.evaluate(
                finding=finding,
                run_id=run_id,
                finding_db_id=db_id,
                use_tier1=True,
            )
            decisions.append(l3_decision)

            if l3_decision.verdict == FPVerdict.REAL:
                counters["real"] += 1
            elif l3_decision.verdict == FPVerdict.FP:
                counters["fp"] += 1
            elif l3_decision.verdict == FPVerdict.ESCALATED:
                counters["escalated"] += 1
            elif l3_decision.verdict == FPVerdict.DEADLOCK:
                counters["deadlock"] += 1

            await audit.log(
                event_type=AuditEvent.FP_LAYER3_DECIDED,
                actor="sast_agent",
                run_id=run_id,
                entity_type="finding",
                entity_id=db_id,
                payload={
                    "verdict": l3_decision.verdict.value,
                    "confidence": l3_decision.confidence,
                },
            )

        except Exception as exc:
            # FP pipeline failure → treat as ESCALATED, don't crash
            logger.error("FP pipeline error | finding=%s error=%s", db_id, exc)
            decisions.append(FPDecision(
                finding_id=db_id,
                run_id=run_id,
                verdict=FPVerdict.ESCALATED,
                source="layer3_llm",   # type: ignore
                confidence=0.0,
                reasoning=f"Pipeline error: {exc}",
                fp_category=None,
            ))
            counters["escalated"] += 1

    # Persist FP decisions to DB
    async with pool.acquire() as conn:
        for decision in decisions:
            await conn.execute(
                """
                INSERT INTO fp_decisions
                    (finding_id, run_id, verdict, source, confidence,
                     fp_category, reasoning, label_status)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
                """,
                decision.finding_id, decision.run_id,
                decision.verdict.value, decision.source.value,
                decision.confidence, decision.fp_category,
                decision.reasoning, decision.label_status.value,
            )

    return {
        **state,
        "fp_results": [d.model_dump() for d in decisions],
        "fp_summary": {**counters, "total": len(decisions)},
    }


async def node_enqueue_next(state: SastWorkflowState, deps: dict) -> SastWorkflowState:
    """
    Node 5: Enqueue next pipeline job and update workflow state.

    Phase 0: after SAST + FP, the scan is considered complete.
    Phase 1+: enqueue code_review.pending for the Code Review Agent.

    DEADLOCK findings go to human.review.pending queue.
    """
    job_queue: PGJobQueue = deps["job_queue"]
    wf_state: WorkflowState = deps["workflow_state"]
    audit: AuditLogger = deps["audit"]
    run_id = state["run_id"]
    fp_summary = state.get("fp_summary", {})

    # Enqueue deadlocked findings for human review
    deadlocked = [
        d for d in state.get("fp_results", [])
        if d.get("verdict") == FPVerdict.DEADLOCK.value
    ]
    if deadlocked:
        await job_queue.enqueue(
            job_type=JobType.HUMAN_REVIEW_PENDING,
            run_id=run_id,
            payload={"finding_ids": [d["finding_id"] for d in deadlocked]},
            priority=2,  # high priority — human review queue
        )

    # Phase 0: mark scan complete
    await job_queue.enqueue(
        job_type=JobType.SCAN_COMPLETED,
        run_id=run_id,
        payload={"fp_summary": fp_summary},
        priority=5,
    )

    await wf_state.set_completed(run_id)
    await audit.log(
        event_type=AuditEvent.SCAN_COMPLETED,
        actor="sast_agent",
        run_id=run_id,
        payload=fp_summary,
    )

    logger.info(
        "SAST workflow complete | run=%s real=%d fp=%d escalated=%d deadlock=%d",
        run_id,
        fp_summary.get("real", 0),
        fp_summary.get("fp", 0),
        fp_summary.get("escalated", 0),
        fp_summary.get("deadlock", 0),
    )
    return state


def should_continue_after_semgrep(state: SastWorkflowState) -> str:
    """Conditional edge: if Semgrep errored, skip to done."""
    return "write_findings" if not state.get("error") else END


# ---------------------------------------------------------------------------
# Build LangGraph Graph
# ---------------------------------------------------------------------------

def build_sast_graph(deps: dict):
    """
    Construct the SAST LangGraph workflow.

    deps: dict of injected dependencies (pool, tools, services).
          Passed to each node via closure.

    Returns: compiled LangGraph app ready for .ainvoke()
    """
    # Wrap each node to inject deps via closure
    async def start(state):  return await node_start_scan(state, deps)
    async def semgrep(state): return await node_run_semgrep(state, deps)
    async def write(state):   return await node_write_findings(state, deps)
    async def fp(state):      return await node_run_fp_pipeline(state, deps)
    async def enqueue(state): return await node_enqueue_next(state, deps)

    graph = StateGraph(SastWorkflowState)

    graph.add_node("start_scan",      start)
    graph.add_node("run_semgrep",     semgrep)
    graph.add_node("write_findings",  write)
    graph.add_node("run_fp_pipeline", fp)
    graph.add_node("enqueue_next",    enqueue)

    graph.set_entry_point("start_scan")
    graph.add_edge("start_scan", "run_semgrep")
    graph.add_conditional_edges(
        "run_semgrep",
        should_continue_after_semgrep,
        {"write_findings": "write_findings", END: END},
    )
    graph.add_edge("write_findings",  "run_fp_pipeline")
    graph.add_edge("run_fp_pipeline", "enqueue_next")
    graph.add_edge("enqueue_next",    END)

    return graph.compile()


async def run_sast_workflow(
    run_id: str,
    scan_path: str,
    deps: dict,
) -> dict:
    """
    Entry point to execute the SAST workflow for a given scan path.

    Args:
        run_id:    Unique run identifier (created by caller).
        scan_path: Local filesystem path to scan.
        deps:      Injected dependencies dict.

    Returns:
        Final workflow state dict with fp_summary and results.
    """
    app = build_sast_graph(deps)

    initial_state: SastWorkflowState = {
        "run_id":         run_id,
        "scan_path":      scan_path,
        "raw_findings":   [],
        "scan_duration_ms": 0,
        "files_scanned":  0,
        "finding_db_ids": {},
        "fp_results":     [],
        "fp_summary":     {},
        "error":          None,
    }

    final_state = await app.ainvoke(initial_state)
    return final_state

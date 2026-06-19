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
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
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
    files_skipped: int
    files_with_findings: int
    skip_reasons: dict
    packages_total: int
    packages_by_file: list

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

    Graph build is now triggered in POST /api/v1/scan (agent_gateway.py) using
    the proper _run_graph_build background task so the UI polling sees
    "building" → "done" immediately when a scan starts.
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
        findings, scan_stats = await tool.scan(state["scan_path"])
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

    # Count packages from build files (pom.xml, build.gradle, requirements.txt, package.json)
    pkg_stats = tool.count_packages(state["scan_path"])

    # Serialise findings to dicts for state (LangGraph state must be serialisable)
    findings_dicts = [f.model_dump() for f in findings]

    logger.info(
        "Semgrep complete | run=%s findings=%d files_scanned=%d packages=%d duration=%dms",
        run_id, len(findings), scan_stats["files_scanned"], pkg_stats["total"], elapsed_ms,
    )
    return {
        **state,
        "raw_findings":        findings_dicts,
        "scan_duration_ms":    elapsed_ms,
        "files_scanned":       scan_stats["files_scanned"],
        "files_skipped":       scan_stats["files_skipped"],
        "files_with_findings": scan_stats["files_with_findings"],
        "skip_reasons":        scan_stats["skip_reasons"],
        "packages_total":      pkg_stats["total"],
        "packages_by_file":    pkg_stats["by_file"],
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
                # Insert finding with all enrichment fields
                await conn.execute(
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
                    finding_id, run_id, finding.fingerprint, "semgrep",
                    finding.rule_id, finding.cwe_id, finding.severity.value,
                    finding.file_path, finding.line_start, finding.line_end,
                    finding.code_snippet, finding.message,
                    finding.framework.value, is_first_scan,
                    finding.class_name, finding.method_name, finding.fix_suggestion,
                    finding.owasp_category,
                    json.dumps(finding.references),
                    finding.likelihood, finding.impact,
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

    # Feature 2: Blast radius enrichment from code-review-graph
    _enrich_blast_radius(state["scan_path"], finding_db_ids, findings, pool)

    # Write scan coverage stats to DB NOW so the UI shows files_scanned immediately
    # (not waiting until node_enqueue_next after the FP pipeline finishes).
    early_stats = {
        "files_scanned":       state.get("files_scanned", 0),
        "files_skipped":       state.get("files_skipped", 0),
        "files_with_findings": state.get("files_with_findings", 0),
        "files_clean":         max(0, state.get("files_scanned", 0) - state.get("files_with_findings", 0)),
        "skip_reasons":        state.get("skip_reasons", {}),
        "packages_total":      state.get("packages_total", 0),
        "packages_by_file":    state.get("packages_by_file", []),
        "scan_duration_ms":    state.get("scan_duration_ms", 0),
    }
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE workflow_runs SET metadata = $1::jsonb WHERE run_id = $2",
                json.dumps(early_stats),
                run_id,
            )
        logger.info(
            "Findings written | run=%s count=%d files_scanned=%d baseline=%s",
            run_id, len(findings), early_stats["files_scanned"], is_first_scan
        )
    except Exception as exc:
        logger.warning("Could not write early scan stats | run=%s error=%s", run_id, exc)

    return {**state, "finding_db_ids": finding_db_ids}


def _enrich_blast_radius(
    scan_path: str,
    finding_db_ids: dict[str, str],
    findings: list,
    pool: asyncpg.Pool,
) -> None:
    """
    Feature 2: Query code-review-graph for blast radius of each HIGH/CRITICAL finding.

    Blast radius = max caller_count across all symbols in that file.
    Updates findings_reports.blast_radius in a fire-and-forget asyncio task
    so it never blocks the pipeline.
    """
    db_path = Path(scan_path) / ".code-review-graph" / "graph.db"
    if not db_path.exists():
        return  # Graph not built yet — blast radius will be NULL

    # Build file → max_caller_count from graph
    file_blast: dict[str, int] = {}
    try:
        conn = sqlite3.connect(str(db_path), timeout=5)
        rows = conn.execute(
            "SELECT qualified_name, caller_count FROM risk_index WHERE caller_count > 0"
        ).fetchall()
        for qname, callers in rows:
            fp = qname.split("::")[0] if "::" in qname else qname
            if (callers or 0) > file_blast.get(fp, 0):
                file_blast[fp] = int(callers)
        conn.close()
    except Exception as exc:
        logger.warning("blast_radius: graph DB read failed: %s", exc)
        return

    if not file_blast:
        return

    # Schedule async DB updates as a background task
    async def _update_blast_radii() -> None:
        async with pool.acquire() as conn:
            for finding in findings:
                # Only enrich HIGH and CRITICAL findings
                if finding.severity.value not in ("HIGH", "CRITICAL"):
                    continue
                blast = file_blast.get(finding.file_path, 0)
                if blast == 0:
                    continue
                db_id = finding_db_ids.get(finding.fingerprint)
                if not db_id:
                    continue
                try:
                    await conn.execute(
                        "UPDATE findings_reports SET blast_radius = $1 WHERE id = $2",
                        blast, db_id,
                    )
                except Exception as exc:
                    logger.warning("blast_radius: DB update failed for %s: %s", db_id, exc)

        logger.info("blast_radius: enriched findings for run")

    # Fire-and-forget — doesn't block the workflow
    try:
        loop = asyncio.get_event_loop()
        loop.create_task(_update_blast_radii())
    except RuntimeError:
        pass  # No running loop — skip silently


async def node_run_fp_pipeline(state: SastWorkflowState, deps: dict) -> SastWorkflowState:
    """
    Node 4: Run 3-layer FP pipeline on all findings.

    Layer 1 → fast YAML rules (<5ms each)
    Layer 3 → LLM analysis for unresolved findings (2–8s each, max 5 concurrent)

    Layer 2 (CodeBERT) is disabled in Phase 0 — activates in Phase 1
    once ≥150 human-confirmed labels exist per segment.
    """
    import time as _t
    layer1: Layer1Rules = deps["layer1_rules"]
    layer3: Layer3LLM = deps["layer3_llm"]
    pool: asyncpg.Pool = deps["pool"]
    audit: AuditLogger = deps["audit"]
    run_id = state["run_id"]
    finding_db_ids = state["finding_db_ids"]

    findings = [SASTFinding(**f) for f in state["raw_findings"]]
    decisions: list[FPDecision] = []
    counters = {"real": 0, "fp": 0, "escalated": 0, "deadlock": 0}

    _fp_start = _t.time()
    logger.info("FP pipeline START | run=%s total_findings=%d", run_id, len(findings))

    # --- Layer 1: fast YAML rules — run synchronously for all findings ---
    _l1_start = _t.time()
    l3_queue: list[tuple[SASTFinding, str]] = []  # findings that need Layer 3
    for finding in findings:
        db_id = finding_db_ids.get(finding.fingerprint, finding.fingerprint)
        l1_decision = layer1.evaluate(finding, run_id)
        if l1_decision:
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
        else:
            l3_queue.append((finding, db_id))

    logger.info(
        "FP pipeline Layer1 DONE | run=%s l1_resolved=%d l3_queue=%d elapsed=%.2fs",
        run_id, len(findings) - len(l3_queue), len(l3_queue), _t.time() - _l1_start,
    )

    # --- Layer 3: LLM calls — max 2 concurrent (matches OLLAMA_NUM_PARALLEL=2).
    # Higher concurrency causes queue buildup inside Ollama: queuing time + inference
    # time exceeds the 120s httpx timeout for calls 3-5 waiting in line.
    sem = asyncio.Semaphore(2)
    _l3_done_count = 0

    async def _run_layer3(finding: SASTFinding, db_id: str) -> FPDecision:
        nonlocal _l3_done_count
        async with sem:
            _call_start = _t.time()
            logger.info(
                "FP/L3 calling LLM | run=%s finding=%s rule=%s",
                run_id, db_id[:8], finding.rule_id,
            )
            try:
                decision = await layer3.evaluate(
                    finding=finding,
                    run_id=run_id,
                    finding_db_id=db_id,
                    use_tier1=False,  # Tier 2 (llama3.2:3b) — fast pass; auto-escalates high-stakes to Tier 1
                )
                _l3_done_count += 1
                logger.info(
                    "FP/L3 LLM done | run=%s finding=%s verdict=%s confidence=%.2f elapsed=%.1fs [%d/%d]",
                    run_id, db_id[:8], decision.verdict.value, decision.confidence,
                    _t.time() - _call_start, _l3_done_count, len(l3_queue),
                )
                await audit.log(
                    event_type=AuditEvent.FP_LAYER3_DECIDED,
                    actor="sast_agent",
                    run_id=run_id,
                    entity_type="finding",
                    entity_id=db_id,
                    payload={
                        "verdict": decision.verdict.value,
                        "confidence": decision.confidence,
                    },
                )
                return decision
            except Exception as exc:
                _l3_done_count += 1
                logger.error(
                    "FP/L3 error | run=%s finding=%s error=%s elapsed=%.1fs [%d/%d]",
                    run_id, db_id[:8], exc, _t.time() - _call_start,
                    _l3_done_count, len(l3_queue),
                )
                return FPDecision(
                    finding_id=db_id,
                    run_id=run_id,
                    verdict=FPVerdict.ESCALATED,
                    source="layer3_llm",   # type: ignore
                    confidence=0.0,
                    reasoning=f"Pipeline error: {exc}",
                    fp_category=None,
                )

    if l3_queue:
        logger.info(
            "FP pipeline Layer3 START | run=%s findings_to_llm=%d concurrency=5",
            run_id, len(l3_queue),
        )
        _l3_start = _t.time()
        l3_results = await asyncio.gather(*[_run_layer3(f, d) for f, d in l3_queue])
        logger.info(
            "FP pipeline Layer3 DONE | run=%s elapsed=%.1fs",
            run_id, _t.time() - _l3_start,
        )
        for decision in l3_results:
            decisions.append(decision)
            if decision.verdict == FPVerdict.REAL:
                counters["real"] += 1
            elif decision.verdict == FPVerdict.FP:
                counters["fp"] += 1
            elif decision.verdict == FPVerdict.ESCALATED:
                counters["escalated"] += 1
            elif decision.verdict == FPVerdict.DEADLOCK:
                counters["deadlock"] += 1

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

    logger.info(
        "FP pipeline COMPLETE | run=%s total=%d real=%d fp=%d escalated=%d deadlock=%d total_elapsed=%.1fs",
        run_id, len(decisions),
        counters["real"], counters["fp"], counters["escalated"], counters["deadlock"],
        _t.time() - _fp_start,
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

    # Phase 1: enqueue FP Challenger for a second-pass re-evaluation
    # The challenger runs AFTER all findings are in DB so pgvector has richer context
    await job_queue.enqueue(
        job_type=JobType.FP_CHALLENGE_PENDING,
        run_id=run_id,
        payload={"fp_summary": fp_summary},
        priority=3,
    )

    # Phase 0: mark scan complete
    await job_queue.enqueue(
        job_type=JobType.SCAN_COMPLETED,
        run_id=run_id,
        payload={"fp_summary": fp_summary},
        priority=5,
    )

    # Persist scan stats into workflow_runs.metadata so the status endpoint can return them
    scan_stats = {
        "files_scanned":       state.get("files_scanned", 0),
        "files_skipped":       state.get("files_skipped", 0),
        "files_with_findings": state.get("files_with_findings", 0),
        "files_clean":         max(0, state.get("files_scanned", 0) - state.get("files_with_findings", 0)),
        "skip_reasons":        state.get("skip_reasons", {}),
        "packages_total":      state.get("packages_total", 0),
        "packages_by_file":    state.get("packages_by_file", []),
        "scan_duration_ms":    state.get("scan_duration_ms", 0),
        "fp_summary":          fp_summary,
    }
    pool: asyncpg.Pool = deps["pool"]
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE workflow_runs SET metadata = $1::jsonb WHERE run_id = $2",
            json.dumps(scan_stats),
            run_id,
        )

    await wf_state.set_completed(run_id)
    await audit.log(
        event_type=AuditEvent.SCAN_COMPLETED,
        actor="sast_agent",
        run_id=run_id,
        payload=scan_stats,
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
        "run_id":              run_id,
        "scan_path":           scan_path,
        "raw_findings":        [],
        "scan_duration_ms":    0,
        "files_scanned":       0,
        "files_skipped":       0,
        "files_with_findings": 0,
        "skip_reasons":        {},
        "packages_total":      0,
        "packages_by_file":    [],
        "finding_db_ids":      {},
        "fp_results":          [],
        "fp_summary":     {},
        "error":          None,
    }

    try:
        final_state = await app.ainvoke(initial_state)
    except Exception as exc:
        # Top-level catch: ensure the run is never left stuck in 'running'
        logger.error("SAST workflow crashed | run=%s error=%s", run_id, exc, exc_info=True)
        wf_state: WorkflowState = deps.get("workflow_state")
        if wf_state:
            await wf_state.set_failed(run_id, str(exc))
        raise

    # If semgrep error propagated through state, mark run as failed
    if final_state.get("error"):
        wf_state = deps.get("workflow_state")
        if wf_state:
            await wf_state.set_failed(run_id, final_state["error"])

    return final_state

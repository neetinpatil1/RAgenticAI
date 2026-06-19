"""
workflows/fp_challenger_workflow.py
=====================================
FP Challenger Agent — Phase 1 (1.8.1).

Design intent:
  The SAST workflow runs L1 + L3 inline as findings arrive from Semgrep.
  At that point the pgvector store is sparse — few past decisions exist yet.

  The FP Challenger is a POST-HOC second pass that runs AFTER all SAST findings
  are written to DB and the pgvector store is populated.  With richer precedent
  context, L3 can reclassify findings that were marked REAL or ESCALATED in the
  first pass.

  Goal: drive ≥85% L2 accuracy and keep FP challenge p50 < 5 min.

Workflow nodes:
  start → load_findings → challenge_findings → persist_verdicts → complete

Triggered by:
  - Automatically after SAST completes (fp_challenge.pending job enqueued by node_enqueue_next)
  - Manually: POST /api/v1/fp-challenge/{run_id}

Progress tracked in fp_challenge_status table (polled by UI / API).
"""

from __future__ import annotations

import asyncio
import logging
from typing import TypedDict, Optional

import asyncpg
from langgraph.graph import StateGraph, END

from core.audit_logger import AuditLogger, AuditEvent
from core.fp_pipeline.layer1_rules import Layer1Rules
from core.fp_pipeline.layer3_llm import Layer3LLM
from core.output_contracts.fp_decision import FPDecision, FPVerdict, FPSource, LabelStatus
from core.output_contracts.sast_report import SASTFinding, Severity, Framework

logger = logging.getLogger(__name__)

# Maximum findings to re-challenge per run (avoids runaway LLM cost on huge scans)
MAX_CHALLENGE_FINDINGS = 100


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

class FPChallengerState(TypedDict):
    run_id:           str
    findings:         list[dict]      # rows from findings_reports + fp_decisions
    total:            int
    done:             int
    fp_found:         int             # findings flipped from REAL/ESCALATED → FP
    verdicts:         list[dict]      # new FPDecision dicts to persist
    error:            Optional[str]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _upsert_status(
    pool: asyncpg.Pool,
    run_id: str,
    status: str,
    total: int,
    done: int,
    fp_found: int,
    current_finding: Optional[str],
) -> None:
    pct = int(done / total * 100) if total > 0 else 0
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO fp_challenge_status
                (run_id, status, findings_total, findings_done, pct, fp_found, current_finding, updated_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())
            ON CONFLICT (run_id) DO UPDATE SET
                status=$2, findings_total=$3, findings_done=$4, pct=$5,
                fp_found=$6, current_finding=$7, updated_at=NOW()
            """,
            run_id, status, total, done, pct, fp_found, current_finding,
        )


def _row_to_finding(row: dict) -> SASTFinding:
    """Reconstruct a SASTFinding from a DB row (findings_reports)."""
    import json
    ref_urls = row.get("ref_urls") or []
    if isinstance(ref_urls, str):
        try:
            ref_urls = json.loads(ref_urls)
        except Exception:
            ref_urls = []

    return SASTFinding(
        rule_id=row["rule_id"],
        cwe_id=row.get("cwe_id"),
        severity=Severity(row["severity"]),
        file_path=row["file_path"],
        line_start=row["line_start"] or 1,
        line_end=row.get("line_end"),
        code_snippet=row.get("code_snippet"),
        message=row["message"],
        class_name=row.get("class_name"),
        method_name=row.get("method_name"),
        fix_suggestion=row.get("fix_suggestion"),
        owasp_category=row.get("owasp_category"),
        references=ref_urls if isinstance(ref_urls, list) else [],
        likelihood=row.get("likelihood"),
        impact=row.get("impact"),
        framework=Framework(row["framework"]) if row.get("framework") else Framework.UNKNOWN,
        confidence=0.5,
    )


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------

async def node_start(state: FPChallengerState, deps: dict) -> FPChallengerState:
    """Node 1: Log start, pre-write status row."""
    pool: asyncpg.Pool = deps["pool"]
    run_id = state["run_id"]
    logger.info("FP Challenger starting | run=%s", run_id)
    await _upsert_status(pool, run_id, "running", 0, 0, 0, None)
    return {**state, "done": 0, "fp_found": 0, "verdicts": [], "error": None}


async def node_load_findings(state: FPChallengerState, deps: dict) -> FPChallengerState:
    """
    Node 2: Load findings that need re-challenge.

    Targets:
      - Findings with no FP decision yet (never processed)
      - Findings where the last verdict was REAL or ESCALATED
    Cap at MAX_CHALLENGE_FINDINGS ordered by severity (CRITICAL/HIGH first).
    """
    pool: asyncpg.Pool = deps["pool"]
    run_id = state["run_id"]

    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT
                fr.id          AS finding_id,
                fr.run_id,
                fr.rule_id,
                fr.cwe_id,
                fr.severity,
                fr.file_path,
                fr.line_start,
                fr.line_end,
                fr.code_snippet,
                fr.message,
                fr.class_name,
                fr.method_name,
                fr.fix_suggestion,
                fr.owasp_category,
                fr.ref_urls,
                fr.likelihood,
                fr.impact,
                fr.framework,
                fpd.verdict    AS existing_verdict
            FROM findings_reports fr
            LEFT JOIN fp_decisions fpd
                ON fpd.finding_id = fr.id
                AND fpd.created_at = (
                    SELECT MAX(created_at) FROM fp_decisions WHERE finding_id = fr.id
                )
            WHERE fr.run_id = $1
              AND (
                  fpd.verdict IS NULL           -- no decision yet
               OR fpd.verdict IN ('REAL', 'ESCALATED')
              )
              AND fr.severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')
            ORDER BY
                CASE fr.severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH'     THEN 2
                    WHEN 'MEDIUM'   THEN 3
                    WHEN 'LOW'      THEN 4
                    ELSE            5
                END
            LIMIT $2
            """,
            run_id, MAX_CHALLENGE_FINDINGS,
        )

    findings = [dict(r) for r in rows]
    total = len(findings)
    logger.info("FP Challenger loaded %d findings to re-challenge | run=%s", total, run_id)

    if total == 0:
        logger.info("FP Challenger: nothing to challenge | run=%s", run_id)

    pool2: asyncpg.Pool = deps["pool"]
    await _upsert_status(pool2, run_id, "running", total, 0, 0, None)

    return {**state, "findings": findings, "total": total}


async def node_challenge_findings(state: FPChallengerState, deps: dict) -> FPChallengerState:
    """
    Node 3: Run L1 → L3 on each finding.

    Uses asyncio.Semaphore(2) to match Ollama's OLLAMA_NUM_PARALLEL=2 setting.
    Findings that flip from REAL/ESCALATED → FP are counted in fp_found.
    """
    if state["total"] == 0:
        return state

    pool: asyncpg.Pool    = deps["pool"]
    layer1: Layer1Rules   = deps["layer1_rules"]
    layer3: Layer3LLM     = deps["layer3_llm"]
    run_id                = state["run_id"]

    verdicts: list[dict] = []
    done     = 0
    fp_found = 0
    sem      = asyncio.Semaphore(2)

    async def challenge_one(row: dict) -> Optional[dict]:
        nonlocal done, fp_found
        async with sem:
            finding_id = str(row["finding_id"])
            rel_path = row.get("file_path", "unknown")

            await _upsert_status(pool, run_id, "running", state["total"], done, fp_found, rel_path)

            try:
                finding = _row_to_finding(row)
            except Exception as exc:
                logger.warning("Could not reconstruct SASTFinding | id=%s error=%s", finding_id, exc)
                done += 1
                return None

            # Layer 1 — deterministic rule check
            l1_decision = layer1.evaluate(finding, run_id)
            if l1_decision is not None:
                l1_decision = l1_decision.model_copy(update={"finding_id": finding_id})
                prev = row.get("existing_verdict")
                if prev in ("REAL", "ESCALATED", None):
                    fp_found += 1
                done += 1
                return {**l1_decision.model_dump(), "finding_id": finding_id}

            # Layer 3 — LLM re-evaluation with richer pgvector context.
            # Start on Tier 2 (llama3.2:3b) for speed; Layer3LLM auto-escalates
            # to Tier 1 (qwen14B) for high-stakes CWEs or low confidence (<0.6).
            try:
                l3_decision = await layer3.evaluate(
                    finding=finding,
                    run_id=run_id,
                    finding_db_id=finding_id,
                    use_tier1=False,
                )
                prev = row.get("existing_verdict")
                if l3_decision.verdict == FPVerdict.FP and prev in ("REAL", "ESCALATED", None):
                    fp_found += 1
                done += 1
                return l3_decision.model_dump()
            except Exception as exc:
                logger.error("L3 challenge error | finding=%s error=%s", finding_id, exc)
                done += 1
                return None

    tasks = [challenge_one(row) for row in state["findings"]]
    results = await asyncio.gather(*tasks, return_exceptions=False)
    verdicts = [r for r in results if r is not None]

    logger.info(
        "FP Challenger done | run=%s total=%d challenged=%d fp_found=%d",
        run_id, state["total"], len(verdicts), fp_found,
    )

    return {**state, "verdicts": verdicts, "done": state["total"], "fp_found": fp_found}


async def node_persist_verdicts(state: FPChallengerState, deps: dict) -> FPChallengerState:
    """
    Node 4: Upsert new FP decisions into fp_decisions table.

    Uses INSERT ... ON CONFLICT DO NOTHING — SAST inline verdicts are preserved;
    we only ADD challenger verdicts as additional rows (different source/timestamp).
    """
    pool: asyncpg.Pool = deps["pool"]
    run_id = state["run_id"]

    if not state["verdicts"]:
        return state

    async with pool.acquire() as conn:
        for v in state["verdicts"]:
            try:
                await conn.execute(
                    """
                    INSERT INTO fp_decisions
                        (finding_id, run_id, verdict, source, confidence,
                         fp_category, reasoning, label_status)
                    VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
                    """,
                    v["finding_id"],
                    run_id,
                    v["verdict"],
                    v.get("source", FPSource.LAYER3_LLM.value),
                    v.get("confidence", 0.5),
                    v.get("fp_category"),
                    v.get("reasoning"),
                    v.get("label_status", LabelStatus.AGENT_ONLY.value),
                )
            except Exception as exc:
                logger.warning("Could not persist challenger verdict | id=%s error=%s", v.get("finding_id"), exc)

    logger.info("FP Challenger persisted %d verdicts | run=%s", len(state["verdicts"]), run_id)
    return state


async def node_complete(state: FPChallengerState, deps: dict) -> FPChallengerState:
    """Node 5: Mark status completed, emit audit log."""
    pool: asyncpg.Pool    = deps["pool"]
    audit: AuditLogger    = deps["audit"]
    run_id                = state["run_id"]

    await _upsert_status(
        pool, run_id, "completed",
        state["total"], state["total"], state["fp_found"], None,
    )

    await audit.log(
        event_type=AuditEvent.SCAN_COMPLETED,
        actor="fp_challenger",
        run_id=run_id,
        payload={
            "total_challenged": state["total"],
            "fp_found":         state["fp_found"],
            "verdicts_written": len(state["verdicts"]),
        },
    )

    logger.info(
        "FP Challenger complete | run=%s challenged=%d fp_found=%d",
        run_id, state["total"], state["fp_found"],
    )
    return state


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------

def build_fp_challenger_graph(deps: dict):
    """
    Build the FP Challenger LangGraph workflow.

    deps: dict with pool, audit, layer1_rules, layer3_llm.
    """
    async def start(state):          return await node_start(state, deps)
    async def load(state):           return await node_load_findings(state, deps)
    async def challenge(state):      return await node_challenge_findings(state, deps)
    async def persist(state):        return await node_persist_verdicts(state, deps)
    async def complete(state):       return await node_complete(state, deps)

    graph = StateGraph(FPChallengerState)
    graph.add_node("start",    start)
    graph.add_node("load",     load)
    graph.add_node("challenge", challenge)
    graph.add_node("persist",  persist)
    graph.add_node("complete", complete)

    graph.set_entry_point("start")
    graph.add_edge("start",    "load")
    graph.add_edge("load",     "challenge")
    graph.add_edge("challenge", "persist")
    graph.add_edge("persist",  "complete")
    graph.add_edge("complete", END)

    return graph.compile()


# ---------------------------------------------------------------------------
# Entry point (called from agent_gateway.py)
# ---------------------------------------------------------------------------

async def run_fp_challenger_workflow(run_id: str, deps: dict) -> None:
    """
    Run the FP Challenger for a completed SAST scan.

    Args:
        run_id: The workflow run ID (must have completed SAST findings in DB).
        deps:   Dependency dict from _build_workflow_deps().
    """
    graph = build_fp_challenger_graph(deps)
    initial_state: FPChallengerState = {
        "run_id":   run_id,
        "findings": [],
        "total":    0,
        "done":     0,
        "fp_found": 0,
        "verdicts": [],
        "error":    None,
    }
    try:
        await graph.ainvoke(initial_state)
    except Exception as exc:
        logger.error("FP Challenger workflow error | run=%s error=%s", run_id, exc)
        pool: asyncpg.Pool = deps["pool"]
        try:
            await _upsert_status(pool, run_id, "failed", 0, 0, 0, None)
        except Exception:
            pass
        raise

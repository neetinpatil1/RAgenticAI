"""
workflows/fp_challenger_workflow.py
=====================================
FP Challenger Agent — Phase 1 (1.9).

Runs a post-hoc second pass on ALL finding types produced during a scan:

  1. SAST findings (findings_reports)
     Re-runs Layer 1 + Layer 3 with full pgvector context now available.
     Can flip REAL/ESCALATED → FP or upgrade FP confidence.

  2. SCA findings (dependency_findings)
     Asks the LLM whether each CVE is actually applicable given how the
     package is used in the codebase.  Writes verdict + fix suggestion.

  3. Code Review observations (code_review_findings)
     Asks the LLM to validate each observation in code context.
     Confirms genuine issues or dismisses false positives; always provides
     a concrete fix suggestion for confirmed findings.

Workflow nodes:
  start → load_sast → challenge_sast → persist_sast
        → challenge_sca → challenge_cr → complete

Triggered by:
  - Automatically after SAST completes (fp_challenge.pending job)
  - Manually: POST /api/v1/fp-challenge/{run_id}

Progress tracked in fp_challenge_status (polled by UI / API).
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import TypedDict, Optional

import asyncpg
from langgraph.graph import StateGraph, END

from core.audit_logger import AuditLogger, AuditEvent
from core.fp_pipeline.layer1_rules import Layer1Rules
from core.fp_pipeline.layer3_llm import Layer3LLM
from core.output_contracts.fp_decision import FPDecision, FPVerdict, FPSource, LabelStatus
from core.output_contracts.sast_report import SASTFinding, Severity, Framework

logger = logging.getLogger(__name__)


def _max_challenge_findings() -> int:
    """Cap for SAST re-challenge. Cloud providers can handle more."""
    from core.config import settings
    return 50 if settings.llm.provider.lower() == "ollama" else 500


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

class FPChallengerState(TypedDict):
    run_id:         str
    scan_path:      str             # resolved from workflow_runs at node_start
    # SAST
    findings:       list[dict]
    total:          int
    done:           int
    fp_found:       int
    verdicts:       list[dict]
    # SCA
    sca_findings:   list[dict]
    sca_total:      int
    sca_done:       int
    # Code Review
    cr_findings:    list[dict]
    cr_total:       int
    cr_done:        int
    cr_fp_found:    int             # code-review FPs dismissed by challenger
    error:          Optional[str]


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
    sca_total: int = 0,
    sca_done: int = 0,
    cr_total: int = 0,
    cr_done: int = 0,
) -> None:
    pct = int(done / total * 100) if total > 0 else 0
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO fp_challenge_status
                (run_id, status, findings_total, findings_done, pct, fp_found,
                 current_finding, sca_total, sca_done, cr_total, cr_done, updated_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW())
            ON CONFLICT (run_id) DO UPDATE SET
                status=$2, findings_total=$3, findings_done=$4, pct=$5,
                fp_found=$6, current_finding=$7,
                sca_total=$8, sca_done=$9, cr_total=$10, cr_done=$11,
                updated_at=NOW()
            """,
            run_id, status, total, done, pct, fp_found, current_finding,
            sca_total, sca_done, cr_total, cr_done,
        )


def _row_to_finding(row: dict) -> SASTFinding:
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


def _read_code_snippet(scan_path: str, file_path: str, line_start: int, line_end: int, context: int = 5) -> str:
    """Read lines around a finding from disk. Returns empty string on any error."""
    try:
        root = Path(scan_path)
        # file_path may be absolute or relative
        p = Path(file_path)
        if not p.is_absolute():
            p = root / file_path
        if not p.exists():
            return ""
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        lo = max(0, (line_start or 1) - 1 - context)
        hi = min(len(lines), (line_end or line_start or 1) + context)
        numbered = [f"{i+1:4}: {lines[i]}" for i in range(lo, hi)]
        return "\n".join(numbered)
    except Exception:
        return ""


def _strip_fences(raw: str) -> str:
    """Strip markdown code fences from LLM output."""
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("```", 2)[1]
        if cleaned.startswith("json"):
            cleaned = cleaned[4:]
        if "```" in cleaned:
            cleaned = cleaned[:cleaned.rindex("```")]
    return cleaned.strip()


async def _call_challenge_llm(system: str, prompt: str) -> dict:
    """Call LLM and parse JSON. Returns {} on failure."""
    from core.llm_client import call_llm
    try:
        raw = await call_llm(
            system_prompt=system,
            user_prompt=prompt,
            use_tier1=False,
            json_mode=True,
            max_tokens=600,
        )
        cleaned = _strip_fences(raw)
        if not cleaned:
            return {}
        return json.loads(cleaned)
    except Exception as exc:
        logger.debug("challenge LLM call failed: %s", exc)
        return {}


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------

async def node_start(state: FPChallengerState, deps: dict) -> FPChallengerState:
    pool: asyncpg.Pool = deps["pool"]
    run_id = state["run_id"]

    # Resolve scan_path from workflow_runs
    scan_path = ""
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT scan_path FROM workflow_runs WHERE run_id=$1", run_id)
        if row:
            scan_path = row["scan_path"] or ""

    logger.info("FP Challenger starting | run=%s scan_path=%s", run_id, scan_path)
    await _upsert_status(pool, run_id, "running", 0, 0, 0, None)
    return {
        **state,
        "scan_path": scan_path,
        "done": 0, "fp_found": 0, "verdicts": [],
        "sca_findings": [], "sca_total": 0, "sca_done": 0,
        "cr_findings": [], "cr_total": 0, "cr_done": 0, "cr_fp_found": 0,
        "error": None,
    }


async def node_load_sast_findings(state: FPChallengerState, deps: dict) -> FPChallengerState:
    """Load SAST findings that need re-challenge (REAL/ESCALATED or no prior decision)."""
    pool: asyncpg.Pool = deps["pool"]
    run_id = state["run_id"]

    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT
                fr.id AS finding_id, fr.run_id, fr.rule_id, fr.cwe_id,
                fr.severity, fr.file_path, fr.line_start, fr.line_end,
                fr.code_snippet, fr.message, fr.class_name, fr.method_name,
                fr.fix_suggestion, fr.owasp_category, fr.ref_urls,
                fr.likelihood, fr.impact, fr.framework,
                fpd.verdict AS existing_verdict
            FROM findings_reports fr
            LEFT JOIN LATERAL (
                SELECT verdict FROM fp_decisions
                WHERE finding_id = fr.id
                ORDER BY created_at DESC LIMIT 1
            ) fpd ON true
            WHERE fr.run_id = $1
              AND (fpd.verdict IS NULL OR fpd.verdict IN ('REAL', 'ESCALATED'))
            ORDER BY
                CASE fr.severity
                    WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM'   THEN 3 WHEN 'LOW'  THEN 4 ELSE 5
                END
            LIMIT $2
            """,
            run_id, _max_challenge_findings(),
        )

    findings = [dict(r) for r in rows]
    total = len(findings)
    logger.info("FP Challenger loaded %d SAST findings | run=%s", total, run_id)
    await _upsert_status(deps["pool"], run_id, "running", total, 0, 0, None)
    return {**state, "findings": findings, "total": total}


async def node_challenge_sast(state: FPChallengerState, deps: dict) -> FPChallengerState:
    """Re-run Layer1+Layer3 on SAST findings with full pgvector context."""
    if state["total"] == 0:
        return state

    pool: asyncpg.Pool  = deps["pool"]
    layer1: Layer1Rules = deps["layer1_rules"]
    layer3: Layer3LLM   = deps["layer3_llm"]
    run_id              = state["run_id"]

    from core.config import settings
    _ollama = settings.llm.provider.lower() == "ollama"
    sem     = asyncio.Semaphore(2 if _ollama else 5)

    verdicts: list[dict] = []
    done     = 0
    fp_found = 0

    async def challenge_one(row: dict) -> Optional[dict]:
        nonlocal done, fp_found
        async with sem:
            finding_id = str(row["finding_id"])
            await _upsert_status(
                pool, run_id, "running",
                state["total"], done, fp_found, row.get("file_path"),
                state["sca_total"], state["sca_done"],
                state["cr_total"], state["cr_done"],
            )
            try:
                finding = _row_to_finding(row)
            except Exception as exc:
                logger.warning("Could not reconstruct SASTFinding | id=%s err=%s", finding_id, exc)
                done += 1
                return None

            l1 = layer1.evaluate(finding, run_id)
            if l1 is not None:
                l1 = l1.model_copy(update={"finding_id": finding_id})
                if row.get("existing_verdict") in ("REAL", "ESCALATED", None):
                    fp_found += 1
                done += 1
                return {**l1.model_dump(), "finding_id": finding_id}

            try:
                l3 = await layer3.evaluate(
                    finding=finding, run_id=run_id,
                    finding_db_id=finding_id, use_tier1=False,
                )
                if l3.verdict == FPVerdict.FP and row.get("existing_verdict") in ("REAL", "ESCALATED", None):
                    fp_found += 1
                done += 1
                return l3.model_dump()
            except Exception as exc:
                logger.error("L3 SAST challenge error | id=%s err=%s", finding_id, exc)
                done += 1
                return None

    results  = await asyncio.gather(*[challenge_one(r) for r in state["findings"]])
    verdicts = [r for r in results if r is not None]

    logger.info(
        "SAST challenge done | run=%s total=%d challenged=%d fp_found=%d",
        run_id, state["total"], len(verdicts), fp_found,
    )
    return {**state, "verdicts": verdicts, "done": state["total"], "fp_found": fp_found}


async def node_persist_sast_verdicts(state: FPChallengerState, deps: dict) -> FPChallengerState:
    """Persist new FP decisions for SAST findings."""
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
                    v["finding_id"], run_id,
                    v["verdict"],
                    v.get("source", FPSource.LAYER3_LLM.value),
                    v.get("confidence", 0.5),
                    v.get("fp_category"),
                    v.get("reasoning"),
                    v.get("label_status", LabelStatus.AGENT_ONLY.value),
                )
            except Exception as exc:
                logger.warning("Could not persist SAST verdict | id=%s err=%s", v.get("finding_id"), exc)

    logger.info("SAST verdicts persisted | run=%s count=%d", run_id, len(state["verdicts"]))
    return state


async def node_challenge_sca(state: FPChallengerState, deps: dict) -> FPChallengerState:
    """
    Load and challenge SCA (dependency) findings.

    For each CVE, LLM decides: APPLICABLE / NOT_APPLICABLE / UNCERTAIN.
    Writes fp_challenge_verdict + fp_challenge_fix back to dependency_findings.
    Also updates findings_reports.fix_suggestion for any linked SAST findings
    that share the same CVE when a concrete upgrade path is available.
    """
    pool: asyncpg.Pool = deps["pool"]
    run_id     = state["run_id"]
    scan_path  = state["scan_path"]

    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, package_name, installed_version, fixed_version,
                   vulnerability_id, severity, description, ecosystem,
                   file_path, reachability, reach_evidence
            FROM dependency_findings
            WHERE run_id = $1
              AND (fp_challenge_verdict IS NULL OR fp_challenge_verdict = 'UNCERTAIN')
            ORDER BY
                CASE severity
                    WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM'   THEN 3 WHEN 'LOW'  THEN 4 ELSE 5
                END
            """,
            run_id,
        )

    sca_findings = [dict(r) for r in rows]
    sca_total    = len(sca_findings)
    logger.info("FP Challenger loaded %d SCA findings | run=%s", sca_total, run_id)

    if sca_total == 0:
        return {**state, "sca_findings": [], "sca_total": 0, "sca_done": 0}

    from core.config import settings
    _ollama = settings.llm.provider.lower() == "ollama"
    sem     = asyncio.Semaphore(2 if _ollama else 5)
    sca_done = 0

    _SYS = (
        "You are a security analyst evaluating CVE applicability. "
        "Respond with valid JSON only — no markdown, no prose."
    )

    async def challenge_sca_one(row: dict) -> None:
        nonlocal sca_done
        async with sem:
            dep_id     = str(row["id"])
            vuln_id    = row["vulnerability_id"]
            pkg        = row["package_name"]
            version    = row.get("installed_version") or "unknown"
            fixed      = row.get("fixed_version") or "unknown"
            desc       = (row.get("description") or "")[:500]
            reach      = row.get("reachability") or "UNKNOWN"
            evidence   = row.get("reach_evidence") or ""

            # Get code snippets that use this package
            from tools.reachability.llm_verdict import _get_usage_snippets
            snippets = _get_usage_snippets(scan_path, pkg, max_lines=15) if scan_path else ""

            prompt = f"""CVE: {vuln_id}
Package: {pkg} v{version} (fix available: v{fixed})
Ecosystem: {row.get('ecosystem','unknown')}
Severity: {row.get('severity','unknown')}
Description: {desc}

Static reachability analysis: {reach}
Evidence: {evidence}

Code snippets using this package:
{snippets or 'No direct usage found in source code.'}

Determine if this CVE is applicable to this application.
Return JSON:
{{
  "verdict": "APPLICABLE" or "NOT_APPLICABLE" or "UNCERTAIN",
  "confidence": 0.0-1.0,
  "reasoning": "2-3 sentence explanation",
  "fix_suggestion": "Concrete remediation: upgrade command, workaround, or why no action needed"
}}"""

            data = await _call_challenge_llm(_SYS, prompt)

            verdict    = data.get("verdict", "UNCERTAIN")
            if verdict not in ("APPLICABLE", "NOT_APPLICABLE", "UNCERTAIN"):
                verdict = "UNCERTAIN"
            reasoning  = data.get("reasoning", "")
            fix        = data.get("fix_suggestion", f"Upgrade {pkg} to {fixed}" if fixed != "unknown" else "")

            try:
                async with pool.acquire() as conn:
                    await conn.execute(
                        """
                        UPDATE dependency_findings
                        SET fp_challenge_verdict=$1,
                            fp_challenge_reasoning=$2,
                            fp_challenge_fix=$3
                        WHERE id=$4
                        """,
                        verdict, reasoning, fix, dep_id,
                    )
            except Exception as exc:
                logger.warning("SCA persist failed | id=%s err=%s", dep_id, exc)

            sca_done += 1
            await _upsert_status(
                pool, run_id, "running",
                state["total"], state["done"], state["fp_found"], None,
                sca_total, sca_done,
                state["cr_total"], state["cr_done"],
            )

    await asyncio.gather(*[challenge_sca_one(r) for r in sca_findings])

    logger.info("SCA challenge done | run=%s total=%d", run_id, sca_total)
    return {**state, "sca_findings": sca_findings, "sca_total": sca_total, "sca_done": sca_done}


async def node_challenge_cr(state: FPChallengerState, deps: dict) -> FPChallengerState:
    """
    Load and challenge code review observations.

    For each finding, LLM re-evaluates in code context:
      CONFIRMED   → genuine issue; fix_suggestion is a concrete code fix
      FALSE_POSITIVE → dismiss; fix_suggestion explains why acceptable
      UNCERTAIN   → needs human review

    Writes fp_challenge_verdict + fp_challenge_fix back to code_review_findings.
    """
    pool: asyncpg.Pool = deps["pool"]
    run_id    = state["run_id"]
    scan_path = state["scan_path"]

    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, file_path, category, severity, line_start, line_end,
                   title, description, recommendation, confidence
            FROM code_review_findings
            WHERE run_id = $1
              AND (fp_challenge_verdict IS NULL OR fp_challenge_verdict = 'UNCERTAIN')
            ORDER BY
                CASE severity
                    WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM'   THEN 3 WHEN 'LOW'  THEN 4 ELSE 5
                END
            """,
            run_id,
        )

    cr_findings = [dict(r) for r in rows]
    cr_total    = len(cr_findings)
    logger.info("FP Challenger loaded %d code-review findings | run=%s", cr_total, run_id)

    if cr_total == 0:
        return {**state, "cr_findings": [], "cr_total": 0, "cr_done": 0, "cr_fp_found": 0}

    from core.config import settings
    _ollama = settings.llm.provider.lower() == "ollama"
    sem     = asyncio.Semaphore(2 if _ollama else 5)
    cr_done    = 0
    cr_fp_found = 0

    _SYS = (
        "You are a senior code reviewer doing a second-pass validation. "
        "Respond with valid JSON only — no markdown, no prose."
    )

    async def challenge_cr_one(row: dict) -> None:
        nonlocal cr_done, cr_fp_found
        async with sem:
            cr_id     = str(row["id"])
            file_path = row.get("file_path", "")
            category  = row.get("category", "")
            severity  = row.get("severity", "")
            title     = row.get("title", "")
            desc      = (row.get("description") or "")[:500]
            reco      = (row.get("recommendation") or "")[:300]
            line_start = row.get("line_start") or 1
            line_end   = row.get("line_end") or line_start

            snippet = _read_code_snippet(scan_path, file_path, line_start, line_end) if scan_path else ""

            prompt = f"""File: {file_path}
Category: {category}  |  Severity: {severity}
Issue title: {title}
Description: {desc}
Original recommendation: {reco}

Code context (lines {line_start}–{line_end}):
{snippet or '(source not available)'}

Validate whether this observation is a genuine issue in this specific code context.
Return JSON:
{{
  "verdict": "CONFIRMED" or "FALSE_POSITIVE" or "UNCERTAIN",
  "confidence": 0.0-1.0,
  "reasoning": "2-3 sentence explanation anchored to the actual code",
  "fix_suggestion": "If CONFIRMED: specific corrected code or steps. If FALSE_POSITIVE: why it is acceptable."
}}"""

            data = await _call_challenge_llm(_SYS, prompt)

            verdict = data.get("verdict", "UNCERTAIN")
            if verdict not in ("CONFIRMED", "FALSE_POSITIVE", "UNCERTAIN"):
                verdict = "UNCERTAIN"
            reasoning = data.get("reasoning", "")
            fix       = data.get("fix_suggestion", "")

            if verdict == "FALSE_POSITIVE":
                cr_fp_found += 1

            try:
                async with pool.acquire() as conn:
                    await conn.execute(
                        """
                        UPDATE code_review_findings
                        SET fp_challenge_verdict=$1,
                            fp_challenge_reasoning=$2,
                            fp_challenge_fix=$3
                        WHERE id=$4
                        """,
                        verdict, reasoning, fix, cr_id,
                    )
            except Exception as exc:
                logger.warning("CR persist failed | id=%s err=%s", cr_id, exc)

            cr_done += 1
            await _upsert_status(
                pool, run_id, "running",
                state["total"], state["done"], state["fp_found"], None,
                state["sca_total"], state["sca_done"],
                cr_total, cr_done,
            )

    await asyncio.gather(*[challenge_cr_one(r) for r in cr_findings])

    logger.info(
        "Code-review challenge done | run=%s total=%d fp_dismissed=%d",
        run_id, cr_total, cr_fp_found,
    )
    return {
        **state,
        "cr_findings": cr_findings, "cr_total": cr_total,
        "cr_done": cr_done, "cr_fp_found": cr_fp_found,
    }


async def node_complete(state: FPChallengerState, deps: dict) -> FPChallengerState:
    pool: asyncpg.Pool  = deps["pool"]
    audit: AuditLogger  = deps["audit"]
    run_id              = state["run_id"]

    await _upsert_status(
        pool, run_id, "completed",
        state["total"], state["total"], state["fp_found"], None,
        state["sca_total"], state["sca_done"],
        state["cr_total"], state["cr_done"],
    )

    await audit.log(
        event_type=AuditEvent.SCAN_COMPLETED,
        actor="fp_challenger",
        run_id=run_id,
        payload={
            "sast_challenged":  state["total"],
            "sast_fp_found":    state["fp_found"],
            "sca_challenged":   state["sca_total"],
            "cr_challenged":    state["cr_total"],
            "cr_fp_dismissed":  state["cr_fp_found"],
        },
    )

    logger.info(
        "FP Challenger complete | run=%s sast=%d(fp=%d) sca=%d cr=%d(fp=%d)",
        run_id,
        state["total"], state["fp_found"],
        state["sca_total"],
        state["cr_total"], state["cr_fp_found"],
    )
    return state


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------

def build_fp_challenger_graph(deps: dict):
    async def start(state):         return await node_start(state, deps)
    async def load_sast(state):     return await node_load_sast_findings(state, deps)
    async def chall_sast(state):    return await node_challenge_sast(state, deps)
    async def persist_sast(state):  return await node_persist_sast_verdicts(state, deps)
    async def chall_sca(state):     return await node_challenge_sca(state, deps)
    async def chall_cr(state):      return await node_challenge_cr(state, deps)
    async def complete(state):      return await node_complete(state, deps)

    graph = StateGraph(FPChallengerState)
    graph.add_node("start",        start)
    graph.add_node("load_sast",    load_sast)
    graph.add_node("chall_sast",   chall_sast)
    graph.add_node("persist_sast", persist_sast)
    graph.add_node("chall_sca",    chall_sca)
    graph.add_node("chall_cr",     chall_cr)
    graph.add_node("complete",     complete)

    graph.set_entry_point("start")
    graph.add_edge("start",        "load_sast")
    graph.add_edge("load_sast",    "chall_sast")
    graph.add_edge("chall_sast",   "persist_sast")
    graph.add_edge("persist_sast", "chall_sca")
    graph.add_edge("chall_sca",    "chall_cr")
    graph.add_edge("chall_cr",     "complete")
    graph.add_edge("complete",     END)

    return graph.compile()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def run_fp_challenger_workflow(run_id: str, deps: dict) -> None:
    graph = build_fp_challenger_graph(deps)
    initial_state: FPChallengerState = {
        "run_id":      run_id,
        "scan_path":   "",
        "findings":    [], "total": 0, "done": 0, "fp_found": 0, "verdicts": [],
        "sca_findings": [], "sca_total": 0, "sca_done": 0,
        "cr_findings": [], "cr_total": 0, "cr_done": 0, "cr_fp_found": 0,
        "error":       None,
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

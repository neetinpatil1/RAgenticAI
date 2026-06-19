"""
workflows/reachability_workflow.py
====================================
CVE Reachability Analyzer — LangGraph workflow.

Triggered after SCA completes when CVE count > 0.
For each CVE finding:
  1. Enrich CVE → get vulnerable class/method
  2. Build dep tree → resolve JARs / npm modules
  3. Assemble reachability chain (import scan + JAR bytecode)
  4. LLM verdict for UNKNOWN cases
  5. Write verdict + evidence back to dependency_findings table

Design principles:
  - Every step wrapped in try/except — failure = UNKNOWN, never crashes scan
  - Writes results progressively (one CVE at a time) — UI can show partial results
  - Runs in parallel with Code Review — no blocking of existing pipeline
"""
from __future__ import annotations
import asyncio
import json
import logging
from datetime import datetime, timezone

import asyncpg

from tools.cve_enricher                   import enrich_cve
from tools.reachability.dep_tree          import build_dep_tree, DepTree
from tools.reachability.chain_assembler   import assemble_chain
from tools.reachability.llm_verdict       import get_llm_verdict
from tools.steady_tool                    import SteadyTool

logger = logging.getLogger(__name__)

# Max concurrent CVE analyses (each does file I/O + optional LLM call)
_SEM = asyncio.Semaphore(3)


async def run_reachability_workflow(
    run_id:    str,
    scan_path: str,
    pool:      asyncpg.Pool,
) -> None:
    """
    Entry point — called from _run_all_agents() after SCA completes.
    Fetches all CVE findings for this run and analyses each one.
    """
    import time as _t
    _start = _t.time()
    logger.info("Reachability | START | run=%s path=%s", run_id, scan_path)

    try:
        # Fetch all CVE findings for this run
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """SELECT id, package_name, installed_version, vulnerability_id,
                          description, ecosystem
                   FROM dependency_findings
                   WHERE run_id = $1
                   ORDER BY
                       CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                                     WHEN 'MEDIUM'   THEN 3 ELSE 4 END""",
                run_id,
            )

        if not rows:
            logger.info("Reachability | no CVE findings — skipping | run=%s", run_id)
            await _mark_done(pool, run_id, 0)
            return

        logger.info("Reachability | analysing %d CVE(s) | run=%s", len(rows), run_id)

        # Build dep tree once for all CVEs (expensive I/O done only once)
        dep_tree: DepTree = DepTree(ecosystem="unknown")
        try:
            dep_tree = build_dep_tree(scan_path)
            logger.info("Reachability | dep_tree ecosystem=%s deps=%d jars=%d",
                        dep_tree.ecosystem, len(dep_tree.direct_deps), len(dep_tree.jar_paths))
        except Exception as exc:
            logger.warning("Reachability | dep_tree failed: %s", exc)

        # Analyse each CVE with heuristic chain assembler (bounded concurrency)
        tasks = [
            _analyse_one(run_id, scan_path, dict(row), dep_tree, pool)
            for row in rows
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

        # Eclipse Steady — call-graph override (Java only, optional)
        # Runs after heuristic pass. Overrides UNKNOWN/LIKELY verdicts where
        # Steady can provide a definitive call-chain-based result.
        steady = SteadyTool()
        if await steady.is_available():
            logger.info("Reachability | Steady available — running call-graph analysis | run=%s", run_id)
            steady_verdicts = await steady.analyze(scan_path=scan_path, run_id=run_id)
            if steady_verdicts:
                await _apply_steady_verdicts(pool, run_id, steady_verdicts)
                logger.info("Reachability | Steady applied %d verdicts | run=%s",
                            len(steady_verdicts), run_id)
        else:
            logger.info("Reachability | Steady not available — using heuristic results | run=%s", run_id)

        elapsed = _t.time() - _start
        logger.info("Reachability | COMPLETE | run=%s cves=%d elapsed=%.1fs",
                    run_id, len(rows), elapsed)
        await _mark_done(pool, run_id, len(rows))

    except Exception as exc:
        logger.error("Reachability | FATAL | run=%s error=%s", run_id, exc)
        await _mark_done(pool, run_id, 0)


async def _analyse_one(
    run_id:    str,
    scan_path: str,
    finding:   dict,
    dep_tree:  DepTree,
    pool:      asyncpg.Pool,
) -> None:
    """Analyse reachability for one CVE finding. Never raises."""
    finding_id  = str(finding["id"])
    vuln_id     = finding["vulnerability_id"]
    pkg_name    = finding["package_name"]
    description = finding.get("description") or ""

    async with _SEM:
        logger.info("Reachability | analysing vuln=%s pkg=%s", vuln_id, pkg_name)
        try:
            # Step 1: Enrich CVE → get vulnerable class
            enriched = await enrich_cve(vuln_id)
            affected_classes = enriched.get("affected_classes", [])

            # Step 2 + 3: Build chain for each affected class; take best result
            result = None
            for cls in affected_classes:
                r = assemble_chain(scan_path, dep_tree, cls, pkg_name)
                # Prefer REACHABLE > NOT_REACHABLE > UNKNOWN
                if result is None or _verdict_rank(r.verdict) > _verdict_rank(result.verdict):
                    result = r
                if result.verdict == "REACHABLE":
                    break  # Found — no need to check other classes

            if result is None:
                # No class mapping — still try LLM so we get LIKELY verdict instead of UNKNOWN
                if description:
                    try:
                        llm = await get_llm_verdict(
                            package_name=pkg_name,
                            vuln_id=vuln_id,
                            cve_description=description,
                            target_class="",  # no specific class known
                            scan_path=scan_path,
                        )
                        result_dict = {
                            "verdict":   llm["verdict"],
                            "evidence":  (
                                f"No specific vulnerable class identified for {vuln_id}. "
                                f"LLM assessed package usage in codebase.\n\n"
                                + llm.get("reasoning", "")
                            ),
                            "confidence": llm["confidence"],
                            "source":    "llm",
                            "affected_classes": [],
                        }
                    except Exception as exc:
                        logger.warning("Reachability | LLM fallback failed for %s: %s", vuln_id, exc)
                        result_dict = {
                            "verdict": "UNKNOWN",
                            "evidence": (
                                f"No vulnerable class mapping found for {vuln_id}. "
                                "OSV.dev does not specify which class is affected. Manual review required."
                            ),
                            "confidence": 0.0,
                            "source": "unknown",
                            "affected_classes": [],
                        }
                else:
                    result_dict = {
                        "verdict": "UNKNOWN",
                        "evidence": (
                            f"No vulnerable class mapping found for {vuln_id}. "
                            "OSV.dev does not specify which class is affected. Manual review required."
                        ),
                        "confidence": 0.0,
                        "source": "unknown",
                        "affected_classes": [],
                    }
            else:
                # Step 4: LLM fallback for UNKNOWN cases
                if result.verdict == "UNKNOWN" and description:
                    try:
                        llm = await get_llm_verdict(
                            package_name=pkg_name,
                            vuln_id=vuln_id,
                            cve_description=description,
                            target_class=affected_classes[0] if affected_classes else "",
                            scan_path=scan_path,
                        )
                        result_dict = {
                            "verdict":   llm["verdict"],
                            "evidence":  result.evidence + "\n\nLLM analysis: " + llm.get("reasoning", ""),
                            "confidence": llm["confidence"],
                            "source":    "llm",
                            "affected_classes": affected_classes,
                        }
                    except Exception as exc:
                        logger.warning("Reachability | LLM failed for %s: %s", vuln_id, exc)
                        result_dict = {
                            "verdict": result.verdict, "evidence": result.evidence,
                            "confidence": result.confidence, "source": result.source,
                            "affected_classes": affected_classes,
                        }
                else:
                    result_dict = {
                        "verdict": result.verdict, "evidence": result.evidence,
                        "confidence": result.confidence, "source": result.source,
                        "affected_classes": affected_classes,
                    }

            # Step 5: Write to DB
            await _write_result(pool, finding_id, result_dict)
            logger.info("Reachability | vuln=%s verdict=%s confidence=%.2f source=%s",
                        vuln_id, result_dict["verdict"], result_dict["confidence"],
                        result_dict["source"])

        except Exception as exc:
            logger.error("Reachability | error for %s: %s", vuln_id, exc)
            await _write_result(pool, finding_id, {
                "verdict": "UNKNOWN",
                "evidence": f"Analysis error: {exc}",
                "confidence": 0.0,
                "source": "unknown",
                "affected_classes": [],
            })


async def _apply_steady_verdicts(
    pool:            asyncpg.Pool,
    run_id:          str,
    steady_verdicts: dict,
) -> None:
    """
    Override heuristic reachability results with Steady's call-graph verdicts.
    Only overrides when Steady confidence > existing confidence, or existing is UNKNOWN.
    """
    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """SELECT id, vulnerability_id, reachability, reach_confidence
                   FROM dependency_findings
                   WHERE run_id = $1""",
                run_id,
            )
            for row in rows:
                vuln_id   = row["vulnerability_id"]
                sv = steady_verdicts.get(vuln_id)
                if not sv:
                    continue
                existing_conf = float(row["reach_confidence"] or 0.0)
                existing_ver  = (row["reachability"] or "UNKNOWN").upper()
                # Override if Steady is more confident OR existing is UNKNOWN/LIKELY
                if sv.confidence > existing_conf or existing_ver in ("UNKNOWN", "LIKELY_REACHABLE", "LIKELY_NOT_REACHABLE"):
                    evidence = f"Eclipse Steady call-graph analysis."
                    if sv.call_chain:
                        evidence += f"\nCall chain: {sv.call_chain}"
                    await conn.execute(
                        """UPDATE dependency_findings
                           SET reachability      = $1,
                               reach_evidence    = $2,
                               reach_confidence  = $3,
                               reach_source      = 'steady'
                           WHERE id = $4""",
                        sv.verdict,
                        evidence,
                        sv.confidence,
                        row["id"],
                    )
                    logger.info(
                        "Reachability | Steady override | vuln=%s %s→%s conf=%.2f",
                        vuln_id, existing_ver, sv.verdict, sv.confidence,
                    )
    except Exception as exc:
        logger.warning("Reachability | _apply_steady_verdicts error: %s", exc)


async def _write_result(pool: asyncpg.Pool, finding_id: str, result: dict) -> None:
    """Write reachability result back to dependency_findings row."""
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                """UPDATE dependency_findings
                   SET reachability    = $1,
                       reach_evidence  = $2,
                       reach_confidence = $3,
                       reach_source    = $4,
                       affected_classes = $5
                   WHERE id = $6""",
                result["verdict"],
                result["evidence"],
                result["confidence"],
                result["source"],
                json.dumps(result.get("affected_classes", [])),
                finding_id,
            )
    except Exception as exc:
        logger.error("Reachability | DB write failed for %s: %s", finding_id, exc)


async def _mark_done(pool: asyncpg.Pool, run_id: str, count: int) -> None:
    """Write reachability completion flag to workflow_runs.metadata (merge, not replace)."""
    try:
        async with pool.acquire() as conn:
            patch = json.dumps({"reachability": {
                "cves_analysed": count,
                "completed_at":  datetime.now(timezone.utc).isoformat(),
            }})
            await conn.execute(
                """UPDATE workflow_runs
                   SET metadata = COALESCE(metadata, '{}'::jsonb) || $1::jsonb
                   WHERE run_id = $2""",
                patch, run_id,
            )
    except Exception as exc:
        logger.warning("Reachability | _mark_done failed: %s", exc)


def _verdict_rank(verdict: str) -> int:
    """Higher rank = more informative verdict."""
    return {"REACHABLE": 3, "NOT_REACHABLE": 2, "LIKELY_REACHABLE": 2,
            "LIKELY_NOT_REACHABLE": 1, "UNKNOWN": 0}.get(verdict, 0)

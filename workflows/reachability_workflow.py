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

# NOTE: _SEM is created inside run_reachability_workflow (not at module level)
# to avoid "Future attached to a different loop" errors in Python 3.9 when the
# module is imported before asyncio.run() starts an event loop.


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

        # Analyse each CVE with heuristic chain assembler (bounded concurrency).
        # Semaphore created here (not module-level) to avoid Python 3.9
        # "Future attached to a different loop" error when the module is imported
        # before asyncio.run() starts the event loop.
        sem = asyncio.Semaphore(3)
        tasks = [
            _analyse_one(run_id, scan_path, dict(row), dep_tree, pool, sem)
            for row in rows
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

        # Eclipse Steady — call-graph override (Java only, optional)
        # Runs after heuristic pass. Overrides UNKNOWN/LIKELY verdicts where
        # Steady can provide a definitive call-chain-based result.
        # Re-fetch findings AFTER heuristic pass so affected_classes (written by
        # _analyse_one → cve_enricher) are included — CIA uses them to narrow
        # constructChanges to specific vulnerable methods, not all library constructs.
        steady = SteadyTool()
        if await steady.is_available():
            logger.info("Reachability | Steady available — running call-graph analysis | run=%s", run_id)
            async with pool.acquire() as conn:
                enriched_rows = await conn.fetch(
                    """SELECT id, package_name, installed_version, vulnerability_id,
                              description, ecosystem, affected_classes, fixed_version
                       FROM dependency_findings
                       WHERE run_id = $1""",
                    run_id,
                )
            known_vulns = [dict(r) for r in enriched_rows]
            steady_verdicts = await steady.analyze(
                scan_path=scan_path, run_id=run_id, known_vulns=known_vulns
            )
            if steady_verdicts:
                applied = await _apply_steady_verdicts(pool, run_id, steady_verdicts)
                logger.info("Reachability | Steady applied %d/%d verdicts | run=%s",
                            applied, len(steady_verdicts), run_id)
            else:
                logger.info("Reachability | Steady returned 0 verdicts (CIA not configured) | run=%s", run_id)
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
    sem:       asyncio.Semaphore,
) -> None:
    """Analyse reachability for one CVE finding. Never raises."""
    finding_id  = str(finding["id"])
    vuln_id     = finding["vulnerability_id"]
    pkg_name    = finding["package_name"]
    description = finding.get("description") or ""

    async with sem:
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
) -> int:
    """
    Override heuristic reachability results with Steady's call-graph verdicts.

    Override policy:
    - ONLY override with definitive CIA-backed verdicts (REACHABLE / NOT_REACHABLE, confidence >= 0.90).
    - LIKELY_REACHABLE from Steady means no CIA service ran — it's just version-matching,
      no better than what SCA already told us. Never let it overwrite heuristic results.
    - When Steady does have a definitive verdict, always prefer it — call-graph analysis
      is more accurate than import/bytecode heuristics.

    Returns the number of rows actually updated.
    """
    applied = 0
    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """SELECT id, vulnerability_id, reachability, reach_confidence
                   FROM dependency_findings
                   WHERE run_id = $1""",
                run_id,
            )
            for row in rows:
                vuln_id = row["vulnerability_id"]
                sv = steady_verdicts.get(vuln_id)
                if not sv:
                    continue

                # Only trust definitive CIA call-graph results.
                # LIKELY_REACHABLE means reachable=0 (no CIA ran) — skip it.
                if sv.verdict not in ("REACHABLE", "NOT_REACHABLE") or sv.confidence < 0.90:
                    logger.debug(
                        "Reachability | Steady skipped (no CIA) | vuln=%s verdict=%s conf=%.2f",
                        vuln_id, sv.verdict, sv.confidence,
                    )
                    continue

                existing_ver = (row["reachability"] or "UNKNOWN").upper()

                # Build rich evidence string
                evidence_lines = ["Eclipse Steady call-graph analysis (CIA-confirmed)."]
                if sv.call_chain:
                    evidence_lines.append(f"Call chain: {sv.call_chain}")
                else:
                    evidence_lines.append("No call chain available (CIA service response incomplete).")
                evidence = "\n".join(evidence_lines)

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
                applied += 1
                logger.info(
                    "Reachability | Steady override | vuln=%s %s→%s conf=%.2f",
                    vuln_id, existing_ver, sv.verdict, sv.confidence,
                )
    except Exception as exc:
        logger.warning("Reachability | _apply_steady_verdicts error: %s", exc)
    return applied


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

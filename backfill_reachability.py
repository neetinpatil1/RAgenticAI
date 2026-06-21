"""
backfill_reachability.py
------------------------
Fast backfill: re-runs assemble_chain() for all dependency_findings rows where
reachability was determined by LLM or is unknown/null AND the package has a
known default vulnerable class (no LLM calls — pure import/bytecode scan).

This upgrades evidence like:
  "No specific vulnerable class identified. LLM assessed package usage."
  → "Vulnerable class `ObjectMapper` directly imported at src/main/java/Foo.java:12"

Only updates a row if the new result is an improvement (REACHABLE > NOT_REACHABLE > UNKNOWN).

Usage:
  python backfill_reachability.py          # all scans with CVEs
  python backfill_reachability.py <run_id> # single scan
"""
from __future__ import annotations
import asyncio
import logging
import sys
from pathlib import Path

import asyncpg
from dotenv import load_dotenv

load_dotenv()

from core.config import settings
from tools.reachability.dep_tree import build_dep_tree, DepTree
from tools.reachability.chain_assembler import assemble_chain

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("backfill")

# Must match _PACKAGE_DEFAULT_CLASSES in reachability_workflow.py
_PACKAGE_DEFAULT_CLASSES: dict[str, list[str]] = {
    "jackson-databind": ["com.fasterxml.jackson.databind.ObjectMapper"],
    "commons-collections": [
        "org.apache.commons.collections.functors.InvokerTransformer",
        "org.apache.commons.collections4.functors.InvokerTransformer",
    ],
    "commons-fileupload": ["org.apache.commons.fileupload.MultipartStream"],
    "snakeyaml":          ["org.yaml.snakeyaml.Yaml"],
    "hibernate-core":     ["org.hibernate.engine.query.HQLQueryPlan"],
    "mysql-connector":    ["com.mysql.cj.jdbc.ConnectionImpl"],
    "guava":              ["com.google.common.io.Files"],
    "spring-webmvc":      ["org.springframework.web.servlet.DispatcherServlet"],
    "log4j-core":         ["org.apache.logging.log4j.core.lookup.JndiLookup"],
}

_VERDICT_RANK = {"REACHABLE": 3, "NOT_REACHABLE": 2,
                 "LIKELY_REACHABLE": 2, "LIKELY_NOT_REACHABLE": 1, "UNKNOWN": 0}


def _default_classes(pkg_name: str) -> list[str]:
    lower = pkg_name.lower()
    for key, classes in _PACKAGE_DEFAULT_CLASSES.items():
        if key in lower:
            return classes
    return []


async def backfill_scan(pool: asyncpg.Pool, run_id: str, scan_path: str) -> dict:
    """Backfill one scan. Returns stats dict."""
    stats = {"run_id": run_id, "checked": 0, "upgraded": 0, "skipped": 0}

    if not Path(scan_path).exists():
        log.warning("%-40s  scan_path does not exist — skipping", run_id)
        stats["skipped"] = -1
        return stats

    # Build dep tree once
    try:
        dep_tree = build_dep_tree(scan_path)
    except Exception as exc:
        log.warning("%-40s  dep_tree failed: %s — using empty", run_id, exc)
        dep_tree = DepTree(ecosystem="unknown")

    # Fetch all findings that could benefit (LLM/unknown/null source)
    rows = await pool.fetch(
        """SELECT id, package_name, vulnerability_id,
                  reachability, reach_source, affected_classes
           FROM dependency_findings
           WHERE run_id = $1
             AND (reach_source IN ('llm', 'unknown') OR reach_source IS NULL
                  OR reachability IS NULL)
           ORDER BY package_name""",
        run_id,
    )

    if not rows:
        log.info("%-40s  no upgradeable findings", run_id)
        return stats

    stats["checked"] = len(rows)
    upgraded = 0

    for row in rows:
        pkg_name = row["package_name"] or ""
        vuln_id  = row["vulnerability_id"]
        finding_id = str(row["id"])
        current_verdict = (row["reachability"] or "UNKNOWN").upper()
        current_rank = _VERDICT_RANK.get(current_verdict, 0)

        classes = _default_classes(pkg_name)
        if not classes:
            continue  # No default class for this package

        # Try each default class with assemble_chain
        best = None
        for cls in classes:
            r = assemble_chain(scan_path, dep_tree, cls, pkg_name)
            if best is None or _VERDICT_RANK.get(r.verdict, 0) > _VERDICT_RANK.get(best.verdict, 0):
                best = r
            if best.verdict == "REACHABLE":
                break

        if best is None:
            continue

        new_rank = _VERDICT_RANK.get(best.verdict, 0)
        if new_rank <= current_rank and current_verdict not in ("UNKNOWN", "NULL"):
            # Not an improvement — keep existing result
            continue

        # Write updated result
        await pool.execute(
            """UPDATE dependency_findings
               SET reachability     = $1,
                   reach_evidence   = $2,
                   reach_confidence = $3,
                   reach_source     = $4,
                   affected_classes = $5
               WHERE id = $6""",
            best.verdict,
            best.evidence,
            best.confidence,
            best.source,
            f'["{classes[0]}"]',
            finding_id,
        )
        upgraded += 1
        log.info("  %-30s  %-38s  %s → %s  (%.2f %s)",
                 pkg_name, vuln_id,
                 current_verdict, best.verdict,
                 best.confidence, best.source)

    stats["upgraded"] = upgraded
    return stats


async def main():
    pool = await asyncpg.create_pool(dsn=settings.db.dsn, min_size=1, max_size=3)

    if len(sys.argv) > 1:
        run_id = sys.argv[1]
        rows = await pool.fetch(
            "SELECT run_id, scan_path FROM workflow_runs WHERE run_id=$1", run_id
        )
    else:
        # All scans with CVE findings, skip currently-running scans
        rows = await pool.fetch(
            """SELECT DISTINCT wr.run_id, wr.scan_path
               FROM workflow_runs wr
               JOIN dependency_findings df ON df.run_id = wr.run_id
               WHERE wr.state != 'running'
               ORDER BY wr.run_id DESC"""
        )

    if not rows:
        log.error("No matching scans found.")
        await pool.close()
        return

    log.info("=" * 70)
    log.info("Backfilling reachability evidence for %d scan(s)", len(rows))
    log.info("(Only updates LLM/unknown results where package default class known)")
    log.info("=" * 70)

    total_checked = total_upgraded = 0
    for row in rows:
        run_id    = row["run_id"]
        scan_path = row["scan_path"]
        log.info("")
        log.info("Run: %s  path: %s", run_id, scan_path)
        stats = await backfill_scan(pool, run_id, scan_path)
        log.info("  → checked=%d upgraded=%d", stats["checked"], stats["upgraded"])
        total_checked  += stats["checked"]
        total_upgraded += stats["upgraded"]

    log.info("")
    log.info("=" * 70)
    log.info("DONE — total checked=%d upgraded=%d", total_checked, total_upgraded)
    log.info("=" * 70)

    await pool.close()


asyncio.run(main())

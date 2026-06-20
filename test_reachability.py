"""
test_reachability.py
--------------------
Standalone reachability test — re-runs ONLY the reachability workflow
against an existing scan run (reuses SCA findings already in the DB).
No full scan needed.

Usage:
  python test_reachability.py [run_id]

  If run_id is omitted, uses the most recent JavaVulnerableLab scan.
"""
import asyncio
import logging
import sys

import asyncpg
from dotenv import load_dotenv

load_dotenv()

from core.config import settings
from workflows.reachability_workflow import run_reachability_workflow

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("reachability_test")


async def main():
    # ── resolve run_id ────────────────────────────────────────────────────────
    pool = await asyncpg.create_pool(
        host=settings.db.host, port=settings.db.port,
        database=settings.db.name, user=settings.db.user,
        password=settings.db.password, min_size=1, max_size=5,
    )

    if len(sys.argv) > 1:
        run_id = sys.argv[1]
        row = await pool.fetchrow(
            "SELECT run_id, scan_path FROM workflow_runs WHERE run_id=$1", run_id
        )
    else:
        row = await pool.fetchrow(
            """SELECT run_id, scan_path FROM workflow_runs
               WHERE scan_path LIKE '%JavaVulnerableLab%'
               ORDER BY created_at DESC LIMIT 1"""
        )

    if not row:
        log.error("No matching run found.")
        await pool.close()
        return

    run_id    = row["run_id"]
    scan_path = row["scan_path"]
    log.info("=" * 60)
    log.info("Run ID    : %s", run_id)
    log.info("Scan path : %s", scan_path)
    log.info("=" * 60)

    # ── show findings BEFORE ──────────────────────────────────────────────────
    before = await pool.fetch(
        """SELECT vulnerability_id, package_name, reachability, reach_confidence, reach_source
           FROM dependency_findings WHERE run_id=$1 ORDER BY package_name""",
        run_id,
    )
    log.info("BEFORE — %d findings:", len(before))
    for r in before:
        log.info("  %-30s %-25s  %-22s  conf=%.2f  src=%s",
                 r["vulnerability_id"], r["package_name"],
                 r["reachability"] or "NULL",
                 r["reach_confidence"] or 0.0,
                 r["reach_source"] or "-")

    # ── reset reachability fields so workflow runs fresh ──────────────────────
    log.info("")
    log.info("Resetting reachability fields for fresh run...")
    await pool.execute(
        """UPDATE dependency_findings
           SET reachability=NULL, reach_evidence=NULL,
               reach_confidence=NULL, reach_source=NULL
           WHERE run_id=$1""",
        run_id,
    )

    # ── run reachability workflow ─────────────────────────────────────────────
    log.info("")
    log.info("Running reachability workflow...")
    await run_reachability_workflow(run_id=run_id, scan_path=scan_path, pool=pool)

    # ── show findings AFTER ───────────────────────────────────────────────────
    after = await pool.fetch(
        """SELECT vulnerability_id, package_name, reachability, reach_confidence,
                  reach_source, reach_evidence
           FROM dependency_findings WHERE run_id=$1 ORDER BY package_name""",
        run_id,
    )
    log.info("")
    log.info("=" * 60)
    log.info("RESULTS — %d findings:", len(after))
    log.info("=" * 60)
    for r in after:
        log.info("  %-30s %-25s  %-22s  conf=%.2f  src=%s",
                 r["vulnerability_id"], r["package_name"],
                 r["reachability"] or "NULL",
                 r["reach_confidence"] or 0.0,
                 r["reach_source"] or "-")
        if r["reach_evidence"]:
            for line in (r["reach_evidence"] or "").splitlines()[:4]:
                log.info("    %s", line)

    await pool.close()


asyncio.run(main())

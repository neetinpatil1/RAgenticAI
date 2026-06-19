"""
core/watchdog.py
=================
SLA monitor — runs every 5 minutes as a background task.

Design (SSDLC_Design_v3.2.docx §8.2):
  SELECT runs WHERE state_age > sla_for(state)
  → alert + auto-replay if eligible

Responsibilities:
  1. Find jobs breaching SLA thresholds (pending too long / processing too long).
  2. Log WATCHDOG_ALERT audit events for every breach.
  3. Auto-replay failed jobs that have remaining attempts.
  4. Clean up expired agent sessions (TTL enforcement).

Phase 0: alerts logged to stdout + audit log.
Phase 1+: forward alerts to Grafana via Prometheus metrics / PagerDuty webhook.
"""

import asyncio
import logging
from datetime import datetime, timezone

from core.config import settings
from core.pg_job_queue import PGJobQueue, JobState
from core.audit_logger import AuditLogger, AuditEvent

logger = logging.getLogger(__name__)


class Watchdog:
    """
    Background SLA monitor. Start with run_forever() as an asyncio task.

    Designed to run on Mac 2 in Phase 1+. In Phase 0 it runs as a
    background task within the Agent Monolith on Mac 1.
    """

    def __init__(
        self,
        job_queue: PGJobQueue,
        audit: AuditLogger,
        pool,    # asyncpg.Pool — typed loosely to avoid circular imports
    ):
        self._queue = job_queue
        self._audit = audit
        self._pool = pool
        self._running = False

    async def run_forever(self) -> None:
        """
        Main watchdog loop. Runs until stopped.
        Interval: settings.watchdog.interval_seconds (default 300s / 5 min).
        """
        self._running = True
        logger.info(
            "Watchdog started | interval=%ds SLA_pending=%ds SLA_processing=%ds",
            settings.watchdog.interval_seconds,
            settings.watchdog.sla_pending_seconds,
            settings.watchdog.sla_processing_seconds,
        )

        while self._running:
            try:
                await self._tick()
            except Exception as exc:
                # Watchdog must not crash — log and continue
                logger.error("Watchdog tick error: %s", exc, exc_info=True)

            await asyncio.sleep(settings.watchdog.interval_seconds)

    async def _tick(self) -> None:
        """One watchdog cycle: check SLAs, clean sessions, replay failures."""
        now = datetime.now(timezone.utc)
        logger.debug("Watchdog tick | time=%s", now.isoformat())

        # --- 1. Find SLA breaches ---
        stale_jobs = await self._queue.get_stale_jobs(
            pending_sla_seconds=settings.watchdog.sla_pending_seconds,
            processing_sla_seconds=settings.watchdog.sla_processing_seconds,
        )

        for job in stale_jobs:
            logger.warning(
                "SLA breach | job_id=%s type=%s state=%s run=%s",
                job["id"], job["job_type"], job["state"], job["run_id"]
            )
            # Write alert to audit log
            await self._audit.log(
                event_type=AuditEvent.WATCHDOG_ALERT,
                actor="watchdog",
                run_id=job["run_id"],
                entity_type="job",
                entity_id=str(job["id"]),
                payload={
                    "job_type":     job["job_type"],
                    "state":        job["state"],
                    "attempt_count": job["attempt_count"],
                    "sla_breach":   True,
                },
            )

            # --- 2. Auto-replay failed jobs with remaining attempts ---
            if (
                job["state"] == JobState.FAILED
                and job["attempt_count"] < job["max_attempts"]
            ):
                await self._queue.fail_job(
                    job_id=job["id"],
                    error="Watchdog: auto-replay after SLA breach",
                    retry=True,
                )
                await self._audit.log(
                    event_type=AuditEvent.WATCHDOG_REPLAY,
                    actor="watchdog",
                    run_id=job["run_id"],
                    entity_type="job",
                    entity_id=str(job["id"]),
                    payload={"reason": "SLA breach auto-replay"},
                )
                logger.info("Watchdog replayed job | id=%s", job["id"])

        # --- 3. Clean up orphaned pending jobs for terminal runs ---
        # Jobs left in 'pending' state for runs that have already completed/failed/killed
        # will never be consumed. Mark them done so they stop firing SLA alerts.
        async with self._pool.acquire() as conn:
            cleaned = await conn.execute("""
                UPDATE pg_jobs SET state='done', done_at=NOW()
                WHERE state = 'pending'
                  AND run_id IN (
                      SELECT run_id FROM workflow_runs
                      WHERE state IN ('completed', 'failed', 'killed')
                  )
            """)
        count_cleaned = cleaned.split()[-1] if cleaned else "0"
        if count_cleaned != "0":
            logger.info("Watchdog: marked %s orphaned pending jobs as done", count_cleaned)

        # --- 4. Clean up expired agent sessions ---
        async with self._pool.acquire() as conn:
            deleted = await conn.execute(
                "DELETE FROM agent_sessions WHERE expires_at < NOW()"
            )
        # asyncpg returns "DELETE N" string
        count_str = deleted.split()[-1] if deleted else "0"
        if count_str != "0":
            logger.debug("Watchdog: cleaned %s expired sessions", count_str)

    def stop(self) -> None:
        """Signal the watchdog to stop after the current tick."""
        self._running = False
        logger.info("Watchdog stop requested")

"""
core/pg_job_queue.py
====================
PostgreSQL-backed job queue using FOR UPDATE SKIP LOCKED.

Replaces Kafka in Phase 0/1. Graduate to Kafka only when:
  - PG queue p95 dispatch latency > 30s sustained, OR
  - >5 services need fan-out, OR
  - Cross-service replay is required

Design (SSDLC_Design_v3.2.docx §8):
  - Job row + workflow state + outbox written in ONE transaction.
    This dissolves the dual-write problem without needing a message broker.
  - Agents poll by calling pick_job() — safe for parallel workers via SKIP LOCKED.
  - Failed jobs are retried up to max_attempts before being marked failed.

Job lifecycle:
  pending → processing → done
                       ↘ failed (after max_attempts exhausted)

Job types (Phase 0):
  code.batch.submitted  — new scan path received, trigger SAST agent
  fp_challenge.pending  — findings ready for FP pipeline
  human.review.pending  — deadlocked findings queued for human
  scan.completed        — all agents done, results ready
"""

import asyncpg
import logging
from datetime import datetime, timezone
from typing import Any, Optional
import json

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Job type constants — use these instead of raw strings
# ---------------------------------------------------------------------------
class JobType:
    CODE_BATCH_SUBMITTED  = "code.batch.submitted"
    FP_CHALLENGE_PENDING  = "fp_challenge.pending"
    HUMAN_REVIEW_PENDING  = "human.review.pending"
    SCAN_COMPLETED        = "scan.completed"
    # Phase 1+ additions
    SCA_SCAN_PENDING      = "sca.scan.pending"
    CODE_REVIEW_PENDING   = "code_review.pending"


class JobState:
    PENDING    = "pending"
    PROCESSING = "processing"
    DONE       = "done"
    FAILED     = "failed"


class PGJobQueue:
    """
    Async job queue backed by the pg_jobs table.
    One instance shared across the application — initialised at startup.
    """

    def __init__(self, pool: asyncpg.Pool):
        self._pool = pool

    async def enqueue(
        self,
        job_type: str,
        run_id: str,
        payload: dict[str, Any],
        priority: int = 5,
        conn: Optional[asyncpg.Connection] = None,
    ) -> int:
        """
        Insert a new job into the queue.

        Pass an existing `conn` to include the insert in a larger transaction
        (e.g. write findings + enqueue FP job atomically).

        Args:
            job_type: One of JobType.* constants.
            run_id:   Associated workflow run.
            payload:  Job-specific data dict.
            priority: 1 (highest) to 10 (lowest). Default 5.
            conn:     Optional existing connection for transactional enqueue.

        Returns:
            New job ID (BIGSERIAL).
        """
        sql = """
            INSERT INTO pg_jobs (job_type, run_id, payload, priority)
            VALUES ($1, $2, $3::jsonb, $4)
            RETURNING id
        """
        payload_json = json.dumps(payload)

        if conn:
            # Use caller's transaction — atomically pairs with other writes
            row = await conn.fetchrow(sql, job_type, run_id, payload_json, priority)
        else:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(sql, job_type, run_id, payload_json, priority)

        job_id = row["id"]
        logger.debug("Job enqueued | type=%s run=%s id=%s", job_type, run_id, job_id)
        return job_id

    async def pick_job(self, job_type: str) -> Optional[dict[str, Any]]:
        """
        Atomically claim one pending job of the given type.

        Uses FOR UPDATE SKIP LOCKED so multiple workers can poll safely
        without collisions — each gets a different job.

        Returns None if no jobs are available.
        """
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    """
                    SELECT id, job_type, run_id, payload, attempt_count, max_attempts
                    FROM pg_jobs
                    WHERE state = 'pending'
                      AND job_type = $1
                      AND scheduled_at <= NOW()
                    ORDER BY priority ASC, scheduled_at ASC
                    LIMIT 1
                    FOR UPDATE SKIP LOCKED
                    """,
                    job_type,
                )
                if not row:
                    return None

                # Mark as processing within the same transaction
                await conn.execute(
                    """
                    UPDATE pg_jobs
                    SET state        = 'processing',
                        picked_at    = NOW(),
                        attempt_count = attempt_count + 1
                    WHERE id = $1
                    """,
                    row["id"],
                )

        job = dict(row)
        job["payload"] = json.loads(job["payload"])
        logger.debug("Job picked | type=%s id=%s run=%s", job_type, job["id"], job["run_id"])
        return job

    async def complete_job(self, job_id: int) -> None:
        """Mark a job as successfully completed."""
        async with self._pool.acquire() as conn:
            await conn.execute(
                "UPDATE pg_jobs SET state='done', done_at=NOW() WHERE id=$1",
                job_id,
            )

    async def fail_job(self, job_id: int, error: str, retry: bool = True) -> None:
        """
        Mark a job as failed.
        If retry=True and attempts remain, reset to 'pending' for retry.
        If max_attempts exhausted, permanently mark as 'failed'.
        """
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT attempt_count, max_attempts FROM pg_jobs WHERE id=$1", job_id
            )
            if row and retry and row["attempt_count"] < row["max_attempts"]:
                # Exponential backoff: 2^attempt minutes
                backoff = f"{2 ** row['attempt_count']} minutes"
                await conn.execute(
                    f"""
                    UPDATE pg_jobs
                    SET state = 'pending',
                        error_msg = $1,
                        scheduled_at = NOW() + INTERVAL '{backoff}'
                    WHERE id = $2
                    """,
                    error, job_id,
                )
                logger.warning("Job will retry | id=%s backoff=%s", job_id, backoff)
            else:
                await conn.execute(
                    "UPDATE pg_jobs SET state='failed', error_msg=$1, done_at=NOW() WHERE id=$2",
                    error, job_id,
                )
                logger.error("Job permanently failed | id=%s error=%s", job_id, error)

    async def get_stale_jobs(
        self,
        pending_sla_seconds: int,
        processing_sla_seconds: int,
    ) -> list[dict]:
        """
        Find jobs breaching SLA — used by the Watchdog.

        Returns jobs that have been in 'pending' or 'processing' state
        longer than their respective SLA thresholds.
        """
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT id, job_type, run_id, state, attempt_count, max_attempts,
                       scheduled_at, picked_at, created_at
                FROM pg_jobs
                WHERE
                    (state = 'pending'    AND created_at   < NOW() - ($1 || ' seconds')::interval)
                 OR (state = 'processing' AND picked_at    < NOW() - ($2 || ' seconds')::interval)
                ORDER BY created_at ASC
                """,
                str(pending_sla_seconds),
                str(processing_sla_seconds),
            )
        return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Module-level singleton — replaced at startup
# ---------------------------------------------------------------------------
_queue_instance: Optional[PGJobQueue] = None


def init_job_queue(pool: asyncpg.Pool) -> None:
    """Call once at application startup after DB pool is created."""
    global _queue_instance
    _queue_instance = PGJobQueue(pool)


def get_job_queue() -> PGJobQueue:
    """Dependency injection helper."""
    if _queue_instance is None:
        raise RuntimeError("PGJobQueue not initialised — call init_job_queue() first")
    return _queue_instance

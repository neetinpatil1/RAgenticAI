from __future__ import annotations

"""
core/state/workflow_state.py
=============================
PostgreSQL-backed workflow state — the authoritative truth for all runs.

Design (SSDLC_Design_v3.2.docx §8.1):
  "Agents read PG before acting, write to PG after acting.
   Recovery point if anything crashes."

  - Agents NEVER hold authoritative state in memory.
  - If an agent crashes mid-run, the watchdog detects it via state_age
    and can replay the job from the last written PG state.
  - State transitions are written atomically with the next job enqueue
    (no dual-write problem in Phase 0/1).

State machine:
  pending → running → completed
                    ↘ failed
                    ↘ cancelled
"""

import asyncpg
import logging
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)


class WorkflowState:
    """
    Thin async wrapper around the workflow_runs table.

    Agents use this to:
      1. Create a new run record when a scan starts.
      2. Update state as the run progresses.
      3. Query current state for recovery / UI.
    """

    def __init__(self, pool: asyncpg.Pool):
        self._pool = pool

    async def create_run(
        self,
        run_id: str,
        scan_path: str,
        agent: str = "sast",
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """
        Insert a new workflow run record in 'pending' state.

        Args:
            run_id:    Unique run identifier (e.g. scan_20250617_143022).
            scan_path: Local path or git URL being scanned.
            agent:     Which agent owns this run.
            metadata:  Optional extra context (branch, commit SHA, etc.).

        Returns:
            The run_id (echoed back for convenience).
        """
        import json
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO workflow_runs (run_id, scan_path, agent, state, metadata)
                VALUES ($1, $2, $3, 'pending', $4::jsonb)
                ON CONFLICT (run_id) DO NOTHING
                """,
                run_id,
                scan_path,
                agent,
                json.dumps(metadata or {}),
            )
        logger.info("Workflow run created | run=%s path=%s", run_id, scan_path)
        return run_id

    async def set_running(self, run_id: str) -> None:
        """Mark run as started. Records started_at timestamp."""
        await self._update_state(run_id, "running", set_started=True)

    async def set_completed(self, run_id: str) -> None:
        """Mark run as successfully completed."""
        await self._update_state(run_id, "completed", set_completed=True)

    async def set_failed(self, run_id: str, error: str) -> None:
        """Mark run as failed and record the error message."""
        await self._update_state(run_id, "failed", error=error, set_completed=True)

    async def get_run(self, run_id: str) -> Optional[dict]:
        """Fetch full run record. Returns None if not found."""
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM workflow_runs WHERE run_id = $1", run_id
            )
        return dict(row) if row else None

    async def list_runs(
        self,
        state: Optional[str] = None,
        limit: int = 50,
    ) -> list[dict]:
        """List recent runs, optionally filtered by state."""
        async with self._pool.acquire() as conn:
            if state:
                rows = await conn.fetch(
                    "SELECT * FROM workflow_runs WHERE state=$1 ORDER BY created_at DESC LIMIT $2",
                    state, limit,
                )
            else:
                rows = await conn.fetch(
                    "SELECT * FROM workflow_runs ORDER BY created_at DESC LIMIT $1", limit
                )
        return [dict(r) for r in rows]

    async def _update_state(
        self,
        run_id: str,
        state: str,
        error: Optional[str] = None,
        set_started: bool = False,
        set_completed: bool = False,
    ) -> None:
        """Internal helper to transition state with appropriate timestamps."""
        async with self._pool.acquire() as conn:
            if set_started:
                await conn.execute(
                    "UPDATE workflow_runs SET state=$1, started_at=NOW() WHERE run_id=$2",
                    state, run_id,
                )
            elif set_completed:
                await conn.execute(
                    """
                    UPDATE workflow_runs
                    SET state=$1, completed_at=NOW(), error_msg=$2
                    WHERE run_id=$3
                    """,
                    state, error, run_id,
                )
            else:
                await conn.execute(
                    "UPDATE workflow_runs SET state=$1 WHERE run_id=$2",
                    state, run_id,
                )
        logger.debug("Workflow state → %s | run=%s", state, run_id)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
_workflow_state_instance: Optional[WorkflowState] = None


def init_workflow_state(pool: asyncpg.Pool) -> None:
    global _workflow_state_instance
    _workflow_state_instance = WorkflowState(pool)


def get_workflow_state() -> WorkflowState:
    if _workflow_state_instance is None:
        raise RuntimeError("WorkflowState not initialised — call init_workflow_state() first")
    return _workflow_state_instance

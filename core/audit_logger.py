"""
core/audit_logger.py
====================
Append-only audit ledger backed by PostgreSQL.

Design rules (from SSDLC_Design_v3.2.docx §8):
  - Every agent action, human decision, and system event is recorded here.
  - NEVER update or delete audit rows — this is a regulatory requirement.
  - Queries by run_id or entity for investigation and compliance reporting.

Usage:
    from core.audit_logger import audit
    await audit.log(
        event_type="finding.created",
        actor="sast_agent",
        run_id=run_id,
        entity_type="finding",
        entity_id=str(finding_id),
        payload={"rule_id": "...", "severity": "HIGH"}
    )
"""

import asyncpg
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Standard event types — use these constants to keep event names consistent
# ---------------------------------------------------------------------------
class AuditEvent:
    # Workflow lifecycle
    WORKFLOW_STARTED    = "workflow.started"
    WORKFLOW_COMPLETED  = "workflow.completed"
    WORKFLOW_FAILED     = "workflow.failed"

    # Job queue
    JOB_DISPATCHED      = "job.dispatched"
    JOB_PICKED          = "job.picked"
    JOB_DONE            = "job.done"
    JOB_FAILED          = "job.failed"
    JOB_REPLAYED        = "job.replayed"          # watchdog auto-replay

    # Findings
    FINDING_CREATED     = "finding.created"
    FINDING_BASELINE    = "finding.baseline"       # first-scan baseline recorded

    # FP pipeline
    FP_LAYER1_RESOLVED  = "fp.layer1.resolved"
    FP_LAYER3_DECIDED   = "fp.layer3.decided"
    FP_ESCALATED        = "fp.escalated"           # re-run on Tier 1
    FP_DEADLOCK         = "fp.deadlock"            # sent to human queue

    # Human actions (label exhaust)
    LABEL_CAPTURED      = "label.captured"
    LABEL_QUARANTINED   = "label.quarantined"      # retraction/overturning

    # SLA watchdog
    WATCHDOG_ALERT      = "watchdog.alert"
    WATCHDOG_REPLAY     = "watchdog.replay"

    # Scan input
    SCAN_STARTED        = "scan.started"
    SCAN_COMPLETED      = "scan.completed"


class AuditLogger:
    """
    Thread-safe, async audit logger.
    Writes directly to PostgreSQL audit_log table (append-only).
    """

    def __init__(self, pool: asyncpg.Pool):
        # asyncpg connection pool shared across the application
        self._pool = pool

    async def log(
        self,
        event_type: str,
        actor: str,
        run_id: str | None = None,
        entity_type: str | None = None,
        entity_id: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> None:
        """
        Write one immutable audit event to the ledger.

        Args:
            event_type:  One of AuditEvent.* constants.
            actor:       Who triggered the event (agent name or user id).
            run_id:      Associated workflow run (optional).
            entity_type: Type of the affected entity (finding/job/label/etc.).
            entity_id:   ID of the affected entity.
            payload:     Arbitrary JSON context — full event details.
        """
        import json
        payload_json = json.dumps(payload or {})

        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO audit_log
                        (event_type, actor, run_id, entity_type, entity_id, payload)
                    VALUES ($1, $2, $3, $4, $5, $6::jsonb)
                    """,
                    event_type,
                    actor,
                    run_id,
                    entity_type,
                    entity_id,
                    payload_json,
                )
        except Exception as exc:
            # Log failure but NEVER raise — audit failures must not break the main flow
            logger.error(
                "Audit write failed | event=%s actor=%s run=%s error=%s",
                event_type, actor, run_id, exc
            )

    async def get_run_events(self, run_id: str) -> list[dict]:
        """Fetch all audit events for a given run (for investigation/UI)."""
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT event_type, actor, entity_type, entity_id, payload, created_at
                FROM audit_log
                WHERE run_id = $1
                ORDER BY created_at ASC
                """,
                run_id,
            )
        return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Module-level placeholder — replaced with real instance after DB pool is ready
# See api/agent_gateway.py startup hook for initialisation
# ---------------------------------------------------------------------------
_audit_instance: AuditLogger | None = None


def init_audit_logger(pool: asyncpg.Pool) -> None:
    """Call once at application startup after DB pool is created."""
    global _audit_instance
    _audit_instance = AuditLogger(pool)


def get_audit_logger() -> AuditLogger:
    """Dependency injection helper for FastAPI routes and agents."""
    if _audit_instance is None:
        raise RuntimeError("AuditLogger not initialised — call init_audit_logger() first")
    return _audit_instance

"""
api/agent_gateway.py
=====================
FastAPI gateway — the single HTTP interface for the SSDLC platform.

Phase 0 endpoints:
  POST /api/v1/scan          — submit a local path for SAST scanning
  GET  /api/v1/scan/{run_id} — get scan status and results
  GET  /api/v1/findings      — list findings (with filters)
  POST /api/v1/label         — capture human label (approve / FP dismiss)
  GET  /api/v1/runs          — list recent workflow runs
  GET  /health               — liveness check

Design (SSDLC_Design_v3.2.docx §14):
  - All data read from PostgreSQL — no separate data store.
  - Real-time agent activity streamed via WebSocket (Phase 1+).
  - Auth: session-token based, roles: CISO | SECURITY_ENGINEER | DEVELOPER.
    Phase 0: auth is stubbed — add before Phase 1 staging.
  - Served on port 8080 (Mac 1).
"""

import asyncio
import logging
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import asyncpg
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from core.config import settings
from core.audit_logger import AuditLogger, AuditEvent, init_audit_logger, get_audit_logger
from core.pg_job_queue import PGJobQueue, JobType, init_job_queue, get_job_queue
from core.prompt_manager import PromptManager, init_prompt_manager, get_prompt_manager
from core.state.workflow_state import WorkflowState, init_workflow_state, get_workflow_state
from core.state.vector_memory import VectorMemory, init_vector_memory, get_vector_memory
from core.fp_pipeline.layer1_rules import Layer1Rules
from core.fp_pipeline.layer3_llm import Layer3LLM
from core.watchdog import Watchdog
from tools.semgrep_tool import SemgrepTool
from workflows.sast_workflow import run_sast_workflow

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level singletons — initialised in lifespan
# ---------------------------------------------------------------------------
_pool: Optional[asyncpg.Pool] = None
_watchdog: Optional[Watchdog] = None
_watchdog_task: Optional[asyncio.Task] = None


# ---------------------------------------------------------------------------
# Application lifespan — startup and shutdown
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan context manager.
    Initialises DB pool, all singletons, and starts the watchdog.
    """
    global _pool, _watchdog, _watchdog_task

    # --- Database connection pool ---
    logger.info("Connecting to PostgreSQL | dsn=%s", settings.db.dsn.replace(settings.db.password, "***"))
    _pool = await asyncpg.create_pool(
        dsn=settings.db.dsn,
        min_size=settings.db.pool_min,
        max_size=settings.db.pool_max,
    )

    # --- Initialise all singletons with the pool ---
    init_audit_logger(_pool)
    init_job_queue(_pool)
    init_workflow_state(_pool)
    init_vector_memory(_pool)
    init_prompt_manager(settings.prompts_dir)

    # --- Start watchdog as background task ---
    audit = get_audit_logger()
    _watchdog = Watchdog(get_job_queue(), audit, _pool)
    _watchdog_task = asyncio.create_task(_watchdog.run_forever())
    logger.info("Watchdog task started")

    logger.info("SSDLC Platform started | port=%d", settings.api_port)
    yield

    # --- Shutdown ---
    if _watchdog:
        _watchdog.stop()
    if _watchdog_task:
        _watchdog_task.cancel()
    if _pool:
        await _pool.close()
    logger.info("SSDLC Platform shut down cleanly")


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------
app = FastAPI(
    title="SSDLC Multi-Agent Platform",
    description="AI-powered security assessment platform — Phase 0 (SAST only)",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8080"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    """Request body for POST /api/v1/scan"""
    path: str = Field(..., description="Absolute local path to the code to scan")
    metadata: dict = Field(default_factory=dict, description="Optional scan context (project, team, etc.)")


class ScanResponse(BaseModel):
    run_id: str
    status: str
    message: str


class LabelRequest(BaseModel):
    """Request body for POST /api/v1/label — captures human FP verdict"""
    finding_id: str = Field(..., description="UUID of the finding being labelled")
    run_id:     str = Field(..., description="Associated workflow run")
    verdict:    str = Field(..., description="REAL or FP")
    fp_category: Optional[str] = Field(None, description="Required if verdict=FP")
    justification: str = Field(..., description="Mandatory explanation (min 10 chars)")
    labeler_id:  str = Field(default="anonymous", description="Reviewer username")

    class Config:
        # Phase 0: simple validation. Phase 1+: auth middleware sets labeler_id.
        pass


# ---------------------------------------------------------------------------
# Dependency injection helpers
# ---------------------------------------------------------------------------

def get_pool() -> asyncpg.Pool:
    if _pool is None:
        raise HTTPException(503, "Database not ready")
    return _pool


def _build_workflow_deps() -> dict:
    """Assemble dependency dict for SAST workflow nodes."""
    pool = get_pool()
    prompt_manager = get_prompt_manager()
    vector_memory = get_vector_memory()

    layer1 = Layer1Rules(settings.semgrep.rules_path)
    layer3 = Layer3LLM(vector_memory, prompt_manager)

    return {
        "pool":           pool,
        "audit":          get_audit_logger(),
        "job_queue":      get_job_queue(),
        "workflow_state": get_workflow_state(),
        "vector_memory":  vector_memory,
        "semgrep_tool":   SemgrepTool(),
        "layer1_rules":   layer1,
        "layer3_llm":     layer3,
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    """Liveness probe. Returns 200 if API is up and DB is reachable."""
    try:
        async with _pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}
    except Exception as exc:
        raise HTTPException(503, f"DB unavailable: {exc}")


@app.post("/api/v1/scan", response_model=ScanResponse, status_code=202)
async def submit_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    pool: asyncpg.Pool = Depends(get_pool),
):
    """
    Submit a local path for SAST scanning.

    Validation:
      - Path must exist on the filesystem.
      - Path must be a directory.

    The scan runs asynchronously. Poll GET /api/v1/scan/{run_id} for status.
    """
    scan_path = Path(request.path)
    if not scan_path.exists():
        raise HTTPException(400, f"Path does not exist: {request.path}")
    if not scan_path.is_dir():
        raise HTTPException(400, f"Path must be a directory: {request.path}")

    # Generate unique run ID with timestamp for readability
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    run_id = f"scan_{timestamp}_{uuid.uuid4().hex[:6]}"

    # Create workflow run record in PG (state=pending)
    wf_state = get_workflow_state()
    await wf_state.create_run(
        run_id=run_id,
        scan_path=str(scan_path.resolve()),
        agent="sast",
        metadata=request.metadata,
    )

    # Enqueue the scan job (picked up by background worker)
    job_queue = get_job_queue()
    await job_queue.enqueue(
        job_type=JobType.CODE_BATCH_SUBMITTED,
        run_id=run_id,
        payload={"scan_path": str(scan_path.resolve()), "metadata": request.metadata},
    )

    # Run the SAST workflow as a FastAPI background task
    # Phase 1+: this will be a separate worker process polling pg_jobs
    deps = _build_workflow_deps()
    background_tasks.add_task(
        run_sast_workflow,
        run_id=run_id,
        scan_path=str(scan_path.resolve()),
        deps=deps,
    )

    logger.info("Scan submitted | run=%s path=%s", run_id, request.path)
    return ScanResponse(
        run_id=run_id,
        status="accepted",
        message=f"Scan started. Poll GET /api/v1/scan/{run_id} for status.",
    )


@app.get("/api/v1/scan/{run_id}")
async def get_scan_status(run_id: str, pool: asyncpg.Pool = Depends(get_pool)):
    """Get current status and summary for a scan run."""
    wf_state = get_workflow_state()
    run = await wf_state.get_run(run_id)
    if not run:
        raise HTTPException(404, f"Run not found: {run_id}")

    # Fetch finding counts
    async with pool.acquire() as conn:
        counts = await conn.fetchrow(
            """
            SELECT
                COUNT(*) FILTER (WHERE severity = 'CRITICAL') AS critical,
                COUNT(*) FILTER (WHERE severity = 'HIGH')     AS high,
                COUNT(*) FILTER (WHERE severity = 'MEDIUM')   AS medium,
                COUNT(*) FILTER (WHERE severity = 'LOW')      AS low,
                COUNT(*) FILTER (WHERE is_baseline = TRUE)    AS baseline,
                COUNT(*)                                       AS total
            FROM findings_reports
            WHERE run_id = $1
            """,
            run_id,
        )

    return {
        "run_id":      run["run_id"],
        "status":      run["state"],
        "scan_path":   run["scan_path"],
        "created_at":  run["created_at"].isoformat() if run["created_at"] else None,
        "completed_at": run["completed_at"].isoformat() if run["completed_at"] else None,
        "error":       run["error_msg"],
        "findings": dict(counts) if counts else {},
    }


@app.get("/api/v1/findings")
async def list_findings(
    run_id:   Optional[str] = Query(None, description="Filter by run"),
    severity: Optional[str] = Query(None, description="CRITICAL|HIGH|MEDIUM|LOW"),
    verdict:  Optional[str] = Query(None, description="REAL|FP|ESCALATED|DEADLOCK"),
    limit:    int            = Query(50, le=200),
    pool:     asyncpg.Pool   = Depends(get_pool),
):
    """List findings with optional filters. Used by the Command Centre UI."""
    conditions = []
    params: list = []

    if run_id:
        params.append(run_id)
        conditions.append(f"fr.run_id = ${len(params)}")
    if severity:
        params.append(severity.upper())
        conditions.append(f"fr.severity = ${len(params)}")
    if verdict:
        params.append(verdict.upper())
        conditions.append(f"fp.verdict = ${len(params)}")

    where = "WHERE " + " AND ".join(conditions) if conditions else ""
    params.append(limit)

    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"""
            SELECT
                fr.id, fr.run_id, fr.rule_id, fr.cwe_id, fr.severity,
                fr.file_path, fr.line_start, fr.message, fr.framework,
                fr.is_baseline, fr.created_at,
                fp.verdict, fp.confidence, fp.fp_category, fp.reasoning,
                fp.label_status
            FROM findings_reports fr
            LEFT JOIN fp_decisions fp ON fp.finding_id = fr.id
            {where}
            ORDER BY fr.created_at DESC
            LIMIT ${len(params)}
            """,
            *params,
        )

    return {"findings": [dict(r) for r in rows], "count": len(rows)}


@app.post("/api/v1/label", status_code=201)
async def capture_label(
    request: LabelRequest,
    pool: asyncpg.Pool = Depends(get_pool),
):
    """
    Capture a human FP label — the core of the labeling-as-exhaust flywheel.

    Every call here:
      1. Writes to human_labels table.
      2. Updates fp_decisions label_status to 'human-confirmed'.
      3. Updates finding_embeddings confidence_weight to 1.0.
      4. Writes audit log event.

    All in ONE transaction — no dual-write problem.

    Phase 0: Called from the minimal HTML labeling screen.
    Phase 1+: Called from the React /console/labeling screen.
    """
    if len(request.justification) < 10:
        raise HTTPException(400, "justification must be at least 10 characters")

    if request.verdict not in ("REAL", "FP"):
        raise HTTPException(400, "verdict must be REAL or FP")

    if request.verdict == "FP" and not request.fp_category:
        raise HTTPException(400, "fp_category is required when verdict is FP")

    vector_memory = get_vector_memory()
    audit = get_audit_logger()
    label_id = str(uuid.uuid4())

    async with pool.acquire() as conn:
        async with conn.transaction():
            # 1. Insert human label
            await conn.execute(
                """
                INSERT INTO human_labels
                    (id, finding_id, labeler_id, verdict, fp_category,
                     justification, confidence_tier, weight)
                VALUES ($1,$2,$3,$4,$5,$6,'human-confirmed',1.0)
                """,
                label_id, request.finding_id, request.labeler_id,
                request.verdict, request.fp_category, request.justification,
            )

            # 2. Update FP decision label status
            await conn.execute(
                """
                UPDATE fp_decisions
                SET label_status = 'human-confirmed', reviewed_at = NOW()
                WHERE finding_id = $1
                """,
                request.finding_id,
            )

    # 3. Update embedding weight (outside transaction — non-critical)
    try:
        await vector_memory.update_weight(
            finding_id=request.finding_id,
            label_status="human-confirmed",
            confidence_weight=1.0,
        )
    except Exception as exc:
        logger.warning("Embedding weight update failed | finding=%s error=%s", request.finding_id, exc)

    # 4. Audit log
    await audit.log(
        event_type=AuditEvent.LABEL_CAPTURED,
        actor=request.labeler_id,
        run_id=request.run_id,
        entity_type="finding",
        entity_id=request.finding_id,
        payload={
            "verdict":      request.verdict,
            "fp_category":  request.fp_category,
            "label_id":     label_id,
        },
    )

    return {"label_id": label_id, "status": "captured"}


@app.get("/api/v1/runs")
async def list_runs(
    limit: int = Query(20, le=100),
    pool: asyncpg.Pool = Depends(get_pool),
):
    """List recent workflow runs for the Command Centre dashboard."""
    wf_state = get_workflow_state()
    runs = await wf_state.list_runs(limit=limit)
    return {"runs": runs, "count": len(runs)}

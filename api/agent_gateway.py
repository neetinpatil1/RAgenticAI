"""
api/agent_gateway.py
=====================
FastAPI gateway — the single HTTP interface for the SSDLC platform.

Phase 0 endpoints:
  GET  /labeling                        — minimal HTML labeling screen
  POST /api/v1/scan                     — submit a local path for SAST scanning
  GET  /api/v1/scan/{run_id}            — get scan status and results
  GET  /api/v1/findings                 — list findings (with filters)
  GET  /api/v1/findings/next-for-review — next finding awaiting human review
  POST /api/v1/label                    — capture human label (approve / FP dismiss)
  GET  /api/v1/labels/count             — total human labels (Phase 0 gate progress)
  GET  /api/v1/runs                     — list recent workflow runs
  GET  /health                          — liveness check

Design (SSDLC_Design_v3.2.docx §14):
  - All data read from PostgreSQL — no separate data store.
  - Real-time agent activity streamed via WebSocket (Phase 1+).
  - Auth: session-token based, roles: CISO | SECURITY_ENGINEER | DEVELOPER.
    Phase 0: auth is stubbed — add before Phase 1 staging.
  - Served on port 8080 (Mac 1).
"""

import asyncio
import json
import logging
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncIterator, Optional

import asyncpg
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from core.config import settings
from db.migrations import run_migrations
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
# Jinja2 templates — serves labeling.html (Phase 0 labeling screen)
# ---------------------------------------------------------------------------
_TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

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

    # --- Run schema migrations (idempotent — safe on every startup) ---
    await run_migrations(_pool)

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
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "http://localhost:8080",
    ],
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

    import json as _json

    # Fetch finding counts grouped by severity + files affected
    async with pool.acquire() as conn:
        counts = await conn.fetchrow(
            """
            SELECT
                COUNT(*) FILTER (WHERE severity = 'CRITICAL') AS critical,
                COUNT(*) FILTER (WHERE severity = 'HIGH')     AS high,
                COUNT(*) FILTER (WHERE severity = 'MEDIUM')   AS medium,
                COUNT(*) FILTER (WHERE severity = 'LOW')      AS low,
                COUNT(*) FILTER (WHERE is_baseline = TRUE)    AS baseline,
                COUNT(*)                                       AS total,
                COUNT(DISTINCT file_path)                      AS files_with_findings
            FROM findings_reports
            WHERE run_id = $1
            """,
            run_id,
        )

    # Scan stats stored in metadata by node_enqueue_next
    meta = run["metadata"] or {}
    if isinstance(meta, str):
        try:
            meta = _json.loads(meta)
        except Exception:
            meta = {}

    findings_dict = dict(counts) if counts else {}

    return {
        "run_id":       run["run_id"],
        "status":       run["state"],
        "scan_path":    run["scan_path"],
        "created_at":   run["created_at"].isoformat() if run["created_at"] else None,
        "completed_at": run["completed_at"].isoformat() if run["completed_at"] else None,
        "error":        run["error_msg"],
        "scan_coverage": {
            "files_scanned":       meta.get("files_scanned", 0),
            "files_with_findings": findings_dict.get("files_with_findings", 0),
            "files_clean":         meta.get("files_clean", 0),
            "files_skipped":       meta.get("files_skipped", 0),
            "packages_total":      meta.get("packages_total", 0),
            "packages_by_file":    meta.get("packages_by_file", []),
            "scan_duration_ms":    meta.get("scan_duration_ms", 0),
        },
        "findings": {k: v for k, v in findings_dict.items() if k != "files_with_findings"},
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
                fr.file_path, fr.line_start, fr.line_end,
                fr.code_snippet, fr.message, fr.framework,
                fr.class_name, fr.method_name,
                fr.fix_suggestion, fr.owasp_category, fr.ref_urls,
                fr.likelihood, fr.impact,
                fr.is_baseline, fr.created_at,
                fp.verdict, fp.confidence, fp.fp_category, fp.reasoning,
                fp.label_status
            FROM findings_reports fr
            LEFT JOIN fp_decisions fp ON fp.finding_id = fr.id
            {where}
            ORDER BY
                CASE fr.severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH'     THEN 2
                    WHEN 'MEDIUM'   THEN 3
                    WHEN 'LOW'      THEN 4
                    ELSE                 5
                END,
                fr.created_at DESC
            LIMIT ${len(params)}
            """,
            *params,
        )

    def _decode_row(r) -> dict:
        d = dict(r)
        # asyncpg returns JSONB columns as raw strings — decode them
        if isinstance(d.get("ref_urls"), str):
            try:
                d["ref_urls"] = json.loads(d["ref_urls"])
            except Exception:
                d["ref_urls"] = []
        if d.get("ref_urls") is None:
            d["ref_urls"] = []
        return d

    return {"findings": [_decode_row(r) for r in rows], "count": len(rows)}


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


@app.get("/api/v1/scan/{run_id}/stream")
async def stream_scan_progress(run_id: str, pool: asyncpg.Pool = Depends(get_pool)):
    """
    SSE endpoint — streams real-time scan progress to the React UI.

    Events emitted (text/event-stream):
      {"type": "status",   "state": "pending|running|completed|failed"}
      {"type": "file",     "file": "relative/path.java", "index": N, "total": M}
      {"type": "progress", "pct": 0-100, "eta_seconds": N}
      {"type": "done",     "state": "completed|failed", "findings_count": N}
      {"type": "error",    "message": "..."}
    """
    wf_state = get_workflow_state()
    run = await wf_state.get_run(run_id)
    if not run:
        raise HTTPException(404, f"Run not found: {run_id}")

    scan_path = Path(run["scan_path"])

    async def _generate() -> AsyncIterator[str]:
        def _sse(data: dict) -> str:
            return f"data: {json.dumps(data)}\n\n"

        # --- Enumerate files the same extensions Semgrep targets ---
        _SCAN_EXTS = {
            ".java", ".py", ".js", ".ts", ".jsx", ".tsx",
            ".go", ".rb", ".php", ".cs", ".kt", ".scala",
            ".yaml", ".yml", ".json", ".tf", ".sh",
        }
        files: list[str] = []
        if scan_path.exists() and scan_path.is_dir():
            for p in sorted(scan_path.rglob("*")):
                if p.is_file() and p.suffix in _SCAN_EXTS:
                    try:
                        files.append(str(p.relative_to(scan_path)))
                    except ValueError:
                        files.append(p.name)

        total = len(files)
        yield _sse({"type": "status", "state": "running", "total_files": total})

        start_ts = asyncio.get_event_loop().time()
        # Stream file names progressively while the background scan runs
        for idx, f in enumerate(files, start=1):
            elapsed = asyncio.get_event_loop().time() - start_ts
            pct = round((idx / total) * 100) if total else 100
            rate = idx / elapsed if elapsed > 0 else 1
            eta = round((total - idx) / rate) if rate > 0 else 0

            yield _sse({
                "type":  "file",
                "file":  f,
                "index": idx,
                "total": total,
                "pct":   pct,
                "eta_seconds": eta,
            })

            # Check if scan already finished — no need to keep streaming
            current = await wf_state.get_run(run_id)
            state = current["state"] if current else "unknown"
            if state in ("completed", "failed"):
                break

            # Pace the file events (~100 files/sec feels natural)
            await asyncio.sleep(0.01)

        # --- Final poll until DB reflects terminal state ---
        for _ in range(120):  # max 120 × 0.5 s = 60 s wait
            current = await wf_state.get_run(run_id)
            state = current["state"] if current else "unknown"
            if state in ("completed", "failed"):
                break
            yield _sse({"type": "status", "state": state, "pct": 99})
            await asyncio.sleep(0.5)

        # Fetch final finding count
        async with pool.acquire() as conn:
            count = await conn.fetchval(
                "SELECT COUNT(*) FROM findings_reports WHERE run_id = $1", run_id
            )

        yield _sse({
            "type":           "done",
            "state":          state,
            "findings_count": count or 0,
            "total_files":    total,
        })

    return StreamingResponse(
        _generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":   "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/labeling", response_class=HTMLResponse)
async def labeling_screen(request: Request):
    """
    Serve the Phase 0 minimal HTML labeling screen.

    Accessible at: http://localhost:8080/labeling
    No auth in Phase 0 — reviewer name is stored in sessionStorage.
    Phase 1+: replaced by React /console/labeling with full auth + kappa stats.
    """
    return templates.TemplateResponse("labeling.html", {"request": request})


@app.get("/api/v1/findings/next-for-review")
async def next_finding_for_review(pool: asyncpg.Pool = Depends(get_pool)):
    """
    Return the next finding awaiting human review.

    Priority order:
      1. DEADLOCK findings (FP Challenger could not resolve — mandatory human)
      2. ESCALATED findings (LLM confidence too low)
      3. REAL findings from last 24h (spot-check for agreement measurement)

    Used by the labeling screen to load one finding at a time.
    Returns 404 when queue is empty.
    """
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT
                fr.id, fr.run_id, fr.rule_id, fr.cwe_id, fr.severity,
                fr.file_path, fr.line_start, fr.line_end,
                fr.code_snippet, fr.message, fr.framework,
                fr.class_name, fr.method_name,
                fr.fix_suggestion, fr.owasp_category, fr.ref_urls,
                fr.likelihood, fr.impact,
                fr.is_baseline,
                fp.verdict, fp.confidence, fp.fp_category, fp.reasoning,
                fp.label_status
            FROM findings_reports fr
            JOIN fp_decisions fp ON fp.finding_id = fr.id
            WHERE
                fp.label_status = 'agent-only'
                AND fp.verdict IN ('DEADLOCK', 'ESCALATED', 'REAL')
                AND fr.is_baseline = FALSE
            ORDER BY
                CASE fp.verdict
                    WHEN 'DEADLOCK'  THEN 1   -- highest priority
                    WHEN 'ESCALATED' THEN 2
                    ELSE                  3
                END,
                fr.severity DESC,
                fr.created_at ASC
            LIMIT 1
            """
        )

    if not row:
        raise HTTPException(404, "No findings awaiting review")

    d = dict(row)
    if isinstance(d.get("ref_urls"), str):
        try:
            d["ref_urls"] = json.loads(d["ref_urls"])
        except Exception:
            d["ref_urls"] = []
    if d.get("ref_urls") is None:
        d["ref_urls"] = []
    return {"finding": d}


@app.get("/api/v1/labels/count")
async def label_count(pool: asyncpg.Pool = Depends(get_pool)):
    """
    Return total human label count — used for Phase 0 gate progress bar.
    Gate: ≥200 labels with ≥75% LLM–human agreement.
    """
    async with pool.acquire() as conn:
        total = await conn.fetchval("SELECT COUNT(*) FROM human_labels")
        real_count = await conn.fetchval(
            "SELECT COUNT(*) FROM human_labels WHERE verdict = 'REAL'"
        )
        fp_count = await conn.fetchval(
            "SELECT COUNT(*) FROM human_labels WHERE verdict = 'FP'"
        )

    return {
        "total":      total,
        "real_count": real_count,
        "fp_count":   fp_count,
        "target":     200,
        "progress_pct": round((total / 200) * 100, 1) if total else 0,
    }


# ---------------------------------------------------------------------------
# React SPA — serve built UI from ui/dist/
# Must come LAST so API routes take priority.
# ---------------------------------------------------------------------------
_UI_DIST = Path(__file__).parent.parent / "ui" / "dist"

if _UI_DIST.exists():
    # Serve static assets (JS, CSS, images)
    app.mount("/assets", StaticFiles(directory=str(_UI_DIST / "assets")), name="assets")

    @app.get("/", include_in_schema=False)
    async def serve_root():
        return FileResponse(str(_UI_DIST / "index.html"))

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(full_path: str):
        """Catch-all — return index.html so React Router handles client-side routes."""
        file = _UI_DIST / full_path
        if file.exists() and file.is_file():
            return FileResponse(str(file))
        return FileResponse(str(_UI_DIST / "index.html"))

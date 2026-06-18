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
from workflows.code_review_workflow import run_code_review_workflow
from workflows.secret_scan_workflow import run_secret_scan_workflow
from workflows.sca_workflow import run_sca_workflow
from workflows.fp_challenger_workflow import run_fp_challenger_workflow

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
# Silence noisy third-party loggers
logging.getLogger("httpx").setLevel(logging.ERROR)
logging.getLogger("httpcore").setLevel(logging.ERROR)
logging.getLogger("asyncpg").setLevel(logging.ERROR)

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
# Phase 1: parallel agent launcher
# ---------------------------------------------------------------------------

async def _run_all_agents(run_id: str, scan_path: str, deps: dict) -> None:
    """
    Orchestration order (guaranteed):
      Step 1 — Code Knowledge Graph build (awaited, blocks step 2)
               Graph must be ready before code review so it can enrich LLM prompts.
      Step 2 — SAST + Secret Scanner + SCA run in parallel (graph already built)
      Step 3 — Code Review runs after SAST/SCA complete with full graph context

    return_exceptions=True ensures one agent crashing does not cancel the others.
    """
    import time as _t
    root = Path(scan_path)
    key  = str(root)

    # ── Step 1: Build code knowledge graph first ──────────────────────────────
    # Skip if already done (e.g. repeat scan of same project)
    if _graph_build_status.get(key, {}).get("status") not in ("done",):
        _graph_build_status[key] = {"status": "building", "error": None, "started_at": _t.time()}
        logger.warning("graph/build: starting BEFORE SAST for %s", root)
        await _run_graph_build(root)   # ← awaited: SAST waits for this
        logger.warning("graph/build: finished, SAST starting now for %s", root)
    else:
        logger.warning("graph/build: already done, skipping rebuild for %s", root)

    # ── Step 2: SAST only (awaited — writes findings to DB before code review) ──
    logger.info("SAST starting | run=%s", run_id)
    try:
        await run_sast_workflow(run_id=run_id, scan_path=scan_path, deps=deps)
    except Exception as exc:
        logger.error("SAST failed | run=%s error=%s", run_id, exc)
    logger.info("SAST complete | run=%s", run_id)

    # ── Step 3: Secrets + SCA + Code Review in parallel ───────────────────────
    # Pre-insert code_review_status='running' BEFORE the gather so the UI
    # immediately sees "running" when it polls — eliminates the race where
    # node_enumerate_files hasn't written its first row yet and the UI gives up.
    try:
        async with _pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS code_review_status (
                    run_id        TEXT PRIMARY KEY,
                    status        TEXT NOT NULL DEFAULT 'running',
                    files_done    INT  NOT NULL DEFAULT 0,
                    total_files   INT  NOT NULL DEFAULT 0,
                    pct           INT  NOT NULL DEFAULT 0,
                    current_file  TEXT,
                    findings_count INT NOT NULL DEFAULT 0,
                    updated_at    TIMESTAMPTZ DEFAULT NOW()
                )
            """)
            await conn.execute(
                """
                INSERT INTO code_review_status
                    (run_id, status, files_done, total_files, pct, current_file, findings_count, updated_at)
                VALUES ($1, 'running', 0, 0, 0, NULL, 0, NOW())
                ON CONFLICT (run_id) DO UPDATE SET
                    status='running', files_done=0, total_files=0, pct=0,
                    current_file=NULL, findings_count=0, updated_at=NOW()
                """,
                run_id,
            )
    except Exception as exc:
        logger.warning("Could not pre-insert code_review_status: %s", exc)

    logger.info("Secrets + SCA + Code Review starting in parallel | run=%s", run_id)
    results = await asyncio.gather(
        run_secret_scan_workflow(run_id=run_id, scan_path=scan_path, deps=deps),
        run_sca_workflow(run_id=run_id, scan_path=scan_path, deps=deps),
        run_code_review_workflow(run_id=run_id, scan_path=scan_path, deps=deps),
        return_exceptions=True,
    )
    for i, r in enumerate(results):
        if isinstance(r, Exception):
            agent = ["secret_scanner", "sca", "code_review"][i]
            logger.error("Agent failed | agent=%s run=%s error=%s", agent, run_id, r)
    logger.info("Secrets + SCA + Code Review complete | run=%s", run_id)

    # ── Step 4: FP Challenger ─────────────────────────────────────────────────
    # Pre-insert fp_challenge_status='running' so the UI detects it immediately
    # instead of waiting for node_load_findings to write the first row.
    try:
        async with _pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO fp_challenge_status
                    (run_id, status, findings_total, findings_done, pct, fp_found, current_finding, updated_at)
                VALUES ($1, 'running', 0, 0, 0, 0, NULL, NOW())
                ON CONFLICT (run_id) DO UPDATE SET
                    status='running', findings_total=0, findings_done=0, pct=0,
                    fp_found=0, current_finding=NULL, updated_at=NOW()
                """,
                run_id,
            )
    except Exception as exc:
        logger.warning("Could not pre-insert fp_challenge_status: %s", exc)

    logger.info("FP Challenger starting | run=%s", run_id)
    await run_fp_challenger_workflow(run_id=run_id, deps=deps)
    logger.info("FP Challenger complete | run=%s", run_id)


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

    # Mark graph as "building" immediately so the UI polling sees it right away
    # (the actual build runs inside _run_all_agents as step 1, before SAST)
    import time as _t
    _key = str(scan_path.resolve())
    if _graph_build_status.get(_key, {}).get("status") != "done":
        _graph_build_status[_key] = {"status": "building", "error": None, "started_at": _t.time()}

    # Phase 1: graph build → SAST/SCA/Secrets → Code Review (sequential steps inside)
    deps = _build_workflow_deps()
    background_tasks.add_task(
        _run_all_agents,
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
                COALESCE(fr.blast_radius, 0) AS blast_radius,
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
    limit: int = Query(50, le=200),
    pool: asyncpg.Pool = Depends(get_pool),
):
    """
    List recent workflow runs with per-run severity counts.
    Used by the Scan History screen.
    """
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT
                wr.run_id,
                wr.scan_path,
                wr.state,
                wr.created_at,
                wr.completed_at,
                wr.error_msg,
                wr.metadata,
                COUNT(fr.id) FILTER (WHERE fr.severity = 'CRITICAL') AS critical,
                COUNT(fr.id) FILTER (WHERE fr.severity = 'HIGH')     AS high,
                COUNT(fr.id) FILTER (WHERE fr.severity = 'MEDIUM')   AS medium,
                COUNT(fr.id) FILTER (WHERE fr.severity = 'LOW')      AS low,
                COUNT(fr.id)                                         AS total
            FROM workflow_runs wr
            LEFT JOIN findings_reports fr ON fr.run_id = wr.run_id
            GROUP BY wr.run_id, wr.scan_path, wr.state,
                     wr.created_at, wr.completed_at, wr.error_msg, wr.metadata
            ORDER BY wr.created_at DESC
            LIMIT $1
            """,
            limit,
        )

    result = []
    for r in rows:
        d = dict(r)
        # Parse metadata JSONB
        meta = d.get("metadata") or {}
        if isinstance(meta, str):
            try:
                meta = json.loads(meta)
            except Exception:
                meta = {}
        # Compute duration from metadata or timestamps
        duration_ms = meta.get("scan_duration_ms", 0)
        if not duration_ms and d.get("completed_at") and d.get("created_at"):
            delta = d["completed_at"] - d["created_at"]
            duration_ms = int(delta.total_seconds() * 1000)
        result.append({
            "run_id":       d["run_id"],
            "scan_path":    d["scan_path"],
            "project_name": d["scan_path"].rstrip("/").split("/")[-1] if d["scan_path"] else "—",
            "state":        d["state"],
            "created_at":   d["created_at"].isoformat() if d["created_at"] else None,
            "completed_at": d["completed_at"].isoformat() if d["completed_at"] else None,
            "duration_ms":  duration_ms,
            "error":        d["error_msg"],
            "severity": {
                "critical": d["critical"] or 0,
                "high":     d["high"]     or 0,
                "medium":   d["medium"]   or 0,
                "low":      d["low"]      or 0,
                "total":    d["total"]    or 0,
            },
        })

    return {"runs": result, "count": len(result)}


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
# Secret Scanner endpoints
# ---------------------------------------------------------------------------

@app.get("/api/v1/secrets/{run_id}")
async def get_secret_findings(
    run_id:   str,
    severity: Optional[str] = Query(None),
    limit:    int            = Query(200, le=500),
    pool:     asyncpg.Pool   = Depends(get_pool),
):
    """Return secret findings for a run with summary counts."""
    conditions = ["run_id = $1"]
    params: list = [run_id]
    if severity:
        params.append(severity.upper())
        conditions.append(f"severity = ${len(params)}")
    where = "WHERE " + " AND ".join(conditions)
    params.append(limit)

    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"""
            SELECT id, run_id, file_path, line_start, secret_type, severity,
                   description, match_preview, entropy, context_line, created_at
            FROM secret_findings
            {where}
            ORDER BY
                CASE severity
                    WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM'   THEN 3 ELSE 4
                END, file_path, line_start
            LIMIT ${len(params)}
            """,
            *params,
        )
        summary = await conn.fetchrow(
            """
            SELECT
                COUNT(*)                                        AS total,
                COUNT(*) FILTER (WHERE severity = 'CRITICAL')  AS critical,
                COUNT(*) FILTER (WHERE severity = 'HIGH')      AS high,
                COUNT(*) FILTER (WHERE severity = 'MEDIUM')    AS medium,
                COUNT(*) FILTER (WHERE severity = 'LOW')       AS low,
                COUNT(DISTINCT file_path)                       AS files_with_secrets
            FROM secret_findings WHERE run_id = $1
            """,
            run_id,
        )

    return {
        "run_id":   run_id,
        "summary":  dict(summary) if summary else {},
        "findings": [dict(r) for r in rows],
        "count":    len(rows),
    }


# ---------------------------------------------------------------------------
# SCA (Dependency) endpoints
# ---------------------------------------------------------------------------

@app.get("/api/v1/dependencies/{run_id}")
async def get_dependency_findings(
    run_id:    str,
    ecosystem: Optional[str] = Query(None, description="python|npm|maven"),
    severity:  Optional[str] = Query(None),
    limit:     int            = Query(200, le=500),
    pool:      asyncpg.Pool   = Depends(get_pool),
):
    """Return dependency vulnerability findings for a run with summary counts."""
    conditions = ["run_id = $1"]
    params: list = [run_id]
    if ecosystem:
        params.append(ecosystem.lower())
        conditions.append(f"ecosystem = ${len(params)}")
    if severity:
        params.append(severity.upper())
        conditions.append(f"severity = ${len(params)}")
    where = "WHERE " + " AND ".join(conditions)
    params.append(limit)

    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"""
            SELECT id, run_id, package_name, installed_version, fixed_version,
                   vulnerability_id, severity, description, ecosystem, file_path, created_at
            FROM dependency_findings
            {where}
            ORDER BY
                CASE severity
                    WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM'   THEN 3 ELSE 4
                END, package_name
            LIMIT ${len(params)}
            """,
            *params,
        )
        summary = await conn.fetchrow(
            """
            SELECT
                COUNT(*)                                        AS total,
                COUNT(*) FILTER (WHERE severity = 'CRITICAL')  AS critical,
                COUNT(*) FILTER (WHERE severity = 'HIGH')      AS high,
                COUNT(*) FILTER (WHERE severity = 'MEDIUM')    AS medium,
                COUNT(*) FILTER (WHERE severity = 'LOW')       AS low,
                COUNT(*) FILTER (WHERE ecosystem = 'python')   AS python,
                COUNT(*) FILTER (WHERE ecosystem = 'npm')      AS npm,
                COUNT(*) FILTER (WHERE ecosystem = 'maven')    AS maven
            FROM dependency_findings WHERE run_id = $1
            """,
            run_id,
        )

    return {
        "run_id":   run_id,
        "summary":  dict(summary) if summary else {},
        "findings": [dict(r) for r in rows],
        "count":    len(rows),
    }


# ---------------------------------------------------------------------------
# Code Review Agent endpoints
# ---------------------------------------------------------------------------

@app.get("/api/v1/review/{run_id}/progress")
async def get_code_review_progress(run_id: str, pool: asyncpg.Pool = Depends(get_pool)):
    """
    Return live progress for an in-flight code review.
    Polls code_review_status table — updated after every file reviewed.
    """
    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM code_review_status WHERE run_id = $1", run_id
            )
    except Exception:
        return {"run_id": run_id, "status": "not_started", "pct": 0, "files_done": 0, "total_files": 0}

    if not row:
        return {"run_id": run_id, "status": "not_started", "pct": 0, "files_done": 0, "total_files": 0}

    return {
        "run_id":         run_id,
        "status":         row["status"],
        "files_done":     row["files_done"],
        "total_files":    row["total_files"],
        "pct":            row["pct"],
        "current_file":   row["current_file"],
        "findings_count": row["findings_count"],
        "updated_at":     row["updated_at"].isoformat() if row["updated_at"] else None,
    }


@app.post("/api/v1/review/{run_id}", status_code=202)
async def trigger_code_review(
    run_id: str,
    background_tasks: BackgroundTasks,
    pool: asyncpg.Pool = Depends(get_pool),
):
    """
    Trigger Code Review Agent for a completed SAST scan.
    Runs Qwen2.5-Coder on every source file — reviews security, performance,
    code quality, and best practices beyond what Semgrep rules detect.
    Results available via GET /api/v1/review/{run_id}.
    """
    wf_state = get_workflow_state()
    run = await wf_state.get_run(run_id)
    if not run:
        raise HTTPException(404, f"Run not found: {run_id}")

    # Check if a code review is already running (status=running in status table)
    # — do NOT block re-runs when previous completed with 0 findings (LLM may have failed)
    async with pool.acquire() as conn:
        # Check for actual findings
        existing_findings = await conn.fetchval(
            "SELECT COUNT(*) FROM code_review_findings WHERE run_id = $1", run_id
        )
        if existing_findings:
            return {"message": "Code review already completed for this run", "run_id": run_id}

        # Check if currently running
        try:
            current_status = await conn.fetchval(
                "SELECT status FROM code_review_status WHERE run_id = $1", run_id
            )
        except Exception:
            current_status = None

        if current_status == "running":
            return {"message": "Code review is already running", "run_id": run_id, "status": "running"}

        # Immediately write "running" to the status table so polls don't see stale "completed"
        try:
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS code_review_status (
                    run_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL DEFAULT 'running',
                    files_done INT NOT NULL DEFAULT 0,
                    total_files INT NOT NULL DEFAULT 0,
                    pct INT NOT NULL DEFAULT 0,
                    current_file TEXT,
                    findings_count INT NOT NULL DEFAULT 0,
                    updated_at TIMESTAMPTZ DEFAULT NOW()
                )
                """
            )
            await conn.execute(
                """
                INSERT INTO code_review_status
                    (run_id, status, files_done, total_files, pct, current_file, findings_count, updated_at)
                VALUES ($1, 'running', 0, 0, 0, NULL, 0, NOW())
                ON CONFLICT (run_id) DO UPDATE SET
                    status='running', files_done=0, total_files=0, pct=0,
                    current_file=NULL, findings_count=0, updated_at=NOW()
                """,
                run_id,
            )
        except Exception as exc:
            logger.warning("Could not pre-set code_review_status: %s", exc)

    scan_path = run["scan_path"]
    deps = _build_workflow_deps()

    background_tasks.add_task(
        run_code_review_workflow,
        run_id=run_id,
        scan_path=scan_path,
        deps=deps,
    )

    logger.info("Code review triggered | run=%s path=%s", run_id, scan_path)
    return {
        "run_id":  run_id,
        "status":  "accepted",
        "message": f"Code review started. Poll GET /api/v1/review/{run_id} for results.",
    }


@app.get("/api/v1/review/{run_id}")
async def get_code_review_findings(
    run_id:   str,
    category: Optional[str] = Query(None, description="SECURITY|PERFORMANCE|CODE_QUALITY|ERROR_HANDLING|BEST_PRACTICES"),
    severity: Optional[str] = Query(None, description="CRITICAL|HIGH|MEDIUM|LOW|INFO"),
    limit:    int            = Query(200, le=500),
    pool:     asyncpg.Pool   = Depends(get_pool),
):
    """
    Return code review findings for a run, with optional filters.
    Also returns a summary: files reviewed, total findings, score distribution.
    """
    conditions = ["run_id = $1"]
    params: list = [run_id]

    if category:
        params.append(category.upper())
        conditions.append(f"category = ${len(params)}")
    if severity:
        params.append(severity.upper())
        conditions.append(f"severity = ${len(params)}")

    where = "WHERE " + " AND ".join(conditions)
    params.append(limit)

    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"""
            SELECT id, run_id, file_path, language, category, severity,
                   line_start, line_end, title, description, recommendation,
                   confidence, overall_file_score, created_at
            FROM code_review_findings
            {where}
            ORDER BY
                CASE severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH'     THEN 2
                    WHEN 'MEDIUM'   THEN 3
                    WHEN 'LOW'      THEN 4
                    ELSE                 5
                END,
                file_path, line_start NULLS LAST
            LIMIT ${len(params)}
            """,
            *params,
        )

        # Summary counts
        summary = await conn.fetchrow(
            """
            SELECT
                COUNT(DISTINCT file_path)                            AS files_reviewed,
                COUNT(*)                                             AS total_findings,
                COUNT(*) FILTER (WHERE severity = 'CRITICAL')       AS critical,
                COUNT(*) FILTER (WHERE severity = 'HIGH')           AS high,
                COUNT(*) FILTER (WHERE severity = 'MEDIUM')         AS medium,
                COUNT(*) FILTER (WHERE severity = 'LOW')            AS low,
                COUNT(*) FILTER (WHERE category = 'SECURITY')       AS security,
                COUNT(*) FILTER (WHERE category = 'PERFORMANCE')    AS performance,
                COUNT(*) FILTER (WHERE category = 'CODE_QUALITY')   AS code_quality,
                COUNT(*) FILTER (WHERE category = 'ERROR_HANDLING') AS error_handling,
                COUNT(*) FILTER (WHERE category = 'BEST_PRACTICES') AS best_practices
            FROM code_review_findings
            WHERE run_id = $1
            """,
            run_id,
        )

    return {
        "run_id":   run_id,
        "summary":  dict(summary) if summary else {},
        "findings": [dict(r) for r in rows],
        "count":    len(rows),
    }


# ---------------------------------------------------------------------------
# Code Graph API — serves code-review-graph visualization + stats
# ---------------------------------------------------------------------------
# FP Challenger endpoints
# ---------------------------------------------------------------------------

@app.post("/api/v1/fp-challenge/{run_id}", status_code=202)
async def trigger_fp_challenge(
    run_id: str,
    background_tasks: BackgroundTasks,
    pool: asyncpg.Pool = Depends(get_pool),
):
    """
    Trigger the FP Challenger Agent for a completed SAST scan.

    The challenger re-runs Layer 1 + Layer 3 on all REAL/ESCALATED findings
    with the full pgvector context now available.  Results are written to
    fp_decisions and retrievable via GET /api/v1/fp-challenge/{run_id}.
    """
    wf_state = get_workflow_state()
    run = await wf_state.get_run(run_id)
    if not run:
        raise HTTPException(404, f"Run not found: {run_id}")

    async with pool.acquire() as conn:
        # Idempotent: skip if already running
        current_status = None
        try:
            current_status = await conn.fetchval(
                "SELECT status FROM fp_challenge_status WHERE run_id = $1", run_id
            )
        except Exception:
            pass

        if current_status == "running":
            return {"message": "FP challenge already running", "run_id": run_id, "status": "running"}

        # Pre-write status row so progress polls see "running" immediately
        try:
            await conn.execute(
                """
                INSERT INTO fp_challenge_status
                    (run_id, status, findings_total, findings_done, pct, fp_found, current_finding, updated_at)
                VALUES ($1, 'running', 0, 0, 0, 0, NULL, NOW())
                ON CONFLICT (run_id) DO UPDATE SET
                    status='running', findings_total=0, findings_done=0, pct=0,
                    fp_found=0, current_finding=NULL, updated_at=NOW()
                """,
                run_id,
            )
        except Exception as exc:
            logger.warning("Could not pre-set fp_challenge_status: %s", exc)

    deps = _build_workflow_deps()
    background_tasks.add_task(run_fp_challenger_workflow, run_id=run_id, deps=deps)

    logger.info("FP challenge triggered | run=%s", run_id)
    return {
        "run_id":  run_id,
        "status":  "accepted",
        "message": f"FP challenge started. Poll GET /api/v1/fp-challenge/{run_id}/progress for progress.",
    }


@app.get("/api/v1/fp-challenge/{run_id}/progress")
async def get_fp_challenge_progress(
    run_id: str,
    pool: asyncpg.Pool = Depends(get_pool),
):
    """Live progress for the FP Challenger (findings_done, pct, fp_found)."""
    async with pool.acquire() as conn:
        try:
            row = await conn.fetchrow(
                "SELECT * FROM fp_challenge_status WHERE run_id = $1", run_id
            )
        except Exception:
            row = None

    if not row:
        return {"run_id": run_id, "status": "not_started", "pct": 0, "findings_done": 0,
                "findings_total": 0, "fp_found": 0, "current_finding": None}

    return {
        "run_id":          run_id,
        "status":          row["status"],
        "findings_done":   row["findings_done"],
        "findings_total":  row["findings_total"],
        "pct":             row["pct"],
        "fp_found":        row["fp_found"],
        "current_finding": row["current_finding"],
        "updated_at":      row["updated_at"].isoformat() if row["updated_at"] else None,
    }


@app.get("/api/v1/fp-challenge/{run_id}")
async def get_fp_challenge_results(
    run_id: str,
    verdict: Optional[str] = Query(None, description="REAL|FP|ESCALATED|DEADLOCK"),
    pool: asyncpg.Pool = Depends(get_pool),
):
    """
    Return FP decisions written by the challenger for this run.

    Optionally filter by verdict (REAL, FP, ESCALATED, DEADLOCK).
    Includes the finding details joined from findings_reports.
    """
    async with pool.acquire() as conn:
        # Progress summary
        try:
            status_row = await conn.fetchrow(
                "SELECT * FROM fp_challenge_status WHERE run_id = $1", run_id
            )
        except Exception:
            status_row = None

        # Decisions — join with findings for context
        where = "fpd.run_id = $1"
        params: list = [run_id]
        if verdict:
            where += " AND fpd.verdict = $2"
            params.append(verdict.upper())

        rows = await conn.fetch(
            f"""
            SELECT
                fpd.id           AS decision_id,
                fpd.finding_id,
                fpd.verdict,
                fpd.source,
                fpd.confidence,
                fpd.fp_category,
                fpd.reasoning,
                fpd.label_status,
                fpd.created_at,
                fr.rule_id,
                fr.cwe_id,
                fr.severity,
                fr.file_path,
                fr.line_start,
                fr.message
            FROM fp_decisions fpd
            JOIN findings_reports fr ON fr.id = fpd.finding_id
            WHERE {where}
            ORDER BY fpd.created_at DESC
            """,
            *params,
        )

    decisions = [
        {
            "decision_id":  str(r["decision_id"]),
            "finding_id":   str(r["finding_id"]),
            "verdict":      r["verdict"],
            "source":       r["source"],
            "confidence":   r["confidence"],
            "fp_category":  r["fp_category"],
            "reasoning":    r["reasoning"],
            "label_status": r["label_status"],
            "created_at":   r["created_at"].isoformat() if r["created_at"] else None,
            "rule_id":      r["rule_id"],
            "cwe_id":       r["cwe_id"],
            "severity":     r["severity"],
            "file_path":    r["file_path"],
            "line_start":   r["line_start"],
            "message":      r["message"],
        }
        for r in rows
    ]

    fp_count   = sum(1 for d in decisions if d["verdict"] == "FP")
    real_count = sum(1 for d in decisions if d["verdict"] == "REAL")

    return {
        "run_id":    run_id,
        "count":     len(decisions),
        "fp_count":  fp_count,
        "real_count": real_count,
        "status":    status_row["status"] if status_row else "not_started",
        "fp_found":  status_row["fp_found"] if status_row else 0,
        "decisions": decisions,
    }


# ---------------------------------------------------------------------------

_GRAPH_DB   = Path(__file__).parent.parent / ".code-review-graph" / "graph.db"
_GRAPH_HTML = Path(__file__).parent.parent / ".code-review-graph" / "graph.html"


@app.get("/api/v1/graph/status")
async def get_graph_status(scan_path: Optional[str] = None):
    """Return code-review-graph stats for a given scan_path (defaults to project root)."""
    root = Path(scan_path) if scan_path else _GRAPH_DB.parent.parent
    db   = root / ".code-review-graph" / "graph.db"
    if not db.exists():
        return {"available": False}
    try:
        import sqlite3
        conn = sqlite3.connect(str(db), timeout=5)
        meta = dict(conn.execute("SELECT key, value FROM metadata").fetchall())
        nodes = conn.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
        edges = conn.execute("SELECT COUNT(*) FROM edges").fetchone()[0]
        files = conn.execute("SELECT COUNT(DISTINCT file_path) FROM nodes WHERE file_path IS NOT NULL").fetchone()[0]
        langs_rows = conn.execute(
            "SELECT language, COUNT(*) FROM nodes WHERE language IS NOT NULL GROUP BY language ORDER BY COUNT(*) DESC"
        ).fetchall()
        conn.close()
        languages = ", ".join(r[0] for r in langs_rows if r[0])
        sha = meta.get("git_head_sha", "")
        return {
            "available":    True,
            "nodes":        nodes,
            "edges":        edges,
            "files":        files,
            "languages":    languages,
            "last_updated": meta.get("last_updated", ""),
            "branch":       meta.get("git_branch", ""),
            "commit":       sha[:8] if sha else "",
        }
    except Exception as exc:
        logger.warning("graph/status error: %s", exc)
        return {"available": False, "error": str(exc)}


# In-memory build status store: keyed by str(root)
# Each entry: {"status": "building"|"done"|"failed", "error": str|None, "started_at": float}
_graph_build_status: dict[str, dict] = {}


async def _run_graph_build(root: Path) -> None:
    """Background task: builds the graph and updates _graph_build_status."""
    import asyncio, subprocess as _sp, time
    key = str(root)
    try:
        proc = await asyncio.create_subprocess_exec(
            "python3.11", "-m", "code_review_graph", "build", "--repo", str(root),
            stdout=_sp.PIPE, stderr=_sp.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=180)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            _graph_build_status[key] = {
                "status": "failed",
                "error": "Build timed out after 3 minutes. Try a smaller project.",
                "started_at": _graph_build_status[key]["started_at"],
            }
            logger.warning("graph/build timed out for %s", root)
            return

        if proc.returncode != 0:
            err_raw = stderr.decode(errors="replace") if stderr else ""
            # surface the last meaningful line (skip blank lines)
            lines = [l.strip() for l in err_raw.splitlines() if l.strip()]
            err_msg = lines[-1] if lines else f"exit code {proc.returncode}"
            _graph_build_status[key] = {
                "status": "failed",
                "error": err_msg,
                "started_at": _graph_build_status[key]["started_at"],
            }
            logger.warning("graph/build failed rc=%d: %s", proc.returncode, err_msg)
            return

        db = root / ".code-review-graph" / "graph.db"
        if not db.exists():
            _graph_build_status[key] = {
                "status": "failed",
                "error": "Build succeeded but graph.db was not created — check that code_review_graph is installed correctly.",
                "started_at": _graph_build_status[key]["started_at"],
            }
            return

        _graph_build_status[key] = {
            "status": "done",
            "error": None,
            "started_at": _graph_build_status[key]["started_at"],
        }
        logger.warning("graph/build done for %s", root)

    except Exception as exc:
        _graph_build_status[key] = {
            "status": "failed",
            "error": str(exc),
            "started_at": _graph_build_status.get(key, {}).get("started_at", 0),
        }
        logger.warning("graph/build exception for %s: %s", root, exc)


@app.post("/api/v1/graph/build")
async def build_graph(background_tasks: BackgroundTasks, scan_path: Optional[str] = None):
    """
    Start an async graph build for *scan_path* and return immediately.
    Poll GET /api/v1/graph/build/status?scan_path=… to track progress.
    """
    import time
    root = Path(scan_path) if scan_path else _GRAPH_DB.parent.parent
    if not root.exists():
        raise HTTPException(404, f"Path does not exist: {root}")

    key = str(root)
    # Reject a duplicate in-flight build
    if _graph_build_status.get(key, {}).get("status") == "building":
        return {"status": "building", "message": "Build already in progress"}

    _graph_build_status[key] = {"status": "building", "error": None, "started_at": time.time()}
    logger.warning("graph/build: queued background build for %s", root)
    background_tasks.add_task(_run_graph_build, root)
    return {"status": "building", "message": f"Build started for {root.name}"}


@app.get("/api/v1/graph/build/status")
async def get_build_status(scan_path: Optional[str] = None):
    """
    Returns the current build status for a project path.
    Possible status values: "idle", "building", "done", "failed"
    """
    import time
    root = Path(scan_path) if scan_path else _GRAPH_DB.parent.parent
    key  = str(root)
    entry = _graph_build_status.get(key)
    if not entry:
        # Check if graph already exists (built in a previous server session)
        db = root / ".code-review-graph" / "graph.db"
        return {"status": "idle", "graph_exists": db.exists()}
    elapsed = int(time.time() - entry.get("started_at", 0))
    return {
        "status":      entry["status"],
        "error":       entry.get("error"),
        "elapsed_sec": elapsed,
        "graph_exists": (root / ".code-review-graph" / "graph.db").exists(),
    }


@app.get("/api/v1/graph/visualization", response_class=HTMLResponse)
async def get_graph_visualization(
    scan_path: Optional[str] = None,
    mode: str = "file",
):
    """
    Regenerate and serve the interactive graph HTML for a given scan_path.
    mode: file (default) | full | community | auto
    Opens full-screen — not meant for iframe embedding (graph uses CDN JS).
    """
    import asyncio, subprocess as _sp
    if mode not in ("file", "full", "community", "auto"):
        mode = "file"
    root = Path(scan_path) if scan_path else _GRAPH_DB.parent.parent
    db   = root / ".code-review-graph" / "graph.db"
    html = root / ".code-review-graph" / "graph.html"

    if not db.exists():
        return HTMLResponse(
            "<html><body style='background:#0f172a;color:#64748b;font-family:monospace;"
            "display:flex;align-items:center;justify-content:center;height:100vh;flex-direction:column;gap:12px'>"
            "<svg xmlns='http://www.w3.org/2000/svg' width='40' height='40' viewBox='0 0 24 24' fill='none' "
            "stroke='currentColor' stroke-width='1.5'><circle cx='12' cy='12' r='10'/>"
            "<line x1='12' y1='8' x2='12' y2='12'/><line x1='12' y1='16' x2='12.01' y2='16'/></svg>"
            "<p>Graph not built for this project yet.</p>"
            "<p style='font-size:12px'>Run a scan to build it automatically.</p></body></html>"
        )
    try:
        proc = await asyncio.create_subprocess_exec(
            "python3.11", "-m", "code_review_graph", "visualize",
            "--format", "html", "--mode", mode,
            "--repo", str(root),
            stdout=_sp.PIPE, stderr=_sp.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=60)
    except Exception as exc:
        logger.warning("graph/visualize error: %s", exc)

    if html.exists():
        return HTMLResponse(html.read_text())
    return HTMLResponse("<html><body style='background:#0f172a;color:#ef4444'>Visualization failed</body></html>")


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

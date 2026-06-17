"""
workflows/code_review_workflow.py
===================================
LangGraph workflow for the Code Review Agent — Phase 1.

Reviews every source file in a project using Qwen2.5-Coder:14b, finding issues
that Semgrep pattern rules cannot detect:
  - Subtle security flaws (logic, auth gaps, business logic)
  - Performance anti-patterns (N+1, resource leaks, O(n²))
  - Code quality (complexity, dead code, missing null checks)
  - Best practices (error handling, idiomatic patterns)

Workflow nodes:
  start → enumerate_files → review_files (per-file loop) → complete

Results stored in code_review_findings table, linked to the run_id.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import TypedDict, Optional

import asyncpg
import httpx
from langgraph.graph import StateGraph, END

from core.config import settings
from core.output_contracts.code_review_report import (
    CodeReviewFileResult, CodeReviewFinding, ReviewCategory, ReviewSeverity,
)
from core.state.workflow_state import WorkflowState

logger = logging.getLogger(__name__)

# File extensions the agent reviews
_REVIEWABLE_EXTS = {
    ".java", ".py", ".js", ".ts", ".jsx", ".tsx",
    ".go", ".rb", ".php", ".kt", ".scala", ".cs",
}

# Priority path keywords — files whose path contains these are reviewed first
_PRIORITY_KEYWORDS = [
    "security", "auth", "payment", "controller", "service",
    "repository", "util", "helper", "config", "filter", "interceptor",
]

_MAX_FILE_BYTES = 51_200    # 50 KB — larger files truncated
_MAX_LINES     = 400        # max lines sent to LLM


# ---------------------------------------------------------------------------
# Workflow State
# ---------------------------------------------------------------------------

class CodeReviewState(TypedDict):
    run_id:       str
    scan_path:    str

    # Set by enumerate_files
    files_to_review:   list[str]   # ordered list of absolute file paths
    total_files:       int

    # Set/updated by review_files
    files_reviewed:    int
    findings_count:    int
    sast_findings:     dict        # file_path → list of SAST finding dicts (context)

    # Error tracking
    error: Optional[str]


# ---------------------------------------------------------------------------
# Helper: load SAST findings from DB for context
# ---------------------------------------------------------------------------

async def _load_sast_findings(pool: asyncpg.Pool, run_id: str) -> dict[str, list]:
    """Return {relative_file_path: [finding_dicts]} for context in LLM prompts."""
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT file_path, rule_id, severity, message, line_start
            FROM findings_reports
            WHERE run_id = $1
            ORDER BY file_path, line_start
            """,
            run_id,
        )
    result: dict[str, list] = {}
    for r in rows:
        fp = r["file_path"]
        result.setdefault(fp, []).append({
            "rule_id":    r["rule_id"],
            "severity":   r["severity"],
            "message":    r["message"],
            "line_start": r["line_start"],
        })
    return result


# ---------------------------------------------------------------------------
# Helper: call Ollama LLM
# ---------------------------------------------------------------------------

async def _call_llm(system_prompt: str, user_prompt: str, timeout: int = 180) -> str:
    """Call Ollama chat API and return the response string."""
    payload = {
        "model": settings.ollama.tier1_model,
        "messages": [
            {"role": "system",    "content": system_prompt},
            {"role": "user",      "content": user_prompt},
        ],
        "stream":  False,
        "options": {"temperature": 0.1, "num_predict": 2048},
    }
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(
            f"{settings.ollama.base_url}/api/chat",
            json=payload,
        )
        resp.raise_for_status()
        data = resp.json()
        return data["message"]["content"]


# ---------------------------------------------------------------------------
# Helper: review a single file
# ---------------------------------------------------------------------------

async def _review_file(
    abs_path: str,
    scan_path: str,
    sast_findings: dict,
    system_prompt: str,
) -> Optional[CodeReviewFileResult]:
    """
    Read a file, build the prompt, call LLM, parse response.
    Returns None if the file should be skipped (binary, too large, unreadable).
    """
    path = Path(abs_path)
    rel_path = str(path.relative_to(scan_path)) if abs_path.startswith(scan_path) else path.name

    # Read file
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, IOError):
        return None

    # Skip if empty
    if not content.strip():
        return None

    # Truncate if needed
    lines = content.splitlines()
    truncated = False
    if len(lines) > _MAX_LINES:
        lines = lines[:_MAX_LINES]
        truncated = True
    content_for_llm = "\n".join(lines)
    if truncated:
        content_for_llm += f"\n\n... [file truncated at {_MAX_LINES} lines]"

    # Detect language from extension
    lang_map = {
        ".java": "Java", ".py": "Python", ".js": "JavaScript",
        ".ts": "TypeScript", ".jsx": "JavaScript (React)", ".tsx": "TypeScript (React)",
        ".go": "Go", ".rb": "Ruby", ".php": "PHP",
        ".kt": "Kotlin", ".scala": "Scala", ".cs": "C#",
    }
    language = lang_map.get(path.suffix.lower(), "Unknown")

    # Build SAST context for this file
    sast_for_file = sast_findings.get(rel_path, [])
    sast_context = ""
    if sast_for_file:
        sast_context = "\n\nSemgrep already found these issues in this file (DO NOT repeat them):\n"
        for f in sast_for_file:
            sast_context += f"  - Line {f['line_start']}: [{f['severity']}] {f['rule_id']} — {f['message'][:120]}\n"

    user_prompt = f"""Review this {language} file: {rel_path}{sast_context}

```{path.suffix.lstrip('.')}
{content_for_llm}
```"""

    start = time.time()
    try:
        raw = await _call_llm(system_prompt, user_prompt)
    except Exception as exc:
        logger.warning("LLM call failed for %s: %s", rel_path, exc)
        return None
    elapsed_ms = int((time.time() - start) * 1000)

    # Parse JSON from LLM response
    try:
        # Strip markdown code fences if present
        text = raw.strip()
        if text.startswith("```"):
            lines_r = text.splitlines()
            text = "\n".join(lines_r[1:-1] if lines_r[-1].strip() == "```" else lines_r[1:])
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError) as exc:
        logger.warning("LLM JSON parse error for %s: %s | raw=%s", rel_path, exc, raw[:200])
        return None

    # Validate through Pydantic
    try:
        findings = [CodeReviewFinding(**f) for f in data.get("findings", [])]
        return CodeReviewFileResult(
            file_path=rel_path,
            language=language,
            findings=findings,
            overall_score=int(data.get("overall_score", 75)),
            summary=str(data.get("summary", "")),
            review_ms=elapsed_ms,
        )
    except Exception as exc:
        logger.warning("Pydantic validation failed for %s: %s", rel_path, exc)
        return None


# ---------------------------------------------------------------------------
# Workflow Nodes
# ---------------------------------------------------------------------------

async def node_start(state: CodeReviewState, deps: dict) -> CodeReviewState:
    """Mark workflow as running and load SAST context."""
    run_id = state["run_id"]
    pool: asyncpg.Pool = deps["pool"]

    # Ensure code_review_findings table exists
    async with pool.acquire() as conn:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS code_review_findings (
                id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                run_id      TEXT NOT NULL,
                file_path   TEXT NOT NULL,
                language    TEXT,
                category    TEXT NOT NULL,
                severity    TEXT NOT NULL,
                line_start  INT,
                line_end    INT,
                title       TEXT NOT NULL,
                description TEXT,
                recommendation TEXT,
                confidence  REAL DEFAULT 0.5,
                overall_file_score INT,
                created_at  TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_cr_findings_run ON code_review_findings(run_id)"
        )

    sast_findings = await _load_sast_findings(pool, run_id)
    logger.info("Code review started | run=%s sast_context_files=%d", run_id, len(sast_findings))
    return {**state, "sast_findings": sast_findings}


async def node_enumerate_files(state: CodeReviewState, deps: dict) -> CodeReviewState:
    """
    Walk the project and build a priority-ordered list of files to review.

    Priority order:
      1. Files that already have SAST findings (review for deeper issues)
      2. Files in security-sensitive paths (controllers, services, auth, payment)
      3. All remaining reviewable files, largest first
    """
    scan_path = state["scan_path"]
    sast_findings = state["sast_findings"]
    root = Path(scan_path)

    # Collect all reviewable files
    all_files: list[Path] = [
        p for p in root.rglob("*")
        if p.is_file()
        and p.suffix.lower() in _REVIEWABLE_EXTS
        and not any(part in {".git", "node_modules", ".venv", "venv", "__pycache__", "target", "build", "dist"}
                    for part in p.parts)
        and p.stat().st_size <= _MAX_FILE_BYTES * 2  # skip very large files
    ]

    # Build sets for prioritisation
    sast_paths = set(sast_findings.keys())

    def priority(p: Path) -> int:
        rel = str(p.relative_to(root))
        if rel in sast_paths:
            return 0  # highest priority
        path_lower = str(p).lower()
        for kw in _PRIORITY_KEYWORDS:
            if kw in path_lower:
                return 1
        return 2

    all_files.sort(key=lambda p: (priority(p), -p.stat().st_size))

    file_list = [str(p) for p in all_files]
    logger.info("Code review: %d files queued | run=%s", len(file_list), state["run_id"])
    return {**state, "files_to_review": file_list, "total_files": len(file_list)}


async def node_review_files(state: CodeReviewState, deps: dict) -> CodeReviewState:
    """
    Review each file sequentially (Ollama handles one request at a time).
    Stores findings to DB immediately after each file — results visible in real time.
    """
    pool: asyncpg.Pool = deps["pool"]
    run_id = state["run_id"]
    scan_path = state["scan_path"]
    sast_findings = state["sast_findings"]
    files = state["files_to_review"]

    # Load system prompt
    system_prompt_path = Path(settings.prompts_dir) / "code_review_agent" / "v1.0" / "system.md"
    if system_prompt_path.exists():
        system_prompt = system_prompt_path.read_text()
    else:
        system_prompt = (
            "You are a senior security engineer. Review the file and return a JSON object "
            "with keys: findings (array), overall_score (0-100), summary (string). "
            "Each finding: category, severity, line_start, line_end, title, description, "
            "recommendation, confidence."
        )

    reviewed = 0
    total_findings = 0

    for abs_path in files:
        result = await _review_file(abs_path, scan_path, sast_findings, system_prompt)
        if result is None:
            continue

        reviewed += 1

        # Store findings to DB
        if result.findings:
            async with pool.acquire() as conn:
                for finding in result.findings:
                    if finding.confidence < 0.5:
                        continue
                    await conn.execute(
                        """
                        INSERT INTO code_review_findings
                            (run_id, file_path, language, category, severity,
                             line_start, line_end, title, description, recommendation,
                             confidence, overall_file_score)
                        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
                        """,
                        run_id, result.file_path, result.language,
                        finding.category.value, finding.severity.value,
                        finding.line_start, finding.line_end,
                        finding.title, finding.description, finding.recommendation,
                        finding.confidence, result.overall_score,
                    )
            total_findings += len(result.findings)
            logger.info(
                "Reviewed %s | score=%d findings=%d",
                result.file_path, result.overall_score, len(result.findings),
            )
        else:
            logger.debug("Reviewed %s | score=%d clean", result.file_path, result.overall_score)

    logger.info(
        "Code review complete | run=%s files=%d findings=%d",
        run_id, reviewed, total_findings,
    )
    return {**state, "files_reviewed": reviewed, "findings_count": total_findings}


async def node_complete(state: CodeReviewState, deps: dict) -> CodeReviewState:
    """Update workflow_runs metadata with code review stats."""
    pool: asyncpg.Pool = deps["pool"]
    run_id = state["run_id"]

    async with pool.acquire() as conn:
        # Read existing metadata and merge code review stats
        existing = await conn.fetchval(
            "SELECT metadata FROM workflow_runs WHERE run_id = $1", run_id
        )
        meta: dict = {}
        if existing:
            try:
                meta = json.loads(existing) if isinstance(existing, str) else (existing or {})
            except Exception:
                meta = {}

        meta["code_review"] = {
            "files_reviewed":  state.get("files_reviewed", 0),
            "total_files":     state.get("total_files", 0),
            "findings_count":  state.get("findings_count", 0),
            "completed_at":    datetime.now(timezone.utc).isoformat(),
        }

        await conn.execute(
            "UPDATE workflow_runs SET metadata = $1::jsonb WHERE run_id = $2",
            json.dumps(meta),
            run_id,
        )

    logger.info("Code review workflow complete | run=%s", run_id)
    return state


# ---------------------------------------------------------------------------
# Build and Run
# ---------------------------------------------------------------------------

def build_code_review_graph(deps: dict):
    async def start(state):    return await node_start(state, deps)
    async def enumerate(state): return await node_enumerate_files(state, deps)
    async def review(state):   return await node_review_files(state, deps)
    async def complete(state): return await node_complete(state, deps)

    graph = StateGraph(CodeReviewState)
    graph.add_node("start",    start)
    graph.add_node("enumerate", enumerate)
    graph.add_node("review",   review)
    graph.add_node("complete", complete)

    graph.set_entry_point("start")
    graph.add_edge("start",    "enumerate")
    graph.add_edge("enumerate", "review")
    graph.add_edge("review",   "complete")
    graph.add_edge("complete", END)

    return graph.compile()


async def run_code_review_workflow(run_id: str, scan_path: str, deps: dict) -> dict:
    """
    Entry point — called from FastAPI background task after SAST completes.

    Args:
        run_id:    The SAST scan run_id to attach code review results to.
        scan_path: Absolute path to the project root.
        deps:      Injected dependencies (pool, etc.).
    """
    app = build_code_review_graph(deps)

    initial_state: CodeReviewState = {
        "run_id":          run_id,
        "scan_path":       scan_path,
        "files_to_review": [],
        "total_files":     0,
        "files_reviewed":  0,
        "findings_count":  0,
        "sast_findings":   {},
        "error":           None,
    }

    try:
        return await app.ainvoke(initial_state)
    except Exception as exc:
        logger.error("Code review workflow crashed | run=%s error=%s", run_id, exc, exc_info=True)
        raise

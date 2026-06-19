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
import sqlite3
import subprocess
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

_MAX_FILE_BYTES = 15_360    # 15 KB — skip files larger than this

# Adaptive limits based on project size — set in node_enumerate_files
# Small  (<= 20 files):  review all,  80 lines each  → ~10 min
# Medium (21-60 files):  review 25,   60 lines each  → ~18 min
# Large  (61-150 files): review 20,   50 lines each  → ~15 min
# XLarge (> 150 files):  review 15,   40 lines each  → ~11 min
_DEFAULT_MAX_FILES = 50   # fallback if not set by enumerate_files
_DEFAULT_MAX_LINES = 80   # fallback if not set by enumerate_files

# Skip paths that rarely contain exploitable logic
_SKIP_PATH_KEYWORDS = {
    "test", "spec", "mock", "fixture", "generated", "gen-src",
    "__generated__", "migration", "seed", "proto", "thrift",
}


# ---------------------------------------------------------------------------
# Workflow State
# ---------------------------------------------------------------------------

class CodeReviewState(TypedDict):
    run_id:       str
    scan_path:    str

    # Set by enumerate_files
    files_to_review:   list[str]   # ordered list of absolute file paths
    total_files:       int
    max_lines:         int         # lines-per-file limit (adaptive to project size)

    # Set/updated by review_files
    files_reviewed:    int
    findings_count:    int
    sast_findings:     dict        # file_path → list of SAST finding dicts (context)
    graph_contexts:    dict        # file_path → GraphContext (from code-review-graph)

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

async def _call_llm(system_prompt: str, user_prompt: str, timeout: int | None = None) -> str:
    """Call Ollama chat API."""
    if timeout is None:
        timeout = settings.ollama.request_timeout
    payload = {
        "model": settings.ollama.tier2_model,  # llama3.2:3b — fast; switch to tier1_model for production
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_prompt},
        ],
        "stream":  False,
        "options": {
            "temperature": 0.1,
            "num_predict": 1024,  # enough for full JSON with multiple findings
            "num_ctx":     3072,  # input (~1200 tokens) + output (1024) = ~2224; 3072 gives headroom
            "num_gpu":     99,    # force all layers onto Metal GPU
            "num_thread":  8,     # CPU threads for prompt processing
        },
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
    graph_ctx: Optional[GraphContext] = None,
    max_lines: int = _DEFAULT_MAX_LINES,
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

    # Truncate if needed (adaptive max_lines from caller)
    lines = content.splitlines()
    truncated = False
    if len(lines) > max_lines:
        lines = lines[:max_lines]
        truncated = True
    content_for_llm = "\n".join(lines)
    if truncated:
        content_for_llm += f"\n\n... [file truncated at {max_lines} lines]"

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

    # Graph context section — injected between file header and code
    graph_section = ""
    if graph_ctx is not None:
        graph_section = "\n\n" + graph_ctx.to_prompt_section()

    user_prompt = f"""Review this {language} file: {rel_path}{graph_section}{sast_context}

```{path.suffix.lstrip('.')}
{content_for_llm}
```"""

    start = time.time()
    logger.warning("LLM START | file=%s lang=%s lines=%d", rel_path, language, len(lines))
    try:
        raw = await _call_llm(system_prompt, user_prompt)
    except Exception as exc:
        logger.warning("LLM FAIL | file=%s error=%s: %s", rel_path, type(exc).__name__, exc)
        return None
    elapsed_ms = int((time.time() - start) * 1000)
    logger.warning("LLM DONE | file=%s elapsed=%dms raw_len=%d", rel_path, elapsed_ms, len(raw))

    # Parse JSON from LLM response — with truncation repair
    def _try_parse(text: str) -> Optional[dict]:
        """Try to parse JSON; if truncated, rescue complete findings objects."""
        try:
            return json.loads(text)
        except (json.JSONDecodeError, ValueError):
            pass

        # Try to extract complete finding objects from a truncated array
        # Strategy: find all complete {...} objects inside "findings": [...]
        import re
        findings_match = re.search(r'"findings"\s*:\s*\[(.+)', text, re.DOTALL)
        if not findings_match:
            return None
        array_text = findings_match.group(1)
        # Collect complete JSON objects (balanced braces)
        rescued: list[dict] = []
        depth = 0
        start = None
        for i, ch in enumerate(array_text):
            if ch == "{":
                if depth == 0:
                    start = i
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0 and start is not None:
                    obj_str = array_text[start:i + 1]
                    try:
                        obj = json.loads(obj_str)
                        rescued.append(obj)
                    except Exception:
                        pass
                    start = None
        if rescued:
            logger.warning("LLM JSON TRUNCATED | file=%s rescued=%d findings", rel_path, len(rescued))
            return {"findings": rescued, "overall_score": 60, "summary": "Response was truncated; partial findings rescued."}
        return None

    try:
        # Strip markdown code fences if present
        text = raw.strip()
        if text.startswith("```"):
            lines_r = text.splitlines()
            inner = lines_r[1:-1] if lines_r and lines_r[-1].strip() == "```" else lines_r[1:]
            text = "\n".join(inner)
        data = _try_parse(text)
        if data is None:
            logger.warning("LLM JSON PARSE ERROR | file=%s | raw_first_300=%r", rel_path, raw[:300])
            return None
    except Exception as exc:
        logger.warning("LLM JSON PARSE ERROR | file=%s err=%s | raw_first_300=%r", rel_path, exc, raw[:300])
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

async def _upsert_progress(pool: asyncpg.Pool, run_id: str, files_done: int, total: int, current_file: str, findings_so_far: int, status: str = "running") -> None:
    """Write live progress into code_review_status so the API can stream it."""
    pct = round((files_done / total) * 100) if total else 0
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO code_review_status
                (run_id, status, files_done, total_files, pct, current_file, findings_count, updated_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())
            ON CONFLICT (run_id) DO UPDATE SET
                status=EXCLUDED.status,
                files_done=EXCLUDED.files_done,
                total_files=EXCLUDED.total_files,
                pct=EXCLUDED.pct,
                current_file=EXCLUDED.current_file,
                findings_count=EXCLUDED.findings_count,
                updated_at=NOW()
            """,
            run_id, status, files_done, total, pct, current_file, findings_so_far,
        )


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
        # Progress tracking table
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

    sast_findings = await _load_sast_findings(pool, run_id)
    logger.warning("CODE REVIEW STARTED | run=%s sast_context_files=%d model=%s", run_id, len(sast_findings), settings.ollama.tier2_model)
    return {**state, "sast_findings": sast_findings}


class GraphContext:
    """Per-file context extracted from the code-review-graph knowledge graph."""
    __slots__ = (
        "hub_score", "community_id", "community_name", "community_purpose",
        "key_symbols", "caller_files", "flows", "risk_score",
        "caller_count", "test_coverage", "security_relevant",
    )

    def __init__(self):
        self.hub_score:          float      = 0.0
        self.community_id:       int | None = None
        self.community_name:     str        = ""
        self.community_purpose:  str        = ""
        self.key_symbols:        list[str]  = []
        self.caller_files:       list[str]  = []   # other files that call into this file
        self.flows:              list[str]  = []   # execution flow names passing through this file
        self.risk_score:         float      = 0.0
        self.caller_count:       int        = 0
        self.test_coverage:      str        = "unknown"
        self.security_relevant:  bool       = False

    def to_prompt_section(self) -> str:
        """
        Returns a concise 3-6 line section for injection into the LLM prompt.
        Kept short to fit within llama3.2:3b's 2048-token context alongside the code.
        """
        lines = ["## Graph Context (from code knowledge graph)"]

        if self.community_name:
            syms = ", ".join(self.key_symbols[:4]) if self.key_symbols else "—"
            lines.append(f"- Module: {self.community_name} (purpose: {self.community_purpose or 'unknown'} | key symbols: {syms})")

        risk_label = "LOW"
        if self.risk_score >= 0.7:   risk_label = "CRITICAL"
        elif self.risk_score >= 0.5: risk_label = "HIGH"
        elif self.risk_score >= 0.3: risk_label = "MEDIUM"
        lines.append(
            f"- Risk: {risk_label} (score={self.risk_score:.2f}, callers={self.caller_count}, "
            f"tests={self.test_coverage}, security_relevant={'YES' if self.security_relevant else 'no'})"
        )

        if self.caller_files:
            callers_short = ", ".join(Path(f).name for f in self.caller_files[:4])
            lines.append(f"- Called by: {callers_short}")
        else:
            lines.append("- Called by: (no callers — entry point or leaf file)")

        if self.flows:
            lines.append(f"- Execution flows through this file: {', '.join(self.flows[:3])}")

        lines.append(
            "Focus your review on issues appropriate to this module's risk level and callers above."
        )
        return "\n".join(lines)


def _load_graph_data(root: Path) -> tuple[dict[str, float], dict[str, int], dict[str, GraphContext]]:
    """
    Load hub scores, community IDs, and rich per-file GraphContext from the
    code-review-graph SQLite DB.

    Returns:
      hub_scores     — file_path → combined hub score (for ordering)
      community_ids  — file_path → community_id (for grouping)
      graph_contexts — file_path → GraphContext (for LLM prompt enrichment)

    All three are empty/None if the graph DB is not built yet.
    """
    db_path = root / ".code-review-graph" / "graph.db"
    if not db_path.exists():
        # Trigger a background build so the next scan benefits
        try:
            subprocess.Popen(
                ["python3.11", "-m", "code_review_graph", "build", "--repo", str(root)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            logger.warning("code-review-graph: started background build for %s", root)
        except Exception as exc:
            logger.warning("code-review-graph: could not start build: %s", exc)
        return {}, {}, {}

    hub_scores:     dict[str, float]        = {}
    community_ids:  dict[str, int]          = {}
    graph_contexts: dict[str, GraphContext] = {}

    try:
        conn = sqlite3.connect(str(db_path), timeout=5)

        # ── 1. Risk index → hub score + per-file risk data ────────────────────
        risk_rows = conn.execute(
            "SELECT qualified_name, risk_score, caller_count, test_coverage, security_relevant "
            "FROM risk_index"
        ).fetchall()
        file_risk: dict[str, dict] = {}  # file_path → best (highest risk) row
        for qname, score, callers, test_cov, sec_rel in risk_rows:
            fp = qname.split("::")[0] if "::" in qname else qname
            combined = (score or 0.0) + (callers or 0) * 0.1
            if hub_scores.get(fp, -1.0) < combined:
                hub_scores[fp] = combined
            if fp not in file_risk or (score or 0) > file_risk[fp]["risk_score"]:
                file_risk[fp] = {
                    "risk_score":        score or 0.0,
                    "caller_count":      callers or 0,
                    "test_coverage":     test_cov or "unknown",
                    "security_relevant": bool(sec_rel),
                }

        # ── 2. Community IDs from nodes table ─────────────────────────────────
        node_rows = conn.execute(
            """
            SELECT file_path, community_id, COUNT(*) AS cnt
            FROM nodes
            WHERE file_path IS NOT NULL AND community_id IS NOT NULL
            GROUP BY file_path, community_id
            ORDER BY file_path, cnt DESC
            """
        ).fetchall()
        seen: set[str] = set()
        for fp, comm_id, _ in node_rows:
            if fp not in seen:
                community_ids[fp] = int(comm_id)
                seen.add(fp)

        # ── 3. Community summaries → name, purpose, key symbols ───────────────
        comm_info: dict[int, dict] = {}
        for comm_id, name, purpose, key_syms, risk in conn.execute(
            "SELECT community_id, name, purpose, key_symbols, risk FROM community_summaries"
        ).fetchall():
            try:
                syms = json.loads(key_syms) if key_syms else []
            except Exception:
                syms = []
            comm_info[int(comm_id)] = {"name": name or "", "purpose": purpose or "", "key_symbols": syms, "risk": risk}

        # ── 4. Callers: edges where target is a node in this file ─────────────
        # edge.source_qualified → the file that calls INTO our file
        caller_rows = conn.execute(
            """
            SELECT DISTINCT
                e.file_path           AS caller_file,
                n.file_path           AS callee_file
            FROM edges e
            JOIN nodes n ON n.qualified_name = e.target_qualified
            WHERE e.kind IN ('CALLS', 'CALLS_METHOD', 'INSTANTIATES')
              AND e.file_path IS NOT NULL
              AND n.file_path IS NOT NULL
              AND e.file_path != n.file_path
            """
        ).fetchall()
        file_callers: dict[str, set[str]] = {}
        for caller_fp, callee_fp in caller_rows:
            file_callers.setdefault(callee_fp, set()).add(caller_fp)

        # ── 5. Flows: which execution flows pass through each file ────────────
        flow_rows = conn.execute(
            """
            SELECT DISTINCT n.file_path, fs.name, fs.criticality
            FROM flow_snapshots fs
            JOIN flow_memberships fm ON fm.flow_id = fs.flow_id
            JOIN nodes n ON n.id = fm.node_id
            WHERE n.file_path IS NOT NULL
            ORDER BY fs.criticality DESC
            """
        ).fetchall() if conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='flow_snapshots'"
        ).fetchone() else []
        file_flows: dict[str, list[str]] = {}
        for fp, flow_name, criticality in flow_rows:
            crit_label = "HIGH" if criticality >= 0.6 else ("MEDIUM" if criticality >= 0.3 else "LOW")
            entry = f"{flow_name} ({crit_label})"
            file_flows.setdefault(fp, []).append(entry)

        conn.close()

        # ── 6. Build GraphContext per file ────────────────────────────────────
        all_files = set(hub_scores) | set(community_ids)
        for fp in all_files:
            ctx = GraphContext()
            ctx.hub_score    = hub_scores.get(fp, 0.0)
            ctx.community_id = community_ids.get(fp)

            if ctx.community_id is not None and ctx.community_id in comm_info:
                ci = comm_info[ctx.community_id]
                ctx.community_name    = ci["name"]
                ctx.community_purpose = ci["purpose"]
                ctx.key_symbols       = ci["key_symbols"]

            risk = file_risk.get(fp, {})
            ctx.risk_score        = risk.get("risk_score",        0.0)
            ctx.caller_count      = risk.get("caller_count",      0)
            ctx.test_coverage     = risk.get("test_coverage",     "unknown")
            ctx.security_relevant = risk.get("security_relevant", False)

            ctx.caller_files = sorted(file_callers.get(fp, set()))
            ctx.flows        = file_flows.get(fp, [])

            graph_contexts[fp] = ctx

        logger.warning(
            "code-review-graph: enriched %d files | hub_scores=%d communities=%d",
            len(graph_contexts), len(hub_scores), len(community_ids),
        )

    except Exception as exc:
        logger.warning("code-review-graph: DB read failed: %s", exc)

    return hub_scores, community_ids, graph_contexts


async def _ensure_graph_built(root: Path) -> bool:
    """
    Build the code-review-graph for `root` if it doesn't exist yet.
    Called at the start of code review — awaited so graph context is always
    available even on the very first scan of a new project.

    Returns True if graph is available after this call, False on failure.
    """
    db_path = root / ".code-review-graph" / "graph.db"
    if db_path.exists():
        return True  # already built

    logger.warning("code-review-graph: graph not found for %s — building now (first-time scan)", root)
    try:
        proc = await asyncio.create_subprocess_exec(
            "python3.11", "-m", "code_review_graph", "build", "--repo", str(root),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=180)
        if proc.returncode != 0:
            err = stderr.decode(errors="replace")[-300:] if stderr else ""
            logger.warning("code-review-graph: build failed (rc=%d): %s", proc.returncode, err)
            return False
        logger.warning("code-review-graph: build complete for %s", root)
        return db_path.exists()
    except asyncio.TimeoutError:
        logger.warning("code-review-graph: build timed out after 180s for %s", root)
        return False
    except Exception as exc:
        logger.warning("code-review-graph: build error: %s", exc)
        return False


async def node_enumerate_files(state: CodeReviewState, deps: dict) -> CodeReviewState:
    """
    Walk the project and build a priority-ordered list of files to review.

    Priority order (with code-review-graph):
      1. Files that already have SAST findings (review for deeper issues)
      2. Files in security-sensitive paths (controllers, services, auth, payment)
      3. All remaining reviewable files, sorted by community then hub centrality score
         (Feature 1: hub-first; Feature 4: community-grouped for richer LLM context)

    Without graph DB: falls back to legacy size-based sort.
    """
    scan_path = state["scan_path"]
    sast_findings = state["sast_findings"]
    root = Path(scan_path)

    # Ensure graph is built — waits synchronously so context is available for first-time scans.
    # For subsequent scans the graph already exists and this returns instantly.
    await _ensure_graph_built(root)

    # Load graph data (Features 1 + 4 + enriched context) — fast, synchronous SQLite read
    hub_scores, community_ids, graph_contexts = _load_graph_data(root)

    # Collect reviewable files, skipping test/generated/build paths
    _HARD_SKIP = {".git", "node_modules", ".venv", "venv", "__pycache__", "target", "build", "dist"}
    all_files: list[Path] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() not in _REVIEWABLE_EXTS:
            continue
        parts_lower = {part.lower() for part in p.parts}
        if parts_lower & _HARD_SKIP:
            continue
        # Skip test/generated paths
        rel_lower = str(p.relative_to(root)).lower()
        if any(kw in rel_lower for kw in _SKIP_PATH_KEYWORDS):
            continue
        try:
            if p.stat().st_size > _MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        all_files.append(p)

    # Priority tier: SAST hits → security paths → rest
    sast_paths = set(sast_findings.keys())

    def priority(p: Path) -> int:
        rel = str(p.relative_to(root))
        if rel in sast_paths:
            return 0
        path_lower = str(p).lower()
        for kw in _PRIORITY_KEYWORDS:
            if kw in path_lower:
                return 1
        return 2

    if hub_scores:
        # Feature 1 + 4: sort by (priority, community_id, -hub_score)
        # Files in the same community are reviewed in sequence → richer LLM context
        # Within each community, highest hub score (most-called file) goes first
        def graph_sort_key(p: Path) -> tuple:
            abs_path = str(p)
            prio = priority(p)
            comm = community_ids.get(abs_path, 9999)
            hub = hub_scores.get(abs_path, 0.0)
            return (prio, comm, -hub)

        all_files.sort(key=graph_sort_key)
        logger.info("code-review-graph: using hub+community sort for %d files", len(all_files))
    else:
        # Legacy sort: priority tier then largest-first
        all_files.sort(key=lambda p: (priority(p), -p.stat().st_size))

    # Adaptive limits based on total reviewable file count
    total_discoverable = len(all_files)
    if total_discoverable <= 20:
        max_files, max_lines = total_discoverable, 80   # small: review all
    elif total_discoverable <= 60:
        max_files, max_lines = 25, 60                   # medium: top 25, 60 lines each
    elif total_discoverable <= 150:
        max_files, max_lines = 20, 50                   # large: top 20, 50 lines each
    else:
        max_files, max_lines = 15, 40                   # xlarge: top 15, 40 lines each

    all_files = all_files[:max_files]

    file_list = [str(p) for p in all_files]
    logger.warning(
        "CODE REVIEW FILES | run=%s discoverable=%d selected=%d max_lines=%d graph_ctx=%d",
        state["run_id"], total_discoverable, len(file_list), max_lines, len(graph_contexts),
    )
    # Write initial progress entry
    pool: asyncpg.Pool = deps["pool"]
    await _upsert_progress(pool, state["run_id"], 0, len(file_list), "", 0, "running")
    return {**state, "files_to_review": file_list, "total_files": len(file_list), "max_lines": max_lines, "graph_contexts": graph_contexts}


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
    graph_contexts: dict[str, GraphContext] = state.get("graph_contexts", {})
    max_lines: int = state.get("max_lines", _DEFAULT_MAX_LINES)

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

    total = len(files)
    reviewed = 0
    processed = 0
    total_findings = 0

    # Semaphore = 2: send 2 files to Ollama concurrently (matches OLLAMA_NUM_PARALLEL=2)
    semaphore = asyncio.Semaphore(2)
    lock = asyncio.Lock()   # protect shared counters

    async def review_one(abs_path: str) -> None:
        nonlocal reviewed, processed, total_findings

        rel = Path(abs_path).name
        async with semaphore:
            async with lock:
                proc_now = processed
                processed += 1
            await _upsert_progress(pool, run_id, proc_now, total, rel, total_findings, "running")

            graph_ctx = graph_contexts.get(abs_path)
            result = await _review_file(abs_path, scan_path, sast_findings, system_prompt, graph_ctx, max_lines)
            if result is None:
                return

            async with lock:
                reviewed += 1

            if result.findings:
                logger.warning("REVIEW %s: %d raw findings (saving confidence >= 0.3)", result.file_path, len(result.findings))
                async with pool.acquire() as conn:
                    for finding in result.findings:
                        if finding.confidence < 0.3:   # lowered from 0.5 — llama3.2:3b gives conservative scores
                            logger.warning("  SKIP low-confidence finding: %s (%.2f)", finding.title, finding.confidence)
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
                async with lock:
                    total_findings += len(result.findings)
                logger.info("Reviewed %s | score=%d findings=%d", result.file_path, result.overall_score, len(result.findings))
            else:
                logger.warning("Reviewed %s | score=%d — LLM returned 0 findings", result.file_path, result.overall_score)

    # Run all files with concurrency=2
    await asyncio.gather(*[review_one(f) for f in files])

    # Mark done
    await _upsert_progress(pool, run_id, total, total, "", total_findings, "completed")
    logger.warning("CODE REVIEW COMPLETE | run=%s files_reviewed=%d total_files=%d findings=%d", run_id, reviewed, total, total_findings)
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
        "max_lines":       _DEFAULT_MAX_LINES,
        "files_reviewed":  0,
        "findings_count":  0,
        "sast_findings":   {},
        "graph_contexts":  {},
        "error":           None,
    }

    try:
        return await app.ainvoke(initial_state)
    except Exception as exc:
        logger.error("Code review workflow crashed | run=%s error=%s", run_id, exc, exc_info=True)
        # Write "failed" status so the UI can show an error instead of spinning forever
        try:
            async with deps["pool"].acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO code_review_status
                        (run_id, status, files_done, total_files, pct, current_file, findings_count, updated_at)
                    VALUES ($1,'failed',$2,$3,$4,NULL,$5,NOW())
                    ON CONFLICT (run_id) DO UPDATE SET
                        status='failed', updated_at=NOW()
                    """,
                    run_id,
                    initial_state.get("files_reviewed", 0),
                    initial_state.get("total_files", 0),
                    0,
                    initial_state.get("findings_count", 0),
                )
        except Exception:
            pass
        raise

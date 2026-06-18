"""
main.py
========
Entry point for the SSDLC Multi-Agent Platform.

Usage:
  # Start the API server (primary mode)
  python main.py serve

  # Submit a local path scan directly (CLI mode, no server needed)
  python main.py scan --path /path/to/your/project

  # Check server health
  python main.py health

Phase 0: local path scanning only.
Phase 1+: add --repo git@github.com:org/repo.git for Git-based scans.
"""

import argparse
import asyncio
import logging
from logging.handlers import RotatingFileHandler
import sys
import uuid
from pathlib import Path
from datetime import datetime, timezone

import uvicorn
from dotenv import load_dotenv

load_dotenv()

_LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_LOG_DATE   = "%Y-%m-%d %H:%M:%S"

_file_handler = RotatingFileHandler(
    Path(__file__).parent / "app.log",
    maxBytes=10 * 1024 * 1024,  # 10 MB per file
    backupCount=5,
    encoding="utf-8",
)
_file_handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_LOG_DATE))

logging.basicConfig(
    level=logging.INFO,
    format=_LOG_FORMAT,
    datefmt=_LOG_DATE,
    handlers=[
        logging.StreamHandler(sys.stdout),
        _file_handler,
    ],
)
logger = logging.getLogger(__name__)


def cmd_serve(args):
    """Start the FastAPI server on configured host:port."""
    from core.config import settings

    logger.info(
        "Starting SSDLC Platform | host=%s port=%d",
        settings.api_host, settings.api_port
    )
    uvicorn.run(
        "api.agent_gateway:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=False,
        log_level="info",
    )


async def _run_scan_async(scan_path: str):
    """
    Run a SAST scan directly from CLI without the HTTP server.

    Useful for:
      - Development and testing
      - CI/CD integration (Phase 1+ will use the API instead)
      - One-off scans without starting the server

    Requires: PostgreSQL running and OLLAMA running.
    """
    import asyncpg
    from core.config import settings
    from core.audit_logger import init_audit_logger, get_audit_logger
    from core.pg_job_queue import init_job_queue, get_job_queue
    from core.prompt_manager import init_prompt_manager, get_prompt_manager
    from core.state.workflow_state import init_workflow_state, get_workflow_state
    from core.state.vector_memory import init_vector_memory, get_vector_memory
    from core.fp_pipeline.layer1_rules import Layer1Rules
    from core.fp_pipeline.layer3_llm import Layer3LLM
    from tools.semgrep_tool import SemgrepTool
    from workflows.sast_workflow import run_sast_workflow

    # --- Validate path ---
    path = Path(scan_path)
    if not path.exists():
        logger.error("Path does not exist: %s", scan_path)
        sys.exit(1)
    if not path.is_dir():
        logger.error("Path must be a directory: %s", scan_path)
        sys.exit(1)

    # --- Connect to PostgreSQL ---
    logger.info("Connecting to PostgreSQL...")
    pool = await asyncpg.create_pool(dsn=settings.db.dsn, min_size=2, max_size=5)

    # --- Initialise all singletons ---
    init_audit_logger(pool)
    init_job_queue(pool)
    init_workflow_state(pool)
    init_vector_memory(pool)
    init_prompt_manager(settings.prompts_dir)

    # --- Create run ID ---
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    run_id = f"scan_{timestamp}_{uuid.uuid4().hex[:6]}"

    # --- Register run in PG ---
    wf_state = get_workflow_state()
    await wf_state.create_run(
        run_id=run_id,
        scan_path=str(path.resolve()),
        agent="sast",
    )

    logger.info("Starting SAST scan | run=%s path=%s", run_id, path.resolve())

    # --- Build deps and run workflow ---
    vector_memory = get_vector_memory()
    prompt_manager = get_prompt_manager()
    layer1 = Layer1Rules(settings.semgrep.rules_path)
    layer3 = Layer3LLM(vector_memory, prompt_manager)

    deps = {
        "pool":           pool,
        "audit":          get_audit_logger(),
        "job_queue":      get_job_queue(),
        "workflow_state": wf_state,
        "vector_memory":  vector_memory,
        "semgrep_tool":   SemgrepTool(),
        "layer1_rules":   layer1,
        "layer3_llm":     layer3,
    }

    final_state = await run_sast_workflow(run_id=run_id, scan_path=str(path.resolve()), deps=deps)

    # --- Print summary ---
    summary = final_state.get("fp_summary", {})
    print("\n" + "=" * 60)
    print(f"  SAST Scan Complete — Run ID: {run_id}")
    print("=" * 60)
    print(f"  Total findings : {summary.get('total', 0)}")
    print(f"  Real           : {summary.get('real', 0)}")
    print(f"  False positives: {summary.get('fp', 0)}")
    print(f"  Escalated      : {summary.get('escalated', 0)}")
    print(f"  Deadlocked     : {summary.get('deadlock', 0)}")
    print("=" * 60)
    print(f"\n  View results: GET /api/v1/scan/{run_id}")
    print(f"  Label findings: POST /api/v1/label")

    if final_state.get("error"):
        print(f"\n  ERROR: {final_state['error']}")
        sys.exit(1)

    await pool.close()


def cmd_scan(args):
    """CLI scan command — runs async workflow synchronously."""
    asyncio.run(_run_scan_async(args.path))


async def _check_health():
    """Check PostgreSQL and Ollama connectivity."""
    import asyncpg
    import httpx
    from core.config import settings

    print("\nChecking SSDLC Platform dependencies...\n")

    # PostgreSQL
    try:
        pool = await asyncpg.create_pool(dsn=settings.db.dsn, min_size=1, max_size=1)
        version = await pool.fetchval("SELECT version()")
        await pool.close()
        print(f"  ✓ PostgreSQL  — {version.split(',')[0]}")
    except Exception as exc:
        print(f"  ✗ PostgreSQL  — {exc}")

    # Ollama
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"{settings.ollama.base_url}/api/tags")
            models = [m["name"] for m in resp.json().get("models", [])]
            tier1_ok = settings.ollama.tier1_model in models
            tier2_ok = settings.ollama.tier2_model in models
            print(f"  {'✓' if tier1_ok else '✗'} Ollama Tier1  — {settings.ollama.tier1_model} {'(available)' if tier1_ok else '(NOT FOUND — run: ollama pull ' + settings.ollama.tier1_model + ')'}")
            print(f"  {'✓' if tier2_ok else '✗'} Ollama Tier2  — {settings.ollama.tier2_model} {'(available)' if tier2_ok else '(NOT FOUND — run: ollama pull ' + settings.ollama.tier2_model + ')'}")
    except Exception as exc:
        print(f"  ✗ Ollama      — {exc}\n    Is Ollama running? Run: ollama serve")

    # Docker (for Semgrep sandbox)
    import subprocess
    try:
        result = subprocess.run(["docker", "info"], capture_output=True, timeout=5)
        if result.returncode == 0:
            print("  ✓ Docker      — available (used for Semgrep sandbox)")
        else:
            print("  ✗ Docker      — not running")
    except Exception:
        print("  ✗ Docker      — not installed")

    print()


def cmd_health(args):
    asyncio.run(_check_health())


# ---------------------------------------------------------------------------
# CLI argument parser
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="ssdlc",
        description="SSDLC Multi-Agent Platform — Phase 0",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # serve
    serve_parser = subparsers.add_parser("serve", help="Start the API server on port 8080")
    serve_parser.set_defaults(func=cmd_serve)

    # scan
    scan_parser = subparsers.add_parser("scan", help="Scan a local directory for security issues")
    scan_parser.add_argument("--path", required=True, help="Path to code directory to scan")
    scan_parser.set_defaults(func=cmd_scan)

    # health
    health_parser = subparsers.add_parser("health", help="Check dependencies (PostgreSQL, Ollama, Docker)")
    health_parser.set_defaults(func=cmd_health)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

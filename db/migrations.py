from __future__ import annotations

"""
db/migrations.py
================
Auto-migration helper — runs the schema SQL at startup.

All DDL in schema.sql uses CREATE TABLE IF NOT EXISTS / CREATE INDEX IF NOT EXISTS,
so this is safe to run on every startup (idempotent).

Called from api/agent_gateway.py lifespan before any other singleton initialisation.
"""

import logging
from pathlib import Path

import asyncpg

logger = logging.getLogger(__name__)

_SCHEMA_FILE = Path(__file__).parent / "schema.sql"


async def run_migrations(pool: asyncpg.Pool) -> None:
    """
    Execute schema.sql against the connected database.
    Skips pgvector extension gracefully if not installed
    (vector search degrades to disabled — Layer 3 still works without it in Phase 0).
    """
    if not _SCHEMA_FILE.exists():
        logger.warning("schema.sql not found at %s — skipping migrations", _SCHEMA_FILE)
        return

    sql = _SCHEMA_FILE.read_text()

    # Split into individual statements by scanning for semicolons that are NOT
    # inside string literals or comments.  A simple line-by-line pass is enough
    # because schema.sql never has semicolons inside string literals.
    statements: list[str] = []
    current: list[str] = []
    for line in sql.splitlines():
        stripped = line.rstrip()
        current.append(stripped)
        # A semicolon at the end of a non-comment line ends the statement.
        code = stripped.lstrip()
        if code and not code.startswith("--") and stripped.rstrip(";") != stripped:
            stmt = "\n".join(current).strip()
            if stmt:
                statements.append(stmt)
            current = []

    # Tables / indexes that require the pgvector extension.
    # These are skipped entirely when pgvector is not installed.
    _VECTOR_DEPENDENT = {"finding_embeddings", "idx_finding_embeddings_hnsw", "idx_finding_embeddings_finding_id"}

    pgvector_available = True  # will be set False if extension creation fails

    async with pool.acquire() as conn:
        for stmt in statements:
            # Skip pure-comment blocks
            non_comment = [
                l for l in stmt.splitlines()
                if l.strip() and not l.strip().startswith("--")
            ]
            if not non_comment:
                continue

            # Skip pgvector-dependent objects when extension is unavailable
            if not pgvector_available:
                stmt_upper = stmt.upper()
                if any(name.upper() in stmt_upper for name in _VECTOR_DEPENDENT):
                    logger.debug("Skipping vector-dependent statement (pgvector not installed)")
                    continue

            try:
                await conn.execute(stmt)
            except (
                asyncpg.exceptions.UndefinedObjectError,
                asyncpg.exceptions.FeatureNotSupportedError,
            ) as exc:
                if "vector" in str(exc).lower():
                    pgvector_available = False
                    logger.warning(
                        "pgvector extension not available — "
                        "Layer 3 semantic search disabled. "
                        "Install with: brew install pgvector  (error: %s)", exc
                    )
                else:
                    logger.warning("Migration statement skipped | error=%s", exc)
            except asyncpg.exceptions.DuplicateTableError:
                pass  # Table already exists — harmless
            except asyncpg.exceptions.DuplicateObjectError:
                pass  # Index already exists — harmless
            except Exception as exc:
                logger.error("Migration error | stmt=%.120s | error=%s", stmt[:120], exc)
                raise

    logger.info("Database migrations applied from %s", _SCHEMA_FILE)

    # -------------------------------------------------------------------------
    # Column additions (ALTER TABLE — idempotent, safe on every startup)
    # These add new columns to existing tables without dropping data.
    # -------------------------------------------------------------------------
    await _add_columns_if_missing(pool)

    # -------------------------------------------------------------------------
    # Code Review Agent table (Phase 1 — created here so it exists on startup)
    # -------------------------------------------------------------------------
    await _create_code_review_table(pool)


async def _add_columns_if_missing(pool: asyncpg.Pool) -> None:
    """
    Add enrichment columns to findings_reports if they don't exist yet.
    Safe to run on an existing DB — PostgreSQL ignores duplicates via
    the column-existence check.
    """
    new_columns = [
        ("findings_reports", "class_name",     "TEXT"),
        ("findings_reports", "method_name",    "TEXT"),
        ("findings_reports", "fix_suggestion", "TEXT"),
        ("findings_reports", "owasp_category", "TEXT"),
        ("findings_reports", "ref_urls",        "JSONB DEFAULT '[]'"),
        ("findings_reports", "likelihood",     "TEXT"),
        ("findings_reports", "impact",         "TEXT"),
    ]

    async with pool.acquire() as conn:
        for table, column, col_type in new_columns:
            # Check if the column already exists
            exists = await conn.fetchval(
                """
                SELECT COUNT(*) FROM information_schema.columns
                WHERE table_name=$1 AND column_name=$2
                """,
                table, column,
            )
            if not exists:
                try:
                    await conn.execute(
                        f"ALTER TABLE {table} ADD COLUMN {column} {col_type}"
                    )
                    logger.info("Added column %s.%s", table, column)
                except Exception as exc:
                    logger.warning("Could not add column %s.%s: %s", table, column, exc)


async def _create_code_review_table(pool: asyncpg.Pool) -> None:
    """Create code_review_findings table if it doesn't exist."""
    async with pool.acquire() as conn:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS code_review_findings (
                id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                run_id          TEXT NOT NULL,
                file_path       TEXT NOT NULL,
                language        TEXT,
                category        TEXT NOT NULL,
                severity        TEXT NOT NULL,
                line_start      INT,
                line_end        INT,
                title           TEXT NOT NULL,
                description     TEXT,
                recommendation  TEXT,
                confidence      REAL DEFAULT 0.5,
                overall_file_score INT,
                created_at      TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_cr_findings_run ON code_review_findings(run_id)"
        )
    logger.info("code_review_findings table ready")

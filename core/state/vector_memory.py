"""
core/state/vector_memory.py
============================
pgvector hybrid retrieval for Layer 3 FP pipeline.

Strategy (SSDLC_Design_v3.2.docx §7.1):
  1. SQL metadata pre-filter:
       WHERE cwe_id = :cwe AND framework = :framework
         AND label_status != 'QUARANTINED'
  2. pgvector ANN similarity on (finding + code context) embedding
       using UniXcoder encoder (768-dim, FP32, runs on M4 Neural Engine).
  3. Re-rank by confidence weight:
       human-confirmed x1.0 | human-audit x0.8 | agent-only x0.4
  4. Return top-5 results injected into Layer 3 prompt.

Poison control:
  - label_status = QUARANTINED → excluded from ALL retrievals.
  - Quarterly: sample retrieved-precedent chains for FP propagation patterns.

Phase 0 note:
  UniXcoder is loaded lazily on first call. In Phase 0 the model must be
  downloaded once and placed at the path in MODELS_PATH env var.
  Use local_files_only=True for air-gap compliance.
"""

import asyncpg
import logging
import numpy as np
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# UniXcoder embedding model (loaded lazily — ~0.5GB, runs on Neural Engine)
# ---------------------------------------------------------------------------
_encoder = None


def _get_encoder():
    """
    Lazy-load UniXcoder embedding model.
    Loaded once on first embed() call to avoid startup overhead.

    Air-gap: set MODELS_PATH and HF_DATASETS_OFFLINE=1 in .env.
    """
    global _encoder
    if _encoder is None:
        import os
        from transformers import AutoTokenizer, AutoModel
        import torch

        model_name = os.getenv("UNIXCODER_MODEL", "microsoft/unixcoder-base")
        models_path = os.getenv("MODELS_PATH", None)

        # Air-gap: use local files only if MODELS_PATH is set
        kwargs = {"local_files_only": bool(models_path)}
        if models_path:
            model_name = f"{models_path}/unixcoder-base"

        logger.info("Loading UniXcoder embedding model from %s ...", model_name)
        tokenizer = AutoTokenizer.from_pretrained(model_name, **kwargs)
        model = AutoModel.from_pretrained(model_name, **kwargs)
        model.eval()
        _encoder = (tokenizer, model)
        logger.info("UniXcoder loaded.")
    return _encoder


def embed(text: str) -> list[float]:
    """
    Encode text to a 768-dim embedding vector using UniXcoder.

    Input: concatenated finding message + code snippet (max 512 tokens).
    Output: L2-normalised float list for pgvector cosine similarity.
    """
    import torch

    tokenizer, model = _get_encoder()

    # Truncate to 512 tokens (UniXcoder max)
    inputs = tokenizer(
        text,
        return_tensors="pt",
        max_length=512,
        truncation=True,
        padding=True,
    )
    with torch.no_grad():
        outputs = model(**inputs)
        # Mean pool over token embeddings → sentence vector
        embedding = outputs.last_hidden_state.mean(dim=1).squeeze().numpy()

    # L2-normalise for cosine similarity in pgvector
    norm = np.linalg.norm(embedding)
    if norm > 0:
        embedding = embedding / norm

    return embedding.tolist()


class VectorMemory:
    """
    pgvector hybrid retrieval for the Layer 3 FP pipeline.

    Used by layer3_llm.py to inject similar past decisions
    into the Qwen2.5-Coder:14b prompt as precedent context.
    """

    def __init__(self, pool: asyncpg.Pool):
        self._pool = pool

    async def store_finding_embedding(
        self,
        finding_id: str,
        text: str,
        label_status: str = "agent-only",
        confidence_weight: float = 0.4,
        fp_decision_id: Optional[str] = None,
    ) -> None:
        """
        Generate and store an embedding for a new finding.

        Called after a finding is written to findings_reports.
        The embedding is used by future similar-finding retrievals.
        """
        vector = embed(text)
        vector_str = "[" + ",".join(str(v) for v in vector) + "]"

        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO finding_embeddings
                    (finding_id, fp_decision_id, embedding, label_status, confidence_weight)
                VALUES ($1, $2, $3::vector, $4, $5)
                ON CONFLICT DO NOTHING
                """,
                finding_id,
                fp_decision_id,
                vector_str,
                label_status,
                confidence_weight,
            )

    async def retrieve_similar(
        self,
        query_text: str,
        cwe_id: Optional[str] = None,
        framework: Optional[str] = None,
        top_k: int = 5,
    ) -> list[dict]:
        """
        Hybrid retrieval: SQL pre-filter → pgvector ANN → confidence re-rank.

        Steps:
          1. Pre-filter by CWE + framework (exact metadata match).
          2. ANN cosine similarity against query embedding.
          3. Re-rank by confidence weight (human > audit > agent).
          4. Return top_k results for Layer 3 prompt injection.

        Quarantined records are always excluded (label_status != 'QUARANTINED').
        """
        query_vector = embed(query_text)
        vector_str = "[" + ",".join(str(v) for v in query_vector) + "]"

        # Build dynamic WHERE clause for optional CWE and framework filters
        conditions = ["fe.label_status != 'QUARANTINED'"]
        params: list = [vector_str]

        if cwe_id:
            params.append(cwe_id)
            conditions.append(f"fr.cwe_id = ${len(params)}")
        if framework:
            params.append(framework)
            conditions.append(f"fr.framework = ${len(params)}")

        where_clause = " AND ".join(conditions)
        params.append(top_k * 3)  # fetch 3x for re-ranking, then trim to top_k

        sql = f"""
            SELECT
                fr.rule_id,
                fr.cwe_id,
                fr.severity,
                fr.message,
                fr.code_snippet,
                fp.verdict,
                fp.fp_category,
                fp.reasoning,
                fe.label_status,
                fe.confidence_weight,
                -- cosine similarity score (lower = more similar in pgvector)
                fe.embedding <=> $1::vector AS distance
            FROM finding_embeddings fe
            JOIN findings_reports fr ON fr.id = fe.finding_id
            LEFT JOIN fp_decisions fp ON fp.id = fe.fp_decision_id
            WHERE {where_clause}
            ORDER BY fe.embedding <=> $1::vector ASC
            LIMIT ${len(params)}
        """

        async with self._pool.acquire() as conn:
            rows = await conn.fetch(sql, *params)

        results = [dict(r) for r in rows]

        # Re-rank: sort by confidence_weight DESC, then similarity ASC
        results.sort(key=lambda r: (-r["confidence_weight"], r["distance"]))

        return results[:top_k]

    async def quarantine(self, finding_id: str) -> None:
        """
        Mark a finding's embedding as QUARANTINED.
        Called when a past decision is retracted or overturned.
        Immediately excludes it from all future retrievals and training data.
        """
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE finding_embeddings
                SET label_status = 'QUARANTINED', confidence_weight = 0.0
                WHERE finding_id = $1
                """,
                finding_id,
            )
        logger.warning("Finding QUARANTINED | finding_id=%s", finding_id)

    async def update_weight(
        self,
        finding_id: str,
        label_status: str,
        confidence_weight: float,
    ) -> None:
        """
        Update label status and weight when a human reviews a finding.
        Called by the label capture endpoint (POST /api/v1/label).
        """
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE finding_embeddings
                SET label_status = $1, confidence_weight = $2
                WHERE finding_id = $3
                """,
                label_status,
                confidence_weight,
                finding_id,
            )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
_vector_memory_instance: Optional[VectorMemory] = None


def init_vector_memory(pool: asyncpg.Pool) -> None:
    global _vector_memory_instance
    _vector_memory_instance = VectorMemory(pool)


def get_vector_memory() -> VectorMemory:
    if _vector_memory_instance is None:
        raise RuntimeError("VectorMemory not initialised — call init_vector_memory() first")
    return _vector_memory_instance

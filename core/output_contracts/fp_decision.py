"""
core/output_contracts/fp_decision.py
=====================================
Pydantic v2 output contract for FP (False Positive) pipeline decisions.

Every layer of the FP pipeline writes its verdict through this contract
before the result is persisted to fp_decisions table in PostgreSQL.

Verdicts:
  REAL      — confirmed security issue, proceed to severity check / human gate
  FP        — false positive, suppress and capture as training label
  ESCALATED — confidence too low, re-run on Tier 1 (Qwen 14B)
  DEADLOCK  — Tier 1 and Tier 2 disagree, route to human review queue

Label status (controls retrieval weight and training inclusion):
  agent-only       — not yet reviewed by human (weight 0.4 in pgvector re-rank)
  human-audit      — spot-checked in weekly audit (weight 0.8)
  human-confirmed  — explicitly approved/dismissed by reviewer (weight 1.0)
  QUARANTINED      — retracted/overturned — excluded from retrieval and training
"""

from __future__ import annotations
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, model_validator


class FPVerdict(str, Enum):
    REAL      = "REAL"
    FP        = "FP"
    ESCALATED = "ESCALATED"   # re-run on Tier 1
    DEADLOCK  = "DEADLOCK"    # human queue


class FPSource(str, Enum):
    LAYER1     = "layer1"        # YAML rule matched
    LAYER2     = "layer2"        # Heuristic filter (path / file-type patterns)
    LAYER3_LLM = "layer3_llm"    # Qwen2.5-Coder:14b verdict
    HUMAN      = "human"         # reviewer decision


class LabelStatus(str, Enum):
    AGENT_ONLY       = "agent-only"
    HUMAN_AUDIT      = "human-audit"
    HUMAN_CONFIRMED  = "human-confirmed"
    QUARANTINED      = "QUARANTINED"


# Map label status → retrieval confidence weight (used in pgvector re-ranking)
LABEL_WEIGHT: dict[LabelStatus, float] = {
    LabelStatus.HUMAN_CONFIRMED: 1.0,
    LabelStatus.HUMAN_AUDIT:     0.8,
    LabelStatus.AGENT_ONLY:      0.4,
    LabelStatus.QUARANTINED:     0.0,   # excluded from retrieval
}


class FPDecision(BaseModel):
    """
    Output contract for a single FP pipeline verdict.

    Produced by:
      - layer1_rules.py  → source=LAYER1
      - layer3_llm.py    → source=LAYER3_LLM
      - Human labeling   → source=HUMAN (via POST /api/v1/label)
    """

    finding_id:   str      = Field(..., description="UUID of the finding in findings_reports")
    run_id:       str      = Field(..., description="Associated workflow run ID")
    verdict:      FPVerdict
    source:       FPSource
    confidence:   float    = Field(0.5, ge=0.0, le=1.0, description="Pipeline confidence 0–1")

    # Populated when verdict=FP
    fp_category:  Optional[str] = Field(
        None,
        description=(
            "FP reason category: test-code | config-only | framework-safe | "
            "dead-code | out-of-scope | annotation-suppressed"
        )
    )
    reasoning:    Optional[str] = Field(
        None,
        description="Human-readable explanation of the verdict (rule match or LLM rationale)"
    )

    label_status: LabelStatus = Field(
        LabelStatus.AGENT_ONLY,
        description="Controls retrieval weight and training data inclusion"
    )

    @model_validator(mode="after")
    def fp_category_required_for_fp(self) -> "FPDecision":
        """FP verdict must include a category — prevents lazy 'FP' without reason."""
        if self.verdict == FPVerdict.FP and not self.fp_category:
            raise ValueError("fp_category is required when verdict is FP")
        return self

    @property
    def retrieval_weight(self) -> float:
        """Weight used when this decision is retrieved as precedent in Layer 3."""
        return LABEL_WEIGHT.get(self.label_status, 0.4)

    @property
    def should_escalate(self) -> bool:
        """
        True if this decision needs re-running on Tier 1 (Qwen 14B).
        Triggered by low confidence or ESCALATED verdict.
        """
        from core.config import settings
        return (
            self.verdict == FPVerdict.ESCALATED
            or self.confidence < settings.llm.escalation_confidence_threshold
        )

    @property
    def needs_human_review(self) -> bool:
        """True if this decision must go to the human review queue."""
        return self.verdict == FPVerdict.DEADLOCK


class FPBatchResult(BaseModel):
    """
    Aggregated FP pipeline results for all findings in one workflow run.
    Written to pg_jobs as the next step payload after FP processing.
    """
    run_id:       str
    total:        int = 0
    real_count:   int = 0        # confirmed security issues
    fp_count:     int = 0        # suppressed as false positives
    escalated:    int = 0        # re-run on Tier 1
    deadlocked:   int = 0        # sent to human queue
    decisions:    list[FPDecision] = Field(default_factory=list)

    @property
    def fp_rate(self) -> float:
        """FP rate for this batch — tracked for LLM–human agreement measurement."""
        if self.total == 0:
            return 0.0
        return self.fp_count / self.total

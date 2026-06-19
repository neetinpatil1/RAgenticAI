"""
core/output_contracts/code_review_report.py
============================================
Pydantic v2 output contract for the Code Review Agent.

Every LLM response is validated against this schema before being written
to PostgreSQL. The LLM reviews each file for:
  - Security issues Semgrep rules didn't catch
  - Performance anti-patterns (N+1, inefficient algorithms, resource leaks)
  - Code quality (complexity, dead code, naming, missing null checks)
  - Best practices (error handling, logging, input validation)
"""

from __future__ import annotations
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, field_validator


class ReviewCategory(str, Enum):
    SECURITY      = "SECURITY"
    PERFORMANCE   = "PERFORMANCE"
    CODE_QUALITY  = "CODE_QUALITY"
    ERROR_HANDLING = "ERROR_HANDLING"
    BEST_PRACTICES = "BEST_PRACTICES"


class ReviewSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class CodeReviewFinding(BaseModel):
    """A single issue found by LLM code review of a file."""

    category:       ReviewCategory  = Field(..., description="Issue category")
    severity:       ReviewSeverity  = Field(..., description="Severity level")
    line_start:     Optional[int]   = Field(None, ge=1, description="Start line (if locatable)")
    line_end:       Optional[int]   = Field(None, description="End line")
    title:          str             = Field(..., description="Short issue title (max 100 chars)")
    description:    str             = Field(..., description="Detailed explanation of the issue")
    recommendation: str             = Field(..., description="Specific fix or mitigation")
    confidence:     float           = Field(0.5, ge=0.0, le=1.0, description="LLM confidence 0–1")

    @field_validator("category", mode="before")
    @classmethod
    def coerce_category(cls, v: object) -> object:
        # LLM sometimes returns "SECURITY|CODE_QUALITY" — take the first value only.
        if isinstance(v, str) and "|" in v:
            v = v.split("|")[0].strip()
        return v

    @field_validator("severity", mode="before")
    @classmethod
    def coerce_severity(cls, v: object) -> object:
        # Guard against the same pipe-separated pattern on severity.
        if isinstance(v, str) and "|" in v:
            v = v.split("|")[0].strip()
        return v

    @field_validator("title")
    @classmethod
    def truncate_title(cls, v: str) -> str:
        return v[:100] if len(v) > 100 else v


class CodeReviewFileResult(BaseModel):
    """LLM review result for one file."""

    file_path:     str                     = Field(..., description="Relative path to reviewed file")
    language:      str                     = Field("unknown", description="Detected language")
    findings:      list[CodeReviewFinding] = Field(default_factory=list)
    overall_score: int                     = Field(75, ge=0, le=100,
                                                    description="Code quality score 0–100 (100=clean)")
    summary:       str                     = Field("", description="One-paragraph file summary")
    review_ms:     int                     = Field(0, description="LLM call duration ms")

    @property
    def has_issues(self) -> bool:
        return len(self.findings) > 0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == ReviewSeverity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == ReviewSeverity.HIGH)

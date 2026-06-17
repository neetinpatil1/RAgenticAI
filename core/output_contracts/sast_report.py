"""
core/output_contracts/sast_report.py
======================================
Pydantic v2 output contract for the SAST Agent.

Every LLM response is validated against this schema before being written
to PostgreSQL. Invalid structured output triggers Tier 1 escalation.

Design principle (SSDLC_Design_v3.2.docx §5):
  "Pydantic output contracts enforce structure; hallucination in structured
   fields is caught before it reaches the database."
"""

from __future__ import annotations
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class Framework(str, Enum):
    SPRING_BOOT = "spring-boot"
    ANGULAR     = "angular"
    DJANGO      = "django"
    FASTAPI     = "fastapi"
    REACT       = "react"
    NODEJS      = "nodejs"
    UNKNOWN     = "unknown"


class SASTFinding(BaseModel):
    """
    A single security finding from Semgrep, enriched by LLM analysis.

    Fields populated by Semgrep (raw tool output):
        rule_id, cwe_id, severity, file_path, line_start, line_end,
        code_snippet, message, fix_suggestion, owasp_category,
        references, class_name, method_name, likelihood, impact

    Fields populated by LLM (Qwen2.5-Coder:14b analysis):
        framework, llm_summary, llm_severity_rationale, confidence
    """

    # --- Raw tool output ---
    rule_id:      str   = Field(..., description="Semgrep rule ID, e.g. java.spring.sqli")
    cwe_id:       Optional[str] = Field(None, description="CWE identifier, e.g. CWE-89")
    severity:     Severity = Field(..., description="Finding severity")
    file_path:    str   = Field(..., description="Relative path to affected file")
    line_start:   int   = Field(..., ge=1, description="Start line number")
    line_end:     Optional[int] = Field(None, description="End line number")
    code_snippet: Optional[str] = Field(None, description="Vulnerable line(s) + surrounding context")
    message:      str   = Field(..., description="Semgrep rule message explaining the issue")

    # --- Location enrichment (derived at scan time) ---
    class_name:   Optional[str] = Field(None, description="Java class name (from filename)")
    method_name:  Optional[str] = Field(None, description="Enclosing method name (scanned from file)")

    # --- Fix & remediation ---
    fix_suggestion: Optional[str] = Field(None, description="Inline fix from rule or LLM suggestion")
    owasp_category: Optional[str] = Field(None, description="OWASP Top 10 category, e.g. A02:2021 - Cryptographic Failures")
    references:     list[str]    = Field(default_factory=list, description="Links to CWE/OWASP/CVE docs")

    # --- Risk metadata ---
    likelihood:   Optional[str] = Field(None, description="Exploitation likelihood: LOW/MEDIUM/HIGH")
    impact:       Optional[str] = Field(None, description="Business impact: LOW/MEDIUM/HIGH")

    # --- LLM enrichment ---
    framework:              Framework = Field(Framework.UNKNOWN, description="Detected framework")
    llm_summary:            Optional[str] = Field(None, description="LLM plain-English explanation of the finding")
    llm_severity_rationale: Optional[str] = Field(None, description="Why this severity was assigned")
    confidence:             float = Field(0.5, ge=0.0, le=1.0, description="LLM self-confidence 0–1")

    @field_validator("code_snippet")
    @classmethod
    def truncate_snippet(cls, v: Optional[str]) -> Optional[str]:
        """Cap snippet at 50 lines to prevent prompt bloat in Layer 3."""
        if v and v.count("\n") > 50:
            lines = v.splitlines()[:50]
            return "\n".join(lines) + "\n... (truncated)"
        return v

    @property
    def fingerprint(self) -> str:
        """
        Deterministic fingerprint for deduplication (baseline vs new logic).
        Based on rule + file + start line — stable across re-runs.
        """
        import hashlib
        raw = f"{self.rule_id}:{self.file_path}:{self.line_start}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @property
    def is_high_stakes(self) -> bool:
        """
        True if this finding touches a high-stakes CWE.
        High-stakes findings always escalate to Tier 1 (Qwen 14B).
        CWE list defined in core/config.py.
        """
        from core.config import settings
        return self.cwe_id in settings.high_stakes_cwes if self.cwe_id else False


class SASTReport(BaseModel):
    """
    Complete output of one SAST scan run.
    Written to findings_reports table in PostgreSQL.
    """
    run_id:    str = Field(..., description="Links to workflow_runs.run_id")
    scan_path: str = Field(..., description="Local path or git repo that was scanned")
    tool:      str = Field("semgrep", description="Scanner that produced these findings")
    findings:  list[SASTFinding] = Field(default_factory=list)

    # Scan metadata
    total_files_scanned: int = Field(0, ge=0)
    scan_duration_ms:    int = Field(0, ge=0)
    semgrep_version:     Optional[str] = None

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def requires_human_gate(self) -> bool:
        """
        True if any non-baseline CRITICAL or HIGH findings exist.
        These block release and enter the human review queue.
        """
        return any(
            f.severity in (Severity.CRITICAL, Severity.HIGH)
            for f in self.findings
        )

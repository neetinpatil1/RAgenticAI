"""
core/fp_pipeline/layer2_heuristics.py
=======================================
Layer 2: Fast heuristic FP filter.

Runs AFTER Layer 1 (YAML rules) and BEFORE Layer 3 (LLM).
Only marks a finding as FP when confidence is very high — conservative
by design to avoid suppressing real vulnerabilities.

Heuristics implemented:
  1. Test file — file path matches test directory / naming conventions.
     These files never run in production; any finding is always FP.

  2. Generated / build artifact — file lives under target/, build/generated-*,
     or follows code-generator naming (*.g.java, *_.java). Generated code is
     not manually maintained so SAST findings are out-of-scope.

  3. Non-source file — finding reported against a file type that Semgrep can
     flag but that has no exploitable runtime path in the JVM stack
     (e.g. XML descriptors, properties files, SQL migration scripts).
     Does NOT apply to JSP/HTML which CAN have XSS.

What is intentionally NOT in L2:
  - Log-injection heuristics: SecurityShepherd shows these ARE real.
  - Catch-generic-exception: legitimate top-level handlers look the same.
  - Repetitive-rule suppression: each location may be a distinct issue.
  These are left to L3 (LLM) which has code context.
"""
from __future__ import annotations

import re
import logging
from typing import Optional

from core.output_contracts.sast_report import SASTFinding
from core.output_contracts.fp_decision import FPDecision, FPVerdict, FPSource, LabelStatus

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Path patterns
# ---------------------------------------------------------------------------

# Matches any path segment that indicates test code.
_TEST_PATH_RE = re.compile(
    r"(?:"
    r"/test/"              # Maven src/test/java/...
    r"|/tests/"
    r"|/test-classes/"
    r"|Test\.java$"        # FooTest.java
    r"|Tests\.java$"       # FooTests.java
    r"|IT\.java$"          # FooIT.java (integration test)
    r"|ITCase\.java$"
    r"|TestCase\.java$"
    r"|Spec\.java$"        # Spock / BDD specs
    r"|/testutil/"
    r"|/testutils/"
    r"|/testhelper/"
    r"|/testhelpers/"
    r"|/testdata/"
    r"|/fixtures/"
    r")",
    re.IGNORECASE,
)

# Matches generated / compiled output directories.
_GENERATED_PATH_RE = re.compile(
    r"(?:"
    r"/target/generated-sources/"
    r"|/target/generated-test-sources/"
    r"|/target/apt_generated/"
    r"|/build/generated/"
    r"|/build/generated-sources/"
    r"|/\.apt_generated/"
    r"|/generated-sources/"
    r"|\.g\.java$"         # ANTLR generated (Foo.g.java)
    r"|_\.java$"           # some generators suffix with underscore
    r")",
    re.IGNORECASE,
)

# Non-source extensions that may be flagged but are not runtime code.
# JSP and HTML are explicitly excluded because they can carry XSS.
_NON_SOURCE_EXTS = frozenset({
    ".xml",       # Spring/Maven config — no direct runtime execution path
    ".properties",
    ".yml",
    ".yaml",
    ".sql",       # migration scripts — parameterised at deploy time
    ".json",
    ".gradle",
    ".kts",       # Kotlin build scripts
    ".md",
    ".txt",
})


def _is_test_file(file_path: str) -> bool:
    return bool(_TEST_PATH_RE.search(file_path))


def _is_generated_file(file_path: str) -> bool:
    return bool(_GENERATED_PATH_RE.search(file_path))


def _is_non_source_file(file_path: str) -> bool:
    """Return True only for extensions where runtime exploit is not possible."""
    dot = file_path.rfind(".")
    if dot == -1:
        return False
    ext = file_path[dot:].lower()
    return ext in _NON_SOURCE_EXTS


# ---------------------------------------------------------------------------
# Layer 2 evaluator
# ---------------------------------------------------------------------------

class Layer2Heuristics:
    """
    Stateless heuristic FP filter.

    evaluate() returns:
      FPDecision  — finding is confidently FP, do not send to L3.
      None        — not sure, pass to L3.
    """

    def evaluate(self, finding: SASTFinding, run_id: str) -> Optional[FPDecision]:
        """
        Evaluate one finding against all L2 heuristics.
        Returns FPDecision(verdict=FP) or None.
        """
        file_path = finding.file_path or ""

        # ── 1. Test file ──────────────────────────────────────────────────
        if _is_test_file(file_path):
            logger.debug(
                "Layer 2 | test-file | rule=%s file=%s",
                finding.rule_id, file_path,
            )
            return self._make_fp(
                finding=finding,
                run_id=run_id,
                fp_category="test-code",
                reasoning=(
                    f"Finding is in a test file and cannot be exploited in production: "
                    f"{file_path}"
                ),
                confidence=0.95,
            )

        # ── 2. Generated / build artifact ────────────────────────────────
        if _is_generated_file(file_path):
            logger.debug(
                "Layer 2 | generated-file | rule=%s file=%s",
                finding.rule_id, file_path,
            )
            return self._make_fp(
                finding=finding,
                run_id=run_id,
                fp_category="out-of-scope",
                reasoning=(
                    f"Finding is in a generated or build artifact — "
                    f"not manually maintained code: {file_path}"
                ),
                confidence=0.95,
            )

        # ── 3. Non-source file ────────────────────────────────────────────
        if _is_non_source_file(file_path):
            logger.debug(
                "Layer 2 | non-source-file | rule=%s file=%s",
                finding.rule_id, file_path,
            )
            return self._make_fp(
                finding=finding,
                run_id=run_id,
                fp_category="out-of-scope",
                reasoning=(
                    f"Finding is in a non-executable config/resource file "
                    f"with no direct runtime exploit path: {file_path}"
                ),
                confidence=0.90,
            )

        # No heuristic matched → pass to L3
        return None

    # ------------------------------------------------------------------
    @staticmethod
    def _make_fp(
        finding: SASTFinding,
        run_id: str,
        fp_category: str,
        reasoning: str,
        confidence: float,
    ) -> FPDecision:
        return FPDecision(
            finding_id=str(finding.fingerprint),
            run_id=run_id,
            verdict=FPVerdict.FP,
            source=FPSource.LAYER2,
            confidence=confidence,
            fp_category=fp_category,
            reasoning=reasoning,
            label_status=LabelStatus.AGENT_ONLY,
        )

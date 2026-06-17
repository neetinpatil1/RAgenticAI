"""
core/fp_pipeline/layer1_rules.py
==================================
Layer 1: YAML rule-based FP pre-filter.

Design (SSDLC_Design_v3.2.docx §6):
  - Always active from Day 1. No training data required.
  - Target: resolve ~30% of findings as FP in <5ms.
  - Rules stored in agents/security/sast/fp_rules.yml (versioned).
  - Spring Boot + Angular rules included at launch.

Rule schema (YAML):
  rules:
    - id: spring_test_code_fp
      description: "Spring @Test and test class findings are always FP"
      match:
        frameworks: [spring-boot]          # optional: only apply to these frameworks
        severity:   [LOW, MEDIUM]          # optional: only apply to these severities
        rule_ids:   []                     # optional: only apply to these Semgrep rule IDs
        code_patterns:                     # optional: regex patterns in code_snippet
          - "@Test"
          - "class.*Test"
      verdict:     FP
      fp_category: test-code
      reasoning:   "Finding is in a test class — not exploitable in production"

If a finding matches all non-empty criteria in a rule, it is resolved as FP.
No match → pass to Layer 3 (LLM).
"""

import re
import yaml
import logging
from pathlib import Path
from typing import Optional

from core.output_contracts.sast_report import SASTFinding
from core.output_contracts.fp_decision import FPDecision, FPVerdict, FPSource, LabelStatus

logger = logging.getLogger(__name__)


class Layer1Rules:
    """
    YAML-driven rule-based FP filter.
    Rules are loaded once at startup and cached in memory.
    Hot-reload supported via reload_rules() (call after Gitea push in Phase 1+).
    """

    def __init__(self, rules_path: str):
        self.rules_path = Path(rules_path)
        self._rules: list[dict] = []
        self.reload_rules()

    def reload_rules(self) -> int:
        """
        Load (or reload) FP rules from YAML file.
        Returns the number of rules loaded.
        """
        if not self.rules_path.exists():
            logger.warning("FP rules file not found: %s — Layer 1 will pass all findings", self.rules_path)
            self._rules = []
            return 0

        with open(self.rules_path) as f:
            data = yaml.safe_load(f)

        self._rules = data.get("rules", [])
        logger.info("Layer 1 FP rules loaded | count=%d path=%s", len(self._rules), self.rules_path)
        return len(self._rules)

    def evaluate(self, finding: SASTFinding, run_id: str) -> Optional[FPDecision]:
        """
        Evaluate a finding against all Layer 1 rules.

        Returns:
            FPDecision with verdict=FP if a rule matches.
            None if no rule matches (finding passes to Layer 3).

        Complexity: O(rules × patterns) — typically <5ms for <100 rules.
        """
        for rule in self._rules:
            if self._rule_matches(rule, finding):
                logger.debug(
                    "Layer 1 match | rule=%s finding=%s:%s",
                    rule.get("id"), finding.file_path, finding.line_start
                )
                return FPDecision(
                    finding_id=str(finding.fingerprint),   # placeholder until DB ID assigned
                    run_id=run_id,
                    verdict=FPVerdict.FP,
                    source=FPSource.LAYER1,
                    confidence=1.0,                        # rule-based = deterministic
                    fp_category=rule.get("fp_category", "rule-match"),
                    reasoning=rule.get("reasoning", f"Matched Layer 1 rule: {rule.get('id')}"),
                    label_status=LabelStatus.AGENT_ONLY,
                )

        # No rule matched — pass to Layer 3
        return None

    def _rule_matches(self, rule: dict, finding: SASTFinding) -> bool:
        """
        Check if a finding satisfies ALL non-empty criteria of a rule.
        Empty/absent criteria are treated as wildcards (match anything).
        """
        match = rule.get("match", {})

        # 1. Framework filter (match any in list)
        allowed_frameworks = match.get("frameworks", [])
        if allowed_frameworks and finding.framework.value not in allowed_frameworks:
            return False

        # 2. Severity filter (match any in list)
        allowed_severities = match.get("severity", [])
        if allowed_severities and finding.severity.value not in allowed_severities:
            return False

        # 3. Rule ID filter (match any in list)
        allowed_rule_ids = match.get("rule_ids", [])
        if allowed_rule_ids and finding.rule_id not in allowed_rule_ids:
            return False

        # 4. Code pattern filter — ALL patterns must match (AND logic within a rule)
        code_patterns = match.get("code_patterns", [])
        if code_patterns:
            snippet = finding.code_snippet or ""
            for pattern in code_patterns:
                if not re.search(pattern, snippet, re.IGNORECASE | re.MULTILINE):
                    return False

        # 5. File path pattern filter
        file_patterns = match.get("file_patterns", [])
        if file_patterns:
            for pattern in file_patterns:
                if not re.search(pattern, finding.file_path, re.IGNORECASE):
                    return False

        return True

    @property
    def rule_count(self) -> int:
        return len(self._rules)

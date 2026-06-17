"""
tools/semgrep_tool.py
======================
Semgrep SAST scanner — Docker-sandboxed wrapper.

Why Docker for this tool specifically:
  Semgrep runs against untrusted code. Sandboxing prevents a malicious
  repository from escaping to the host filesystem. All other services
  (PostgreSQL, Ollama, FastAPI) run natively.

Air-gap setup (SSDLC_Design_v3.2.docx §3, Gap #2):
  Rules are downloaded once on a jump workstation and committed to
  agents/security/sast/fp_rules.yml (and a full rules repo in Phase 1+).
  Semgrep is invoked with:
    --config=file:///rules/  (mounted from local path, no registry call)

Phase 0: single rule file (fp_rules.yml).
Phase 1+: full rules directory mounted from Gitea checkout.

Output: raw Semgrep JSON → parsed into list[SASTFinding].
"""

import asyncio
import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Optional

from core.config import settings
from core.output_contracts.sast_report import SASTFinding, Severity, Framework

logger = logging.getLogger(__name__)


class SemgrepTool:
    """
    Async wrapper for Semgrep running inside a Docker container.

    Mounts:
      - scan_path (read-only) → /src inside container
      - rules_path (read-only) → /rules inside container

    Returns parsed SASTFinding list ready for FP pipeline.
    """

    def __init__(
        self,
        docker_image: Optional[str] = None,
        rules_path: Optional[str] = None,
        timeout: Optional[int] = None,
    ):
        self.docker_image = docker_image or settings.semgrep.docker_image
        self.rules_path   = rules_path   or settings.semgrep.rules_path
        self.timeout      = timeout      or settings.semgrep.timeout

    async def scan(self, scan_path: str) -> list[SASTFinding]:
        """
        Run Semgrep against a local directory.

        Args:
            scan_path: Absolute path to the code to scan.

        Returns:
            List of SASTFinding objects (may be empty if no findings).

        Raises:
            RuntimeError: if Docker is unavailable or Semgrep exits with error.
        """
        scan_path = str(Path(scan_path).resolve())

        if not Path(scan_path).exists():
            raise ValueError(f"Scan path does not exist: {scan_path}")

        rules_path = str(Path(self.rules_path).resolve())
        if not Path(rules_path).exists():
            raise ValueError(f"Semgrep rules not found: {rules_path}. "
                             "Download rules first (see scripts/airgap/setup_semgrep_rules.sh)")

        cmd = self._build_docker_command(scan_path, rules_path)
        logger.info("Semgrep scan starting | path=%s rules=%s", scan_path, rules_path)

        stdout, stderr, returncode = await self._run_command(cmd)

        # Semgrep exit codes: 0=ok/no findings, 1=findings found, 2=error
        if returncode == 2:
            raise RuntimeError(f"Semgrep error (exit 2): {stderr[:500]}")

        findings = self._parse_output(stdout, scan_path)
        logger.info("Semgrep scan complete | findings=%d", len(findings))
        return findings

    def _build_docker_command(self, scan_path: str, rules_path: str) -> list[str]:
        """
        Build the Docker run command for Semgrep.

        Security notes:
          - --read-only: container filesystem is read-only
          - --network none: no network access during scan (air-gap enforcement)
          - --user: run as current user, not root
          - --rm: remove container after run
        """
        uid = os.getuid()
        return [
            "docker", "run",
            "--rm",
            "--read-only",
            "--network", "none",             # no network access during scan
            "--user", f"{uid}:{uid}",
            "-v", f"{scan_path}:/src:ro",   # mount code read-only
            "-v", f"{rules_path}:/rules:ro", # mount rules read-only
            self.docker_image,
            "semgrep",
            "--config", "file:///rules",     # air-gap: use local rules only
            "--json",                         # structured output
            "--no-git-ignore",               # scan all files
            "--timeout", str(self.timeout),
            "--max-target-bytes", "1000000", # skip files >1MB
            "/src",
        ]

    async def _run_command(self, cmd: list[str]) -> tuple[str, str, int]:
        """Run Docker command asynchronously, capturing stdout and stderr."""
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(),
                timeout=self.timeout + 30,  # grace period beyond Semgrep timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            raise RuntimeError(f"Semgrep scan timed out after {self.timeout}s")

        return (
            stdout_bytes.decode("utf-8", errors="replace"),
            stderr_bytes.decode("utf-8", errors="replace"),
            proc.returncode,
        )

    def _parse_output(self, stdout: str, scan_path: str) -> list[SASTFinding]:
        """
        Parse Semgrep JSON output into SASTFinding objects.

        Semgrep JSON schema (relevant fields):
          results[]:
            check_id     → rule_id
            path         → file_path (relative to scan root)
            start.line   → line_start
            end.line     → line_end
            extra:
              message    → message
              severity   → severity
              metadata:
                cwe[]    → cwe_id (first element)
                technology[] → framework hint
              lines      → code_snippet
        """
        if not stdout.strip():
            return []

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as exc:
            logger.warning("Semgrep output parse error: %s — returning empty", exc)
            return []

        findings = []
        for result in data.get("results", []):
            try:
                finding = self._map_result(result, scan_path)
                if finding:
                    findings.append(finding)
            except Exception as exc:
                logger.debug("Skipping malformed Semgrep result: %s", exc)
                continue

        # Enforce max_findings circuit breaker
        if len(findings) > settings.semgrep.max_findings:
            logger.warning(
                "Semgrep max_findings limit hit | found=%d limit=%d — truncating",
                len(findings), settings.semgrep.max_findings
            )
            findings = findings[: settings.semgrep.max_findings]

        return findings

    def _map_result(self, result: dict, scan_path: str) -> Optional[SASTFinding]:
        """Map a single Semgrep result dict to a SASTFinding."""
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})

        # Severity mapping (Semgrep uses uppercase already)
        severity_raw = extra.get("severity", "MEDIUM").upper()
        try:
            severity = Severity(severity_raw)
        except ValueError:
            severity = Severity.MEDIUM

        # CWE: Semgrep emits ["CWE-89: SQL Injection"] — extract ID only
        cwe_list = metadata.get("cwe", [])
        cwe_id = None
        if cwe_list:
            raw_cwe = cwe_list[0] if isinstance(cwe_list, list) else cwe_list
            cwe_id = str(raw_cwe).split(":")[0].strip()

        # Framework detection from Semgrep technology metadata
        tech_list = metadata.get("technology", [])
        framework = self._detect_framework(tech_list, result.get("path", ""))

        # Make file path relative to scan root for cleaner output
        file_path = result.get("path", "")
        if file_path.startswith(scan_path):
            file_path = file_path[len(scan_path):].lstrip("/")

        return SASTFinding(
            rule_id=result.get("check_id", "unknown"),
            cwe_id=cwe_id,
            severity=severity,
            file_path=file_path,
            line_start=result.get("start", {}).get("line", 1),
            line_end=result.get("end", {}).get("line"),
            code_snippet=extra.get("lines"),
            message=extra.get("message", ""),
            framework=framework,
        )

    @staticmethod
    def _detect_framework(tech_list: list, file_path: str) -> Framework:
        """
        Detect framework from Semgrep technology metadata or file path heuristics.
        """
        tech_str = " ".join(tech_list).lower()
        path_lower = file_path.lower()

        if "spring" in tech_str or "spring" in path_lower:
            return Framework.SPRING_BOOT
        if "angular" in tech_str or ".component.ts" in path_lower:
            return Framework.ANGULAR
        if "django" in tech_str:
            return Framework.DJANGO
        if "fastapi" in tech_str or "flask" in tech_str:
            return Framework.FASTAPI
        if "react" in tech_str or ".jsx" in path_lower or ".tsx" in path_lower:
            return Framework.REACT
        if "node" in tech_str or ".js" in path_lower:
            return Framework.NODEJS

        return Framework.UNKNOWN

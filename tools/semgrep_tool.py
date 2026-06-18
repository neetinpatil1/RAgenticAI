"""
tools/semgrep_tool.py
======================
Semgrep SAST scanner — Docker-sandboxed with native fallback.

Execution strategy (tried in order):
  1. Docker sandbox (preferred — isolates untrusted code from host FS).
  2. Native semgrep binary (fallback when Docker is not installed).
     Phase 0 acceptable: we're scanning our own trusted local paths.
     Phase 1+: enforce Docker or add seccomp/chroot as alternative sandbox.

Air-gap setup (SSDLC_Design_v3.2.docx §3, Gap #2):
  Rules are committed to agents/security/sast/fp_rules.yml.
  Semgrep is invoked with --config=<local path> (no network call).

Phase 0: single rule file (fp_rules.yml).
Phase 1+: full rules directory mounted from Gitea checkout.

Output: raw Semgrep JSON → parsed into list[SASTFinding].
"""

import asyncio
import json
import logging
import os
import shutil
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
        detection_rules_path: Optional[str] = None,
        timeout: Optional[int] = None,
    ):
        self.docker_image         = docker_image          or settings.semgrep.docker_image
        # detection_rules_path is passed to Semgrep --config (Semgrep-format YAML)
        # NOT fp_rules.yml which is the Layer 1 Python FP filter
        self.detection_rules_path = detection_rules_path or settings.semgrep.detection_rules_path
        self.timeout              = timeout               or settings.semgrep.timeout

    @staticmethod
    def _docker_available() -> bool:
        """Return True if the docker binary exists and the daemon is reachable."""
        return shutil.which("docker") is not None

    @staticmethod
    def _native_semgrep() -> Optional[str]:
        """
        Return path to native semgrep binary, or None.
        Checks the project venv first so `pip install semgrep` is found.
        """
        # Prefer venv-local binary
        venv_bin = Path(__file__).parent.parent / ".venv" / "bin" / "semgrep"
        if venv_bin.exists():
            return str(venv_bin)
        return shutil.which("semgrep")

    async def scan(self, scan_path: str) -> list[SASTFinding]:
        """
        Run Semgrep against a local directory.

        Tries Docker first; falls back to native semgrep binary.

        Args:
            scan_path: Absolute path to the code to scan.

        Returns:
            List of SASTFinding objects (may be empty if no findings).

        Raises:
            RuntimeError: if neither Docker nor native semgrep is available.
        """
        scan_path = str(Path(scan_path).resolve())

        if not Path(scan_path).exists():
            raise ValueError(f"Scan path does not exist: {scan_path}")

        detection_rules_path = str(Path(self.detection_rules_path).resolve())
        if not Path(detection_rules_path).exists():
            raise ValueError(
                f"Semgrep detection rules not found: {detection_rules_path}. "
                "Expected at agents/security/sast/semgrep_detection_rules.yml"
            )

        logger.info("Semgrep scan starting | path=%s rules=%s", scan_path, detection_rules_path)

        if self._docker_available():
            cmd = self._build_docker_command(scan_path, detection_rules_path)
            logger.info("Using Docker sandbox for Semgrep")
        else:
            native = self._native_semgrep()
            if not native:
                raise RuntimeError(
                    "Neither Docker nor a native semgrep binary found. "
                    "Install one: brew install --cask docker  OR  pip install semgrep"
                )
            cmd = self._build_native_command(native, scan_path, detection_rules_path)
            logger.warning(
                "Docker not available — running Semgrep natively (no sandbox). "
                "Install Docker for production use."
            )

        stdout, stderr, returncode = await self._run_command(cmd)

        # Semgrep exit codes: 0=ok/no findings, 1=findings found, 2=partial results with rule errors
        # Exit code 2 means some rules failed but the scan still ran — parse what we have.
        # Only treat it as fatal if stdout is empty (no JSON produced at all).
        if returncode == 2:
            if not stdout.strip():
                raise RuntimeError(f"Semgrep error (exit 2): {stderr[:500]}")
            logger.warning(
                "Semgrep exited with code 2 (some rules had errors) — continuing with partial results. "
                "stderr: %s", stderr[:300]
            )

        findings = self._parse_output(stdout, scan_path)
        findings, scan_stats = self._parse_output(stdout, scan_path)
        logger.info(
            "Semgrep scan complete | findings=%d files_scanned=%d skipped=%d",
            len(findings), scan_stats["files_scanned"], scan_stats["files_skipped"],
        )
        return findings, scan_stats

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

    def _build_native_command(self, semgrep_bin: str, scan_path: str, rules_path: str) -> list[str]:
        """
        Build the native (non-Docker) Semgrep command.
        Used as fallback when Docker is not installed.
        """
        return [
            semgrep_bin,
            "--config", rules_path,   # local rules — no network call
            "--json",
            "--no-git-ignore",
            "--timeout", str(self.timeout),
            "--max-target-bytes", "1000000",
            scan_path,
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

    def _parse_output(self, stdout: str, scan_path: str) -> tuple[list[SASTFinding], dict]:
        """
        Parse Semgrep JSON output into SASTFinding objects plus scan statistics.

        Returns:
            (findings, scan_stats) where scan_stats contains:
              files_scanned   — total files Semgrep analysed
              files_skipped   — files excluded (too large, binary, etc.)
              skip_reasons    — breakdown of why files were skipped
              files_with_findings — set of unique file paths that have findings
        """
        empty_stats = {"files_scanned": 0, "files_skipped": 0, "skip_reasons": {}, "files_with_findings": 0}

        if not stdout.strip():
            return [], empty_stats

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as exc:
            logger.warning("Semgrep output parse error: %s — returning empty", exc)
            return [], empty_stats

        # --- Scan statistics from paths block ---
        paths = data.get("paths", {})
        scanned_list = paths.get("scanned", [])
        skipped_list = paths.get("skipped", [])

        skip_reasons: dict[str, int] = {}
        for s in skipped_list:
            reason = s.get("reason", "unknown") if isinstance(s, dict) else "unknown"
            skip_reasons[reason] = skip_reasons.get(reason, 0) + 1

        # --- Parse findings ---
        findings = []
        files_with_findings: set[str] = set()
        for result in data.get("results", []):
            try:
                finding = self._map_result(result, scan_path)
                if finding:
                    findings.append(finding)
                    files_with_findings.add(finding.file_path)
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

        scan_stats = {
            "files_scanned":       len(scanned_list),
            "files_skipped":       len(skipped_list),
            "skip_reasons":        skip_reasons,
            "files_with_findings": len(files_with_findings),
        }

        return findings, scan_stats

    def _map_result(self, result: dict, scan_path: str) -> Optional[SASTFinding]:
        """Map a single Semgrep result dict to a SASTFinding."""
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})

        # Severity: Semgrep uses WARNING/ERROR, map to our enum
        sev_map = {"ERROR": "CRITICAL", "WARNING": "HIGH", "INFO": "LOW"}
        severity_raw = extra.get("severity", "MEDIUM").upper()
        severity_raw = sev_map.get(severity_raw, severity_raw)
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

        # OWASP category — use most recent year entry if multiple
        owasp_list = metadata.get("owasp", [])
        owasp_category = None
        if owasp_list:
            # Prefer 2021 entry, fall back to first available
            for entry in owasp_list:
                if "2021" in entry:
                    owasp_category = entry
                    break
            if not owasp_category:
                owasp_category = owasp_list[0] if isinstance(owasp_list, list) else str(owasp_list)

        # References — documentation/CVE links from rule metadata
        references = metadata.get("references", [])
        if not isinstance(references, list):
            references = [str(references)] if references else []

        # Fix suggestion — inline fix provided by the rule (not all rules have this)
        fix_suggestion = extra.get("fix") or None
        if fix_suggestion:
            fix_suggestion = fix_suggestion.strip()

        # Likelihood and Impact — from Semgrep rule metadata
        likelihood = metadata.get("likelihood") or None
        impact = metadata.get("impact") or None

        # Framework detection from Semgrep technology metadata
        tech_list = metadata.get("technology", [])
        framework = self._detect_framework(tech_list, result.get("path", ""))

        # File path — make relative to scan root for cleaner output
        abs_file_path = result.get("path", "")
        file_path = abs_file_path
        if file_path.startswith(scan_path):
            file_path = file_path[len(scan_path):].lstrip("/")

        line_start = result.get("start", {}).get("line", 1)
        line_end   = result.get("end",   {}).get("line")

        # Class name — Java class name equals the filename without extension
        class_name = self._extract_class_name(file_path)

        # Code snippet — Semgrep OSS requires login for extra.lines.
        # Read the file directly to get the vulnerable lines + context.
        code_snippet = self._read_code_context(abs_file_path, line_start, line_end)

        # Method name — scan backwards from line_start to find enclosing method
        method_name = self._extract_method_name(abs_file_path, line_start)

        return SASTFinding(
            rule_id=result.get("check_id", "unknown"),
            cwe_id=cwe_id,
            severity=severity,
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            code_snippet=code_snippet,
            message=extra.get("message", "").strip(),
            class_name=class_name,
            method_name=method_name,
            fix_suggestion=fix_suggestion,
            owasp_category=owasp_category,
            references=references,
            likelihood=likelihood,
            impact=impact,
            framework=framework,
        )

    @staticmethod
    def count_packages(scan_path: str) -> dict:
        """
        Count declared dependencies from common build files found in the project.

        Supports:
          - Maven   (pom.xml)          → <dependency> count
          - Gradle  (build.gradle)     → implementation/compile/api count
          - Python  (requirements.txt) → line count
          - Node    (package.json)     → dependencies + devDependencies count

        Returns a dict with keys: total, by_file [{file, count, type}]
        """
        import xml.etree.ElementTree as ET
        import re

        results = []
        root = Path(scan_path)

        # Maven pom.xml
        for pom in root.rglob("pom.xml"):
            try:
                tree = ET.parse(pom)
                ns = {"m": "http://maven.apache.org/POM/4.0.0"}
                deps = tree.findall(".//m:dependency", ns) or tree.findall(".//dependency")
                count = len(deps)
                if count:
                    results.append({
                        "file": str(pom.relative_to(root)),
                        "count": count,
                        "type": "maven",
                    })
            except Exception:
                pass

        # Gradle build.gradle / build.gradle.kts
        for gradle in list(root.rglob("build.gradle")) + list(root.rglob("build.gradle.kts")):
            try:
                text = gradle.read_text(errors="replace")
                deps = re.findall(
                    r'\b(?:implementation|compile|api|testImplementation|runtimeOnly)\s*[\(\'":]',
                    text
                )
                if deps:
                    results.append({
                        "file": str(gradle.relative_to(root)),
                        "count": len(deps),
                        "type": "gradle",
                    })
            except Exception:
                pass

        # Python requirements.txt
        for req in root.rglob("requirements*.txt"):
            try:
                lines = [l.strip() for l in req.read_text().splitlines()
                         if l.strip() and not l.startswith("#")]
                if lines:
                    results.append({
                        "file": str(req.relative_to(root)),
                        "count": len(lines),
                        "type": "pip",
                    })
            except Exception:
                pass

        # Node package.json
        for pkg in root.rglob("package.json"):
            if "node_modules" in str(pkg):
                continue
            try:
                import json as _json
                data = _json.loads(pkg.read_text())
                count = len(data.get("dependencies", {})) + len(data.get("devDependencies", {}))
                if count:
                    results.append({
                        "file": str(pkg.relative_to(root)),
                        "count": count,
                        "type": "npm",
                    })
            except Exception:
                pass

        total = sum(r["count"] for r in results)
        return {"total": total, "by_file": results}

    @staticmethod
    def _extract_class_name(file_path: str) -> Optional[str]:
        """Derive class name from file path (Java: filename without extension)."""
        name = Path(file_path).stem
        return name if name else None

    @staticmethod
    def _read_code_context(
        abs_file_path: str,
        line_start: int,
        line_end: Optional[int],
        context_lines: int = 3,
    ) -> Optional[str]:
        """
        Read the vulnerable lines from disk plus a few context lines.
        Returns None if the file cannot be read.

        Output format:
          [line N]  code line
          >>>       vulnerable line(s)
          [line N]  code line
        """
        try:
            with open(abs_file_path, encoding="utf-8", errors="replace") as f:
                all_lines = f.readlines()
        except (OSError, IOError):
            return None

        end = line_end or line_start
        # 0-indexed
        ctx_start = max(0, line_start - 1 - context_lines)
        ctx_end   = min(len(all_lines), end + context_lines)

        output_lines = []
        for i in range(ctx_start, ctx_end):
            lineno = i + 1
            code   = all_lines[i].rstrip()
            if line_start <= lineno <= end:
                output_lines.append(f">>> {lineno:4d} | {code}")  # mark vulnerable lines
            else:
                output_lines.append(f"    {lineno:4d} | {code}")

        return "\n".join(output_lines) if output_lines else None

    @staticmethod
    def _extract_method_name(abs_file_path: str, line_start: int) -> Optional[str]:
        """
        Scan backwards from line_start to find the enclosing Java/Python method.
        Returns the method signature (truncated) or None.
        """
        import re

        # Java method signature pattern
        java_method = re.compile(
            r'^\s*(public|private|protected|static|final|synchronized|'
            r'abstract|native|default|override|\@\w+\s*)*'
            r'[\w<>\[\],\s]+\s+(\w+)\s*\('
        )
        # Python def pattern
        py_method = re.compile(r'^\s*(?:async\s+)?def\s+(\w+)\s*\(')

        try:
            with open(abs_file_path, encoding="utf-8", errors="replace") as f:
                all_lines = f.readlines()
        except (OSError, IOError):
            return None

        # Scan backwards from the finding line (max 50 lines up)
        search_start = min(line_start - 1, len(all_lines) - 1)
        for i in range(search_start, max(0, search_start - 50), -1):
            line = all_lines[i]
            m = java_method.match(line)
            if m:
                method = m.group(2)
                # Skip common false matches (class declarations, annotations)
                if method not in ("class", "interface", "enum", "return", "if", "for", "while"):
                    return method
            m = py_method.match(line)
            if m:
                return m.group(1)

        return None

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

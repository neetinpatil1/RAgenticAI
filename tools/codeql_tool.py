"""
tools/codeql_tool.py
=====================
CodeQL CLI wrapper — async, graceful-skip when CLI is absent.

Execution strategy:
  1. Detect CodeQL CLI binary (several well-known locations).
  2. Detect project language from build files in scan_path.
  3. Create a CodeQL database (with Maven build for Java; source-only for others).
  4. Run the security query pack against the database.
  5. Parse SARIF output into SASTFinding list.
  6. Clean up /tmp artefacts in a finally block.

When CodeQL is NOT installed, is_available() returns False and scan()
returns ([], CodeQLStats(skipped=True, ...)) immediately — it never raises.

Design notes:
  - All subprocess calls use asyncio.create_subprocess_exec (timeout=600s).
  - Every failure path logs a warning and returns empty results.
  - DB path: /tmp/codeql-db-{run_id}/  (cleaned up in finally).
  - SARIF output: /tmp/codeql-{run_id}.sarif (cleaned up in finally).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from core.output_contracts.sast_report import SASTFinding, Severity, Framework

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CodeQL Stats dataclass
# ---------------------------------------------------------------------------

@dataclass
class CodeQLStats:
    language: str
    db_created: bool
    findings_count: int
    query_pack: str
    db_size_mb: float
    duration_ms: int
    skipped: bool = False
    skip_reason: str = ""


# ---------------------------------------------------------------------------
# Severity / level mapping
# ---------------------------------------------------------------------------

_LEVEL_TO_SEVERITY = {
    "error":   Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note":    Severity.LOW,
    "none":    Severity.INFO,
}

# ---------------------------------------------------------------------------
# CodeQL Tool
# ---------------------------------------------------------------------------

class CodeQLTool:
    """
    Async wrapper for the CodeQL CLI.

    Usage:
        tool = CodeQLTool()
        if tool.is_available():
            findings, stats = await tool.scan(scan_path, run_id)
    """

    # Ordered list of candidate binary locations
    _CANDIDATE_PATHS = [
        None,                    # shutil.which first
        "~/codeql/codeql",
        "~/.local/bin/codeql",
        "/opt/codeql/codeql",
    ]

    def __init__(self, timeout: int = 600):
        self._timeout = timeout
        self._cli_path: Optional[str] = None  # resolved lazily

    # ------------------------------------------------------------------
    # CLI detection
    # ------------------------------------------------------------------

    @staticmethod
    def _find_cli() -> Optional[str]:
        """Search for the codeql binary in well-known locations."""
        # 1. PATH via shutil.which
        found = shutil.which("codeql")
        if found:
            return found

        # 2. Fixed locations
        for candidate in ("~/codeql/codeql", "~/.local/bin/codeql", "/opt/codeql/codeql"):
            expanded = Path(candidate).expanduser()
            if expanded.exists() and os.access(str(expanded), os.X_OK):
                return str(expanded)

        return None

    def is_available(self) -> bool:
        """Return True if the codeql CLI binary can be found."""
        if self._cli_path is None:
            self._cli_path = self._find_cli() or ""
        return bool(self._cli_path)

    def _cli(self) -> str:
        """Return resolved CLI path (raises if not available)."""
        if not self.is_available():
            raise RuntimeError("CodeQL CLI not found")
        return self._cli_path  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Language detection
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_language(scan_path: str) -> str:
        """
        Detect the primary language of the project from build files.

        Priority:
          pom.xml / build.gradle  → java
          requirements*.txt / setup.py → python
          package.json            → javascript
          default                 → java
        """
        root = Path(scan_path)

        # Java
        if list(root.rglob("pom.xml")) or list(root.rglob("build.gradle")):
            return "java"

        # Python
        if list(root.rglob("requirements*.txt")) or list(root.rglob("setup.py")):
            return "python"

        # JavaScript / TypeScript
        pkg_jsons = [p for p in root.rglob("package.json") if "node_modules" not in str(p)]
        if pkg_jsons:
            return "javascript"

        return "java"

    # ------------------------------------------------------------------
    # Database creation
    # ------------------------------------------------------------------

    async def _create_database(
        self,
        scan_path: str,
        db_path: str,
        language: str,
        run_id: str,
    ) -> bool:
        """
        Create a CodeQL database for the project.

        For Java projects, attempts a Maven-assisted build first (more accurate).
        If Maven compile fails, falls back to source-only mode.

        Returns True if the database was created successfully.
        """
        # Find pom.xml for Java projects
        pom_xml: Optional[str] = None
        if language == "java":
            pom_files = list(Path(scan_path).rglob("pom.xml"))
            if pom_files:
                pom_xml = str(pom_files[0])

        # Attempt 1: with Maven build command (Java only, more accurate)
        if language == "java" and pom_xml:
            success = await self._run_database_create(
                scan_path=scan_path,
                db_path=db_path,
                language=language,
                build_command=f"mvn compile -q -f {pom_xml}",
            )
            if success:
                logger.info(
                    "CodeQL database created (Maven build) | run=%s lang=%s", run_id, language
                )
                return True
            # Maven build failed — retry without build command (source-only)
            logger.warning(
                "CodeQL: Maven compile failed — retrying in source-only mode | run=%s", run_id
            )

        # Attempt 2: source-only (Python, JS, or Java fallback)
        success = await self._run_database_create(
            scan_path=scan_path,
            db_path=db_path,
            language=language,
            build_command=None,
        )
        if success:
            logger.info(
                "CodeQL database created (source-only) | run=%s lang=%s", run_id, language
            )
        return success

    async def _run_database_create(
        self,
        scan_path: str,
        db_path: str,
        language: str,
        build_command: Optional[str],
    ) -> bool:
        """Execute `codeql database create` and return True on success."""
        cmd = [
            self._cli(),
            "database", "create", db_path,
            f"--language={language}",
            f"--source-root={scan_path}",
            "--overwrite",
        ]
        if build_command:
            cmd.append(f"--command={build_command}")

        stdout, stderr, rc = await self._run_command(cmd, timeout=self._timeout)
        if rc != 0:
            logger.warning(
                "codeql database create failed | rc=%d stderr=%s", rc, stderr[:500]
            )
            return False
        return True

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------

    async def _run_analysis(
        self,
        db_path: str,
        sarif_path: str,
        language: str,
        run_id: str,
    ) -> bool:
        """
        Execute `codeql database analyze` and write SARIF to sarif_path.
        Returns True on success.
        """
        query_pack = f"codeql/{language}-queries:Security/"
        cmd = [
            self._cli(),
            "database", "analyze", db_path,
            "--format=sarif-latest",
            f"--output={sarif_path}",
            query_pack,
        ]

        stdout, stderr, rc = await self._run_command(cmd, timeout=self._timeout)
        if rc != 0:
            logger.warning(
                "codeql database analyze failed | run=%s rc=%d stderr=%s",
                run_id, rc, stderr[:500],
            )
            return False

        logger.info("CodeQL analysis complete | run=%s sarif=%s", run_id, sarif_path)
        return True

    # ------------------------------------------------------------------
    # SARIF parsing
    # ------------------------------------------------------------------

    def _parse_sarif(self, sarif_path: str, scan_path: str, language: str) -> list[SASTFinding]:
        """
        Parse a CodeQL SARIF file into a list of SASTFinding objects.

        SARIF structure (simplified):
          runs[0].results[*] → findings
          runs[0].tool.driver.rules[*] → rule metadata (fix, tags)
        """
        try:
            with open(sarif_path, encoding="utf-8", errors="replace") as f:
                data = json.load(f)
        except Exception as exc:
            logger.warning("CodeQL: SARIF parse error: %s", exc)
            return []

        findings: list[SASTFinding] = []

        for run in data.get("runs", []):
            # Build rule lookup: ruleId → rule metadata
            rules_by_id: dict[str, dict] = {}
            driver = run.get("tool", {}).get("driver", {})
            for rule in driver.get("rules", []):
                rule_id = rule.get("id", "")
                if rule_id:
                    rules_by_id[rule_id] = rule

            for result in run.get("results", []):
                try:
                    finding = self._map_result(result, rules_by_id, scan_path, language)
                    if finding:
                        findings.append(finding)
                except Exception as exc:
                    logger.debug("CodeQL: skipping malformed result: %s", exc)
                    continue

        return findings

    def _map_result(
        self,
        result: dict,
        rules_by_id: dict[str, dict],
        scan_path: str,
        language: str,
    ) -> Optional[SASTFinding]:
        """Map a single SARIF result dict to a SASTFinding."""
        rule_id = result.get("ruleId", "unknown")
        message = result.get("message", {}).get("text", "").strip()
        level = result.get("level", "warning").lower()

        severity = _LEVEL_TO_SEVERITY.get(level, Severity.MEDIUM)

        # Location — first physical location
        locations = result.get("locations", [])
        file_path = ""
        line_start = 1
        line_end: Optional[int] = None

        if locations:
            phys = locations[0].get("physicalLocation", {})
            artifact = phys.get("artifactLocation", {})
            region = phys.get("region", {})

            uri = artifact.get("uri", "")
            # Make path relative to scan_path
            file_path = self._resolve_file_path(uri, scan_path)
            line_start = region.get("startLine", 1)
            line_end = region.get("endLine") or None

        # Rule metadata from driver.rules
        rule_meta = rules_by_id.get(rule_id, {})
        tags: list[str] = rule_meta.get("properties", {}).get("tags", [])

        # CWE — from tags like "external/cwe/cwe-089" → "CWE-89"
        cwe_id: Optional[str] = None
        for tag in tags:
            tag_lower = tag.lower()
            if "cwe" in tag_lower:
                # e.g. "external/cwe/cwe-089" → "CWE-89"
                parts = tag_lower.split("/")
                cwe_part = parts[-1]  # "cwe-089"
                if cwe_part.startswith("cwe-"):
                    num = cwe_part[4:].lstrip("0") or "0"
                    cwe_id = f"CWE-{num}"
                break

        # OWASP category — from tags like "security/owasp/a1" → "A1"
        owasp_category: Optional[str] = None
        for tag in tags:
            tag_lower = tag.lower()
            if "owasp" in tag_lower:
                parts = tag_lower.split("/")
                owasp_part = parts[-1]  # "a1"
                if owasp_part:
                    owasp_category = owasp_part.upper()
                break

        # Fix suggestion from rule help.text
        fix_suggestion: Optional[str] = None
        help_block = rule_meta.get("help", {})
        if isinstance(help_block, dict):
            fix_suggestion = help_block.get("text") or help_block.get("markdown") or None

        # Framework from language
        framework = self._language_to_framework(language)

        # Code snippet — read from actual source file
        abs_file_path = str(Path(scan_path) / file_path) if file_path else ""
        code_snippet: Optional[str] = None
        if abs_file_path and Path(abs_file_path).exists():
            code_snippet = _read_code_context(abs_file_path, line_start, line_end)

        # Method name
        method_name: Optional[str] = None
        if abs_file_path and Path(abs_file_path).exists():
            method_name = _extract_method_name(abs_file_path, line_start)

        # Class name from file
        class_name = Path(file_path).stem if file_path else None

        if not message:
            message = rule_meta.get("shortDescription", {}).get("text", rule_id)

        return SASTFinding(
            rule_id=rule_id,
            cwe_id=cwe_id,
            severity=severity,
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            code_snippet=code_snippet,
            message=message,
            class_name=class_name,
            method_name=method_name,
            fix_suggestion=fix_suggestion,
            owasp_category=owasp_category,
            references=[],
            framework=framework,
        )

    @staticmethod
    def _resolve_file_path(uri: str, scan_path: str) -> str:
        """
        Make a SARIF artifact URI relative to scan_path.

        CodeQL emits URIs like "src/main/java/Foo.java" or absolute paths.
        Strip file:// prefix and make relative to scan_path.
        """
        # Strip file:// scheme
        if uri.startswith("file://"):
            uri = uri[7:]

        # If absolute and under scan_path, make relative
        if uri.startswith(scan_path):
            return uri[len(scan_path):].lstrip("/")

        # If it starts with a leading slash but not under scan_path, try stripping
        if uri.startswith("/"):
            return uri.lstrip("/")

        return uri

    @staticmethod
    def _language_to_framework(language: str) -> Framework:
        mapping = {
            "java":       Framework.SPRING_BOOT,
            "python":     Framework.DJANGO,
            "javascript": Framework.NODEJS,
        }
        return mapping.get(language, Framework.UNKNOWN)

    # ------------------------------------------------------------------
    # Database size helper
    # ------------------------------------------------------------------

    @staticmethod
    def _db_size_mb(db_path: str) -> float:
        """Return the size of the CodeQL database directory in MB."""
        try:
            total = sum(
                f.stat().st_size
                for f in Path(db_path).rglob("*")
                if f.is_file()
            )
            return round(total / (1024 * 1024), 2)
        except Exception:
            return 0.0

    # ------------------------------------------------------------------
    # subprocess helper
    # ------------------------------------------------------------------

    async def _run_command(
        self, cmd: list[str], timeout: int = 600
    ) -> tuple[str, str, int]:
        """Run a subprocess command with timeout, returning (stdout, stderr, rc)."""
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()
                logger.warning("CodeQL command timed out after %ds: %s", timeout, cmd[0])
                return "", f"Timed out after {timeout}s", -1

            return (
                stdout_bytes.decode("utf-8", errors="replace"),
                stderr_bytes.decode("utf-8", errors="replace"),
                proc.returncode,
            )
        except Exception as exc:
            logger.warning("CodeQL command exception: %s", exc)
            return "", str(exc), -1

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def scan(
        self,
        scan_path: str,
        run_id: str,
    ) -> tuple[list[SASTFinding], CodeQLStats]:
        """
        Run a full CodeQL scan: detect → create DB → analyze → parse SARIF.

        Always returns (findings, stats) — never raises.
        On any failure: returns ([], stats_with_skipped=True).
        Cleans up /tmp artefacts in a finally block.
        """
        start_ms = int(datetime.now(timezone.utc).timestamp() * 1000)

        # --- CLI availability ---
        if not self.is_available():
            logger.warning("CodeQL CLI not found — skipping scan | run=%s", run_id)
            return [], CodeQLStats(
                language="unknown",
                db_created=False,
                findings_count=0,
                query_pack="",
                db_size_mb=0.0,
                duration_ms=0,
                skipped=True,
                skip_reason="codeql CLI not found",
            )

        language = self._detect_language(scan_path)
        db_path   = f"/tmp/codeql-db-{run_id}"
        sarif_path = f"/tmp/codeql-{run_id}.sarif"
        query_pack = f"codeql/{language}-queries:Security/"

        logger.info(
            "CodeQL scan starting | run=%s lang=%s path=%s", run_id, language, scan_path
        )

        try:
            # --- Step 1: Create database ---
            db_created = await self._create_database(scan_path, db_path, language, run_id)
            if not db_created:
                elapsed = int(datetime.now(timezone.utc).timestamp() * 1000) - start_ms
                logger.warning("CodeQL: database creation failed | run=%s", run_id)
                return [], CodeQLStats(
                    language=language,
                    db_created=False,
                    findings_count=0,
                    query_pack=query_pack,
                    db_size_mb=0.0,
                    duration_ms=elapsed,
                    skipped=True,
                    skip_reason="database creation failed",
                )

            db_size = self._db_size_mb(db_path)

            # --- Step 2: Analyze ---
            analysis_ok = await self._run_analysis(db_path, sarif_path, language, run_id)
            if not analysis_ok:
                elapsed = int(datetime.now(timezone.utc).timestamp() * 1000) - start_ms
                logger.warning("CodeQL: analysis failed | run=%s", run_id)
                return [], CodeQLStats(
                    language=language,
                    db_created=True,
                    findings_count=0,
                    query_pack=query_pack,
                    db_size_mb=db_size,
                    duration_ms=elapsed,
                    skipped=True,
                    skip_reason="analysis failed",
                )

            # --- Step 3: Parse SARIF ---
            findings = self._parse_sarif(sarif_path, scan_path, language)
            elapsed = int(datetime.now(timezone.utc).timestamp() * 1000) - start_ms

            logger.info(
                "CodeQL scan complete | run=%s findings=%d duration_ms=%d",
                run_id, len(findings), elapsed,
            )

            return findings, CodeQLStats(
                language=language,
                db_created=True,
                findings_count=len(findings),
                query_pack=query_pack,
                db_size_mb=db_size,
                duration_ms=elapsed,
            )

        except Exception as exc:
            elapsed = int(datetime.now(timezone.utc).timestamp() * 1000) - start_ms
            logger.warning("CodeQL scan exception | run=%s error=%s", run_id, exc)
            return [], CodeQLStats(
                language=language,
                db_created=False,
                findings_count=0,
                query_pack=query_pack,
                db_size_mb=0.0,
                duration_ms=elapsed,
                skipped=True,
                skip_reason=str(exc),
            )

        finally:
            # Always clean up temp artefacts
            _cleanup(db_path)
            _cleanup(sarif_path)


# ---------------------------------------------------------------------------
# Module-level helpers (shared with SASTFinding enrichment, mirrors semgrep_tool)
# ---------------------------------------------------------------------------

def _read_code_context(
    abs_file_path: str,
    line_start: int,
    line_end: Optional[int],
    context_lines: int = 3,
) -> Optional[str]:
    """Read vulnerable lines + surrounding context from a source file."""
    try:
        with open(abs_file_path, encoding="utf-8", errors="replace") as f:
            all_lines = f.readlines()
    except (OSError, IOError):
        return None

    end = line_end or line_start
    ctx_start = max(0, line_start - 1 - context_lines)
    ctx_end   = min(len(all_lines), end + context_lines)

    output_lines = []
    for i in range(ctx_start, ctx_end):
        lineno = i + 1
        code   = all_lines[i].rstrip()
        if line_start <= lineno <= end:
            output_lines.append(f">>> {lineno:4d} | {code}")
        else:
            output_lines.append(f"    {lineno:4d} | {code}")

    return "\n".join(output_lines) if output_lines else None


def _extract_method_name(abs_file_path: str, line_start: int) -> Optional[str]:
    """Scan backwards from line_start to find the enclosing Java/Python method."""
    import re

    java_method = re.compile(
        r'^\s*(public|private|protected|static|final|synchronized|'
        r'abstract|native|default|override|\@\w+\s*)*'
        r'[\w<>\[\],\s]+\s+(\w+)\s*\('
    )
    py_method = re.compile(r'^\s*(?:async\s+)?def\s+(\w+)\s*\(')

    try:
        with open(abs_file_path, encoding="utf-8", errors="replace") as f:
            all_lines = f.readlines()
    except (OSError, IOError):
        return None

    search_start = min(line_start - 1, len(all_lines) - 1)
    for i in range(search_start, max(0, search_start - 50), -1):
        line = all_lines[i]
        m = java_method.match(line)
        if m:
            method = m.group(2)
            if method not in ("class", "interface", "enum", "return", "if", "for", "while"):
                return method
        m = py_method.match(line)
        if m:
            return m.group(1)

    return None


def _cleanup(path: str) -> None:
    """Remove a file or directory, logging on failure."""
    p = Path(path)
    try:
        if p.is_dir():
            shutil.rmtree(str(p), ignore_errors=True)
        elif p.exists():
            p.unlink()
    except Exception as exc:
        logger.warning("CodeQL cleanup failed for %s: %s", path, exc)

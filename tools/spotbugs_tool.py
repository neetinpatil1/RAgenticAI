"""
tools/spotbugs_tool.py
=======================
SpotBugs + FindSecBugs Java bytecode SAST.

Finds security issues in compiled .class files that Semgrep (source-only) misses:
  - Bytecode-only bugs (Lombok-generated, annotation processors, generated classes)
  - FindSecBugs 130+ security rules: injection, insecure crypto, XXE, SSRF,
    deserialization, hardcoded secrets, path traversal, SQL injection, XSS

Prerequisites (auto-downloaded to tools/vendor/ on first run):
  - SpotBugs JAR   — github.com/spotbugs/spotbugs/releases
  - FindSecBugs    — github.com/find-sec-bugs/find-sec-bugs/releases

Build requirement:
  - Needs compiled .class files in target/classes/ (Maven) or build/classes/ (Gradle)
  - If not present, attempts `mvn compile -q` silently
  - If build fails, logs warning and returns [] — never blocks the scan
"""
from __future__ import annotations

import asyncio
import logging
import os
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# FindSecBugs CWE/OWASP mappings for the most common bug patterns
_BUG_PATTERN_MAP: dict[str, dict] = {
    # SQL Injection
    "SQL_INJECTION":              {"cwe": "CWE-89",  "owasp": "A03:2021", "sev": "HIGH"},
    "SQL_INJECTION_HIBERNATE":    {"cwe": "CWE-89",  "owasp": "A03:2021", "sev": "HIGH"},
    "SQL_INJECTION_JPA":          {"cwe": "CWE-89",  "owasp": "A03:2021", "sev": "HIGH"},
    "SQL_INJECTION_SPRING_JDBC":  {"cwe": "CWE-89",  "owasp": "A03:2021", "sev": "HIGH"},
    # Command Injection
    "COMMAND_INJECTION":          {"cwe": "CWE-78",  "owasp": "A03:2021", "sev": "CRITICAL"},
    "SCALA_COMMAND_INJECTION":    {"cwe": "CWE-78",  "owasp": "A03:2021", "sev": "CRITICAL"},
    # Path Traversal
    "PATH_TRAVERSAL_IN":          {"cwe": "CWE-22",  "owasp": "A01:2021", "sev": "HIGH"},
    "PATH_TRAVERSAL_OUT":         {"cwe": "CWE-22",  "owasp": "A01:2021", "sev": "HIGH"},
    # XSS
    "XSS_REQUEST_PARAMETER_TO_SEND_ERROR": {"cwe": "CWE-79", "owasp": "A03:2021", "sev": "HIGH"},
    "XSS_REQUEST_PARAMETER_TO_JSP_WRITER": {"cwe": "CWE-79", "owasp": "A03:2021", "sev": "HIGH"},
    "XSS_JSP_PRINT":              {"cwe": "CWE-79",  "owasp": "A03:2021", "sev": "HIGH"},
    "XSS_SERVLET":                {"cwe": "CWE-79",  "owasp": "A03:2021", "sev": "HIGH"},
    # Deserialization
    "OBJECT_DESERIALIZATION":     {"cwe": "CWE-502", "owasp": "A08:2021", "sev": "HIGH"},
    "JACKSON_UNSAFE_DESERIALIZATION": {"cwe": "CWE-502", "owasp": "A08:2021", "sev": "HIGH"},
    # Insecure Crypto
    "WEAK_MESSAGE_DIGEST_MD5":    {"cwe": "CWE-327", "owasp": "A02:2021", "sev": "MEDIUM"},
    "WEAK_MESSAGE_DIGEST_SHA1":   {"cwe": "CWE-327", "owasp": "A02:2021", "sev": "MEDIUM"},
    "DES_USAGE":                  {"cwe": "CWE-327", "owasp": "A02:2021", "sev": "HIGH"},
    "TDES_USAGE":                 {"cwe": "CWE-327", "owasp": "A02:2021", "sev": "MEDIUM"},
    "RSA_NO_PADDING":             {"cwe": "CWE-780", "owasp": "A02:2021", "sev": "HIGH"},
    "CIPHER_INTEGRITY":           {"cwe": "CWE-353", "owasp": "A02:2021", "sev": "HIGH"},
    "ECB_MODE":                   {"cwe": "CWE-327", "owasp": "A02:2021", "sev": "HIGH"},
    "STATIC_IV":                  {"cwe": "CWE-329", "owasp": "A02:2021", "sev": "HIGH"},
    # Insecure Random
    "PREDICTABLE_RANDOM":         {"cwe": "CWE-330", "owasp": "A02:2021", "sev": "MEDIUM"},
    "PREDICTABLE_RANDOM_SCALA":   {"cwe": "CWE-330", "owasp": "A02:2021", "sev": "MEDIUM"},
    # Hardcoded Passwords
    "HARD_CODE_PASSWORD":         {"cwe": "CWE-259", "owasp": "A07:2021", "sev": "HIGH"},
    "HARD_CODE_KEY":              {"cwe": "CWE-321", "owasp": "A02:2021", "sev": "HIGH"},
    # SSRF
    "URLCONNECTION_SSRF_FD":      {"cwe": "CWE-918", "owasp": "A10:2021", "sev": "HIGH"},
    "SERVER_SIDE_REQUEST_FORGERY":{"cwe": "CWE-918", "owasp": "A10:2021", "sev": "HIGH"},
    # XXE
    "XXE_SAXPARSER":              {"cwe": "CWE-611", "owasp": "A05:2021", "sev": "HIGH"},
    "XXE_XMLREADER":              {"cwe": "CWE-611", "owasp": "A05:2021", "sev": "HIGH"},
    "XXE_DOCUMENT":               {"cwe": "CWE-611", "owasp": "A05:2021", "sev": "HIGH"},
    # LDAP Injection
    "LDAP_INJECTION":             {"cwe": "CWE-90",  "owasp": "A03:2021", "sev": "HIGH"},
    # CSRF
    "SPRING_CSRF_PROTECTION_DISABLED": {"cwe": "CWE-352", "owasp": "A01:2021", "sev": "HIGH"},
    # Trust Boundary
    "TRUST_BOUNDARY_VIOLATION":   {"cwe": "CWE-501", "owasp": "A04:2021", "sev": "MEDIUM"},
}

_SEVERITY_MAP = {
    "1": "HIGH",    # High priority in SpotBugs (1=high, 2=normal, 3=low)
    "2": "MEDIUM",
    "3": "LOW",
}

# Vendor dir for SpotBugs/FindSecBugs
_VENDOR_DIR     = Path(__file__).parent / "vendor"
_FINDSEC_DIR    = _VENDOR_DIR / "findsecbugs-cli"
_FINDSEC_SH     = _FINDSEC_DIR / "findsecbugs.sh"
_SPOTBUGS_JAR   = _FINDSEC_DIR / "lib" / "spotbugs-4.9.3.jar"   # for _jars_available() check
_FINDSEC_JAR    = _FINDSEC_DIR / "lib" / "findsecbugs-plugin-1.14.0.jar"

# FindSecBugs CLI zip bundles SpotBugs + all dependencies + findsecbugs.sh runner
_FINDSEC_CLI_URL = "https://github.com/find-sec-bugs/find-sec-bugs/releases/download/version-1.14.0/findsecbugs-cli-1.14.0.zip"


@dataclass
class SpotBugsFinding:
    rule_id:        str
    cwe_id:         Optional[str]
    severity:       str
    file_path:      str
    line_start:     Optional[int]
    line_end:       Optional[int]
    class_name:     Optional[str]
    method_name:    Optional[str]
    message:        str
    owasp_category: Optional[str]
    source:         str = "findsecbugs"
    framework:      str = "java"


class SpotBugsTool:
    """
    Runs SpotBugs + FindSecBugs on compiled Java bytecode.
    Returns [] and logs a warning if SpotBugs is unavailable or build fails.
    """

    def __init__(self, timeout: int = 300):
        self.timeout = timeout

    async def scan(self, scan_path: str) -> list[SpotBugsFinding]:
        root = Path(scan_path).resolve()

        # Step 1: Check JAR availability
        if not self._jars_available():
            if not await self._download_jars():
                logger.warning("SpotBugs | JARs unavailable — skipping Java bytecode scan")
                return []

        # Step 2: Find or build bytecode
        classes_dir = self._find_classes_dir(root)
        if classes_dir is None:
            logger.info("SpotBugs | No compiled classes found — attempting mvn compile")
            classes_dir = await self._try_compile(root)
        if classes_dir is None:
            logger.warning("SpotBugs | No bytecode available — skipping (not a Java project or build required)")
            return []

        logger.info("SpotBugs | scanning classes_dir=%s", classes_dir)

        # Step 3: Run SpotBugs + FindSecBugs
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
            output_file = f.name

        try:
            findings = await self._run_spotbugs(root, classes_dir, output_file)
            logger.info("SpotBugs | complete | findings=%d", len(findings))
            return findings
        finally:
            try:
                os.unlink(output_file)
            except OSError:
                pass

    def _jars_available(self) -> bool:
        return _FINDSEC_SH.exists() and _SPOTBUGS_JAR.exists() and _FINDSEC_JAR.exists()

    async def _download_jars(self) -> bool:
        """
        Download FindSecBugs CLI zip which bundles both spotbugs.jar and
        findsecbugs-plugin.jar. One download provides everything needed.
        """
        _VENDOR_DIR.mkdir(parents=True, exist_ok=True)
        import httpx, io, zipfile

        if self._jars_available():
            return True

        _FINDSEC_DIR.mkdir(parents=True, exist_ok=True)
        logger.info("SpotBugs | downloading FindSecBugs CLI (includes SpotBugs + all deps)...")
        try:
            async with httpx.AsyncClient(timeout=180, follow_redirects=True) as client:
                r = await client.get(_FINDSEC_CLI_URL)
                if r.status_code != 200:
                    logger.warning("SpotBugs | download failed: HTTP %d", r.status_code)
                    return False

            # Extract entire zip into _FINDSEC_DIR to preserve lib/ directory structure
            with zipfile.ZipFile(io.BytesIO(r.content)) as z:
                z.extractall(str(_FINDSEC_DIR))

            # Fix Windows CRLF line endings and make executable
            if _FINDSEC_SH.exists():
                raw = _FINDSEC_SH.read_bytes()
                _FINDSEC_SH.write_bytes(raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n"))
                _FINDSEC_SH.chmod(0o755)

            if not self._jars_available():
                logger.warning("SpotBugs | extraction complete but expected files missing")
                return False

            logger.info("SpotBugs | FindSecBugs CLI ready at %s", _FINDSEC_DIR)
            return True
        except Exception as exc:
            logger.warning("SpotBugs | download error: %s", exc)
            return False

    def _find_classes_dir(self, root: Path) -> Optional[Path]:
        """Find compiled .class files. Checks Maven target/ and Gradle build/ layouts."""
        candidates = [
            root / "target" / "classes",
            root / "build" / "classes" / "java" / "main",
            root / "build" / "classes" / "kotlin" / "main",
            root / "out" / "production" / "classes",
        ]
        for c in candidates:
            if c.exists() and any(c.rglob("*.class")):
                return c
        # Multi-module Maven: look for any target/classes under subdirs
        for p in root.rglob("target/classes"):
            if p.is_dir() and any(p.rglob("*.class")):
                return p
        return None

    async def _try_compile(self, root: Path) -> Optional[Path]:
        """
        Attempt to build the project. Strategy:
          1. `mvn compile -q -DskipTests` (standard Maven build)
          2. If step 1 fails (e.g. javax.servlet.annotation missing on Java 9+),
             fall back to direct javac compilation with the correct servlet-api jar.
        """
        pom = root / "pom.xml"
        if not pom.exists():
            return None
        mvn = shutil.which("mvn")
        if not mvn:
            return None

        # ── Pass 1: standard Maven compile ────────────────────────────────────
        try:
            proc = await asyncio.create_subprocess_exec(
                mvn, "compile", "-q", "-DskipTests",
                "-Dmaven.compiler.source=11", "-Dmaven.compiler.target=11",
                cwd=str(root),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=180)
            if proc.returncode == 0:
                return self._find_classes_dir(root)
            err_text = stderr.decode("utf-8", errors="replace")
            # Check if failure is a known Java EE classpath issue
            if "javax.servlet" not in err_text and "package javax" not in err_text:
                logger.warning("SpotBugs | mvn compile failed: %s", err_text[-300:])
                return None
            logger.info("SpotBugs | mvn compile failed (missing servlet API) — trying javac fallback")
        except asyncio.TimeoutError:
            logger.warning("SpotBugs | mvn compile timed out")
            return None
        except Exception as exc:
            logger.warning("SpotBugs | mvn compile error: %s", exc)
            return None

        # ── Pass 2: javac fallback with servlet-api 3.1.0 ────────────────────
        # Resolve full compile classpath via Maven, then compile with javac
        # adding the newer servlet-api jar that provides @WebServlet.
        return await self._try_javac_compile(root, mvn)

    async def _try_javac_compile(self, root: Path, mvn: str) -> Optional[Path]:
        """Direct javac compilation for Java EE projects that need servlet-api 3.1+."""
        javac = shutil.which("javac")
        if not javac:
            return None

        # Ensure javax.servlet-api 3.1.0 is in the local Maven repo
        await self._ensure_servlet_api(mvn)

        servlet_jar = Path.home() / ".m2/repository/javax/servlet/javax.servlet-api/3.1.0/javax.servlet-api-3.1.0.jar"

        # Build Maven dependency classpath
        cp_file = root / "target" / ".spotbugs-cp.txt"
        cp_file.parent.mkdir(parents=True, exist_ok=True)
        try:
            proc = await asyncio.create_subprocess_exec(
                mvn, "dependency:build-classpath",
                f"-Dmdep.outputFile={cp_file}",
                "-q",
                cwd=str(root),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=60)
        except Exception as exc:
            logger.warning("SpotBugs | dependency:build-classpath failed: %s", exc)
            return None

        classpath = cp_file.read_text().strip() if cp_file.exists() else ""
        if servlet_jar.exists():
            classpath = f"{classpath}:{servlet_jar}" if classpath else str(servlet_jar)

        # Collect source files
        sources = list(root.rglob("src/main/java/**/*.java"))
        if not sources:
            sources = list((root / "src" / "main" / "java").rglob("*.java")) if (root / "src" / "main" / "java").exists() else []
        if not sources:
            return None

        sources_file = root / "target" / ".spotbugs-sources.txt"
        sources_file.write_text("\n".join(str(s) for s in sources))

        classes_dir = root / "target" / "classes"
        classes_dir.mkdir(parents=True, exist_ok=True)

        try:
            cmd = [javac, "-source", "11", "-target", "11"]
            if classpath:
                cmd += ["-cp", classpath]
            cmd += ["-d", str(classes_dir), f"@{sources_file}"]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(root),
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=180)
            if proc.returncode != 0:
                err = stderr.decode("utf-8", errors="replace")
                logger.warning("SpotBugs | javac fallback failed: %s", err[-200:])
                return None
            logger.info("SpotBugs | javac fallback succeeded")
            return self._find_classes_dir(root)
        except asyncio.TimeoutError:
            logger.warning("SpotBugs | javac fallback timed out")
            return None
        except Exception as exc:
            logger.warning("SpotBugs | javac fallback error: %s", exc)
            return None

    async def _ensure_servlet_api(self, mvn: str) -> None:
        """Download javax.servlet-api 3.1.0 to local Maven repo if not present."""
        jar = Path.home() / ".m2/repository/javax/servlet/javax.servlet-api/3.1.0/javax.servlet-api-3.1.0.jar"
        if jar.exists():
            return
        try:
            proc = await asyncio.create_subprocess_exec(
                mvn, "dependency:get",
                "-Dartifact=javax.servlet:javax.servlet-api:3.1.0:jar",
                "-q",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=60)
        except Exception as exc:
            logger.debug("SpotBugs | servlet-api download attempt: %s", exc)

    async def _run_spotbugs(
        self, root: Path, classes_dir: Path, output_file: str
    ) -> list[SpotBugsFinding]:
        """
        Run SpotBugs + FindSecBugs via the findsecbugs.sh CLI runner.
        The CLI runner handles the full classpath (all lib/ JARs) automatically.
        """
        if not _FINDSEC_SH.exists():
            logger.warning("SpotBugs | findsecbugs.sh not found")
            return []

        # findsecbugs.sh [options] <classes_dir>
        # -xml:withMessages  — XML output with human-readable messages
        # -effort:max        — most thorough analysis
        # -low               — report all priority levels (1=high, 2=normal, 3=low)
        cmd = [
            str(_FINDSEC_SH),
            "-xml:withMessages",
            "-effort:max",
            "-low",
            "-output", output_file,
            str(classes_dir),
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(root),
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
            rc = proc.returncode
            # SpotBugs exits: 0=no bugs, 1=bugs found, 2=error
            if rc == 2:
                err = stderr.decode("utf-8", errors="replace")
                logger.warning("SpotBugs | error exit: %s", err[-300:])
                return []
            logger.debug("SpotBugs | exit code=%d stdout=%s", rc,
                         stdout.decode("utf-8", errors="replace")[-100:])
        except asyncio.TimeoutError:
            logger.warning("SpotBugs | timed out after %ds", self.timeout)
            return []
        except Exception as exc:
            logger.warning("SpotBugs | run error: %s", exc)
            return []

        return self._parse_xml(output_file, root)

    def _parse_xml(self, xml_path: str, root: Path) -> list[SpotBugsFinding]:
        """Parse SpotBugs XML BugCollection output."""
        findings: list[SpotBugsFinding] = []
        try:
            tree = ET.parse(xml_path)
        except Exception as exc:
            logger.warning("SpotBugs | XML parse error: %s", exc)
            return findings

        bug_collection = tree.getroot()
        # Build source file → relative path index from <Project> / <SrcDir>
        src_dirs: list[str] = []
        project_el = bug_collection.find("Project")
        if project_el is not None:
            for sd in project_el.findall("SrcDir"):
                if sd.text:
                    src_dirs.append(sd.text.strip())

        for bug in bug_collection.findall("BugInstance"):
            pattern   = bug.get("type", "UNKNOWN")
            priority  = bug.get("priority", "2")
            category  = bug.get("category", "")

            # Only keep security-relevant categories and FindSecBugs patterns
            if category not in ("SECURITY", "MALICIOUS_CODE") and pattern not in _BUG_PATTERN_MAP:
                continue

            meta    = _BUG_PATTERN_MAP.get(pattern, {})
            cwe     = meta.get("cwe")
            owasp   = meta.get("owasp")
            sev     = meta.get("sev") or _SEVERITY_MAP.get(priority, "MEDIUM")

            # Get source location
            src_el  = bug.find("SourceLine")
            file_path = ""
            line_start: Optional[int] = None
            line_end:   Optional[int] = None
            if src_el is not None:
                source_file = src_el.get("sourcefile", "")
                source_path = src_el.get("sourcepath", "")
                # Try to resolve relative to scan root
                file_path = self._resolve_source_path(root, src_dirs, source_path or source_file)
                try:
                    start_str = src_el.get("start")
                    end_str   = src_el.get("end")
                    if start_str:
                        line_start = int(start_str)
                    if end_str:
                        line_end = int(end_str)
                except (ValueError, TypeError):
                    pass

            # Class / method
            class_el  = bug.find("Class")
            method_el = bug.find("Method")
            class_name  = class_el.get("classname")  if class_el  is not None else None
            method_name = method_el.get("name")       if method_el is not None else None

            # Human-readable message
            msg_el = bug.find("LongMessage")
            if msg_el is None:
                msg_el = bug.find("ShortMessage")
            message = (msg_el.text or pattern).strip() if msg_el is not None else pattern

            findings.append(SpotBugsFinding(
                rule_id=f"findsecbugs/{pattern}",
                cwe_id=cwe,
                severity=sev,
                file_path=file_path or (class_name or "unknown").replace(".", "/") + ".java",
                line_start=line_start,
                line_end=line_end,
                class_name=class_name,
                method_name=method_name,
                message=message,
                owasp_category=owasp,
            ))

        return findings

    def _resolve_source_path(self, root: Path, src_dirs: list[str], source_path: str) -> str:
        """Resolve a source file path to a project-relative path."""
        if not source_path:
            return ""
        # Direct relative-to-root check
        candidate = root / source_path
        if candidate.exists():
            return source_path
        # Try known src dirs
        for src_dir in src_dirs:
            candidate = Path(src_dir) / source_path
            if candidate.exists():
                try:
                    return str(candidate.relative_to(root))
                except ValueError:
                    return source_path
        # Last resort: just use source_path as-is
        return source_path

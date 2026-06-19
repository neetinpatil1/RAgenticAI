"""
tools/sca_tool.py
==================
Software Composition Analysis (SCA) — finds known vulnerabilities in
third-party dependencies.

Supported ecosystems:
  - Python  — pip-audit (uses OSV / PyPI Advisory Database)
  - Node.js — npm audit (uses npm Advisory Database)
  - Maven   — pom.xml parsing + OSV API lookup

Air-gap note: pip-audit and npm audit require internet for CVE data.
Phase 2+: replace with locally-cached NVD feed.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

_SKIP_DIRS    = {".git", "node_modules", ".venv", "venv", "__pycache__", "target", "build", "dist"}
_OSV_BATCH    = "https://api.osv.dev/v1/querybatch"
_OSV_VULN     = "https://api.osv.dev/v1/vulns"   # GET /{id} for full details


@dataclass
class DependencyFinding:
    package_name:      str
    installed_version: Optional[str]
    fixed_version:     Optional[str]
    vulnerability_id:  str
    severity:          str
    description:       str
    ecosystem:         str    # python | npm | maven
    file_path:         str    # relative path to manifest


class SCATool:
    """Runs dependency vulnerability scanning across multiple ecosystems."""

    def __init__(self, timeout: int = 120):
        self.timeout = timeout

    async def scan(self, scan_path: str) -> tuple[list[DependencyFinding], dict]:
        root = Path(scan_path).resolve()
        stats = {"python": 0, "npm": 0, "maven": 0, "total_packages": 0}

        results = await asyncio.gather(
            self._scan_python(root, stats),
            self._scan_npm(root, stats),
            self._scan_maven(root, stats),
            return_exceptions=True,
        )

        all_findings: list[DependencyFinding] = []
        for r in results:
            if isinstance(r, list):
                all_findings.extend(r)
            elif isinstance(r, Exception):
                logger.warning("SCA ecosystem error: %s", r)

        logger.info(
            "SCA complete | findings=%d python_pkgs=%d npm_pkgs=%d maven_pkgs=%d",
            len(all_findings), stats["python"], stats["npm"], stats["maven"],
        )
        return all_findings, stats

    # -----------------------------------------------------------------------
    # Python — pip-audit
    # -----------------------------------------------------------------------

    async def _scan_python(self, root: Path, stats: dict) -> list[DependencyFinding]:
        findings: list[DependencyFinding] = []
        req_files = [
            p for p in root.rglob("requirements*.txt")
            if not any(d in _SKIP_DIRS for d in p.parts)
        ]
        if not req_files:
            return findings

        pip_audit = self._find_pip_audit()
        if not pip_audit:
            logger.warning("pip-audit not found — Python SCA skipped")
            return findings

        for req_file in req_files:
            rel = str(req_file.relative_to(root))
            try:
                proc = await asyncio.create_subprocess_exec(
                    pip_audit, "-r", str(req_file),
                    "--format", "json", "--no-deps",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
                raw = stdout.decode("utf-8", errors="replace").strip()
                if not raw:
                    continue
                data = json.loads(raw)
                deps = data.get("dependencies", [])
                stats["python"]         += len(deps)
                stats["total_packages"] += len(deps)

                for dep in deps:
                    for vuln in dep.get("vulns", []):
                        aliases    = vuln.get("aliases", [])
                        vuln_id    = vuln.get("id", "") or (aliases[0] if aliases else "UNKNOWN")
                        fix_vers   = vuln.get("fix_versions", [])
                        fixed      = fix_vers[0] if fix_vers else None
                        findings.append(DependencyFinding(
                            package_name=dep.get("name", "unknown"),
                            installed_version=dep.get("version"),
                            fixed_version=fixed,
                            vulnerability_id=vuln_id,
                            severity=self._osv_severity(vuln),
                            description=(vuln.get("description") or "")[:500],
                            ecosystem="python",
                            file_path=rel,
                        ))
            except asyncio.TimeoutError:
                logger.warning("pip-audit timed out for %s", req_file)
            except Exception as exc:
                logger.warning("pip-audit error for %s: %s", req_file, exc)

        return findings

    def _find_pip_audit(self) -> Optional[str]:
        venv_bin = Path(__file__).parent.parent / ".venv" / "bin" / "pip-audit"
        if venv_bin.exists():
            return str(venv_bin)
        return shutil.which("pip-audit")

    # -----------------------------------------------------------------------
    # Node.js — npm audit
    # -----------------------------------------------------------------------

    async def _scan_npm(self, root: Path, stats: dict) -> list[DependencyFinding]:
        findings: list[DependencyFinding] = []
        npm = shutil.which("npm")
        if not npm:
            logger.warning("npm not found — Node.js SCA skipped")
            return findings

        pkg_files = [
            p for p in root.rglob("package.json")
            if "node_modules" not in str(p)
            and not any(d in _SKIP_DIRS for d in p.parts)
        ]

        for pkg_file in pkg_files:
            pkg_dir = pkg_file.parent
            rel     = str(pkg_file.relative_to(root))

            if not (pkg_dir / "node_modules").exists():
                logger.debug("Skipping npm audit for %s — no node_modules", rel)
                continue

            try:
                proc = await asyncio.create_subprocess_exec(
                    npm, "audit", "--json",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=str(pkg_dir),
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
                raw = stdout.decode("utf-8", errors="replace").strip()
                if not raw:
                    continue
                data = json.loads(raw)

                deps_count = len(data.get("dependencies", {}) or {})
                stats["npm"]            += deps_count
                stats["total_packages"] += deps_count

                for pkg_name, info in (data.get("vulnerabilities") or {}).items():
                    sev_raw  = (info.get("severity") or "LOW").upper()
                    severity = {"CRITICAL": "CRITICAL", "HIGH": "HIGH",
                                "MODERATE": "MEDIUM", "LOW": "LOW",
                                "INFO": "LOW"}.get(sev_raw, "LOW")
                    via = info.get("via", [])
                    description = ""
                    vuln_id     = "NPM-ADVISORY"
                    if via and isinstance(via[0], dict):
                        description = (via[0].get("title") or "")[:500]
                        url         = via[0].get("url", "")
                        vuln_id     = url.split("/")[-1] if url else "NPM-ADVISORY"

                    fix_available = info.get("fixAvailable")
                    fixed_version = None
                    if isinstance(fix_available, dict):
                        fixed_version = fix_available.get("version")

                    findings.append(DependencyFinding(
                        package_name=pkg_name,
                        installed_version=info.get("range"),
                        fixed_version=fixed_version,
                        vulnerability_id=vuln_id,
                        severity=severity,
                        description=description,
                        ecosystem="npm",
                        file_path=rel,
                    ))
            except asyncio.TimeoutError:
                logger.warning("npm audit timed out for %s", pkg_dir)
            except Exception as exc:
                logger.warning("npm audit error for %s: %s", pkg_dir, exc)

        return findings

    # -----------------------------------------------------------------------
    # Maven — pom.xml + OSV API
    # -----------------------------------------------------------------------

    async def _scan_maven(self, root: Path, stats: dict) -> list[DependencyFinding]:
        findings: list[DependencyFinding] = []
        pom_files = [
            p for p in root.rglob("pom.xml")
            if not any(d in _SKIP_DIRS for d in p.parts)
        ]
        if not pom_files:
            return findings

        ns = {"m": "http://maven.apache.org/POM/4.0.0"}
        packages: list[tuple[str, str, str, str]] = []  # group, artifact, version, rel_path
        seen: set[tuple[str, str, str]] = set()  # dedup across multi-module poms

        for pom in pom_files:
            rel = str(pom.relative_to(root))
            try:
                tree = ET.parse(pom)
                root_el = tree.getroot()

                # Collect <properties> from this pom so we can resolve ${...} refs
                props: dict[str, str] = {}
                props_el = root_el.find("m:properties", ns) or root_el.find("properties")
                if props_el is not None:
                    for child in props_el:
                        tag = child.tag.split("}")[-1]  # strip namespace
                        if child.text:
                            props[tag] = child.text.strip()

                def resolve(value: str) -> str:
                    """Substitute ${prop} references using this pom's <properties>."""
                    if not value or not value.startswith("${"):
                        return value
                    key = value[2:-1]  # strip ${ and }
                    return props.get(key, "")  # empty string → will be filtered below

                for dep in (root_el.findall(".//m:dependency", ns) or root_el.findall(".//dependency")):
                    group    = self._xml_text(dep, "groupId",    ns)
                    artifact = self._xml_text(dep, "artifactId", ns)
                    raw_ver  = self._xml_text(dep, "version",    ns)

                    if not group or not artifact:
                        continue

                    # Resolve property references; skip if version is unknown
                    version = resolve(raw_ver) if raw_ver else None
                    if not version:
                        continue

                    key = (group, artifact, version)
                    if key in seen:
                        continue
                    seen.add(key)
                    packages.append((group, artifact, version, rel))
            except Exception as exc:
                logger.debug("pom.xml parse error %s: %s", rel, exc)

        stats["maven"]          += len(packages)
        stats["total_packages"] += len(packages)
        logger.info("SCA Maven | pom_files=%d resolved_packages=%d", len(pom_files), len(packages))
        if not packages:
            return findings

        try:
            findings = await self._query_osv_batch(packages, "Maven")
        except Exception as exc:
            logger.warning("OSV Maven query failed: %s", exc)

        return findings

    async def _query_osv_batch(
        self,
        packages: list[tuple[str, str, str, str]],
        ecosystem: str,
    ) -> list[DependencyFinding]:
        """
        Two-step OSV lookup:
          Step 1 — POST /v1/querybatch  finds which packages are affected.
                   The batch response only returns {id, modified} — no summary/details/ranges.
          Step 2 — GET  /v1/vulns/{id}  fetches full details for each unique vuln ID.
        """
        findings: list[DependencyFinding] = []
        eco_lower = ecosystem.lower()
        batch_size = 50

        # Step 1: collect unique vuln IDs and which package they affect
        vuln_to_pkg: dict[str, tuple[str, str, str, str]] = {}

        async with httpx.AsyncClient(timeout=30) as client:
            for i in range(0, len(packages), batch_size):
                batch = packages[i : i + batch_size]
                queries = [
                    {
                        "version": version,
                        "package": {
                            "name":      f"{group}:{artifact}" if eco_lower == "maven" else artifact,
                            "ecosystem": ecosystem,
                        },
                    }
                    for group, artifact, version, _ in batch
                ]
                try:
                    resp = await client.post(_OSV_BATCH, json={"queries": queries})
                    if resp.status_code != 200:
                        continue
                    for idx, result in enumerate(resp.json().get("results", [])):
                        for vuln in result.get("vulns", []):
                            vid = vuln.get("id", "")
                            if vid and vid not in vuln_to_pkg:
                                vuln_to_pkg[vid] = batch[idx]
                except Exception as exc:
                    logger.warning("OSV batch query error: %s", exc)

            # Step 2: fetch full details (summary, details, fixed version) per vuln ID
            for vid, (group, artifact, version, rel) in vuln_to_pkg.items():
                try:
                    r = await client.get(f"{_OSV_VULN}/{vid}", timeout=10)
                    if r.status_code != 200:
                        continue
                    vuln = r.json()

                    # Extract earliest fixed version across all affected ranges
                    fixed = None
                    for affected in vuln.get("affected", []):
                        for rng in affected.get("ranges", []):
                            for evt in rng.get("events", []):
                                if "fixed" in evt:
                                    fixed = evt["fixed"]
                                    break

                    # Prefer summary; fall back to first 400 chars of details
                    desc = (vuln.get("summary") or "").strip()
                    if not desc:
                        desc = (vuln.get("details") or "").strip()[:400]

                    findings.append(DependencyFinding(
                        package_name=f"{group}:{artifact}" if eco_lower == "maven" else artifact,
                        installed_version=version,
                        fixed_version=fixed,
                        vulnerability_id=vid,
                        severity=self._osv_severity(vuln),
                        description=desc[:500],
                        ecosystem=eco_lower,
                        file_path=rel,
                    ))
                except Exception as exc:
                    logger.warning("OSV vuln detail fetch error %s: %s", vid, exc)

        return findings

    @staticmethod
    def _xml_text(element, tag: str, ns: dict) -> Optional[str]:
        # Python's ElementTree C-extension lazily populates .text — find() can
        # return an element with .text=None until its children are iterated.
        # Iterate directly and match by local name to reliably get the text value.
        for child in element:
            local = child.tag.split("}")[-1] if "}" in child.tag else child.tag
            if local == tag and child.text:
                return child.text.strip()
        return None

    @staticmethod
    def _osv_severity(vuln: dict) -> str:
        # 1. Try database_specific.severity (GHSA advisories)
        db  = vuln.get("database_specific") or {}
        raw = (db.get("severity") or "").upper()
        if raw:
            return {"CRITICAL": "CRITICAL", "HIGH": "HIGH",
                    "MODERATE": "MEDIUM",   "MEDIUM": "MEDIUM",
                    "LOW": "LOW"}.get(raw, "MEDIUM")
        # 2. Try top-level severity[] (CVSS scores from OSV)
        for sev in (vuln.get("severity") or []):
            score_type = (sev.get("type") or "").upper()
            score = sev.get("score", "")
            # CVSS v3 base score: extract numeric value from vector or score string
            if "CVSS" in score_type and score:
                # score may be a vector like "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                # Extract base score by checking the impact components
                # Simpler: parse the score string as float if it's numeric
                try:
                    numeric = float(score)
                    if numeric >= 9.0: return "CRITICAL"
                    if numeric >= 7.0: return "HIGH"
                    if numeric >= 4.0: return "MEDIUM"
                    return "LOW"
                except ValueError:
                    # It's a vector string — count critical indicators
                    if any(x in score for x in ("C:H/I:H", "C:H/I:H/A:H")): return "CRITICAL"
                    if "C:H" in score or "I:H" in score:                      return "HIGH"
        return "MEDIUM"

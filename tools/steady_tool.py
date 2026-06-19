"""
tools/steady_tool.py
=====================
Eclipse Steady (SAP) — call-graph-based CVE reachability for Java.

Unlike our Phase 1 heuristic reachability (JAR bytecode string search + import scan),
Steady traces the *actual execution path* from the application's entry point to
the vulnerable library method. Evidence is a full call chain:
  App.m() → Parent.foo() → VulnerableClass.vuln()

Integration:
  - Steady runs as a local server (Docker or JAR). Default: localhost:8033
  - This tool calls the Steady REST API to:
      1. Register the application (POST /backend/apps)
      2. Trigger reachability analysis (POST /backend/apps/{gid}/{aid}/{ver}/reachability)
      3. Poll for completion (GET  /backend/apps/{gid}/{aid}/{ver}/reachability)
      4. Fetch CVE verdicts (GET  /backend/apps/{gid}/{aid}/{ver}/vulndeps)
  - If the Steady server is unreachable (GET /health fails), returns {} silently.
    The reachability workflow falls back to Phase 1 heuristic results.

Setup:
  docker run -p 8033:8033 eclipse/steady:latest
  (or see docs/steady_setup.md for JAR-only setup)
"""
from __future__ import annotations

import asyncio
import logging
import os
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

_STEADY_URL = os.getenv("STEADY_URL", "http://localhost:8033")
_STEADY_TIMEOUT = int(os.getenv("STEADY_TIMEOUT", "300"))   # 5 min max for analysis

# Poll interval and max polls for reachability analysis completion
_POLL_INTERVAL = 10   # seconds
_MAX_POLLS     = 30   # 5 min total

from dataclasses import dataclass

@dataclass
class SteadyVerdict:
    vulnerability_id:  str
    package_name:      str
    verdict:           str          # REACHABLE | NOT_REACHABLE | UNKNOWN
    call_chain:        Optional[str]  # Full call chain evidence from Steady
    confidence:        float


class SteadyTool:
    """
    Calls Eclipse Steady REST API to get call-graph-based reachability verdicts.
    Returns {} (empty dict mapping vuln_id → verdict) if Steady is unavailable.
    """

    def __init__(self):
        self._base = _STEADY_URL.rstrip("/")

    async def is_available(self) -> bool:
        """Quick health check. False if Steady server is not reachable."""
        try:
            async with httpx.AsyncClient(timeout=3) as client:
                # Steady doesn't have /health — use /backend/spaces which always returns 200
                r = await client.get(f"{self._base}/backend/spaces")
                return r.status_code == 200
        except Exception:
            return False

    async def analyze(
        self,
        scan_path: str,
        run_id: str,
    ) -> dict[str, SteadyVerdict]:
        """
        Register the app, trigger reachability analysis, return per-CVE verdicts.
        Returns {} if Steady is unavailable or analysis fails.
        """
        root = Path(scan_path).resolve()

        if not await self.is_available():
            logger.info("Steady | server not available at %s — skipping", self._base)
            return {}

        # Read app coordinates from pom.xml
        coords = self._read_pom_coords(root)
        if not coords:
            logger.info("Steady | no pom.xml found — Steady only supports Maven projects")
            return {}

        group_id, artifact_id, version = coords
        app_key = f"{group_id}/{artifact_id}/{version}"
        logger.info("Steady | START | app=%s run=%s", app_key, run_id)

        try:
            async with httpx.AsyncClient(timeout=30, base_url=self._base) as client:
                # Step 1: Register application
                await self._register_app(client, group_id, artifact_id, version, root)

                # Step 2: Upload dependencies (pom.xml declared deps)
                await self._upload_dependencies(client, group_id, artifact_id, version, root)

                # Step 3: Trigger reachability analysis
                await self._trigger_reachability(client, group_id, artifact_id, version)

                # Step 4: Poll for completion
                completed = await self._wait_for_analysis(client, group_id, artifact_id, version)
                if not completed:
                    logger.warning("Steady | analysis did not complete within timeout | app=%s", app_key)
                    return {}

                # Step 5: Fetch per-CVE verdicts
                verdicts = await self._fetch_verdicts(client, group_id, artifact_id, version)
                logger.info("Steady | COMPLETE | app=%s verdicts=%d", app_key, len(verdicts))
                return verdicts

        except Exception as exc:
            logger.warning("Steady | analysis error: %s", exc)
            return {}

    async def _register_app(
        self,
        client: httpx.AsyncClient,
        group_id: str,
        artifact_id: str,
        version: str,
        root: Path,
    ) -> None:
        payload = {
            "mvnGroup":     group_id,
            "artifact":     artifact_id,
            "version":      version,
            "space":        {"spaceToken": "public"},
            "constructIds": [],
        }
        r = await client.post("/backend/apps", json=payload)
        if r.status_code not in (200, 201, 409):   # 409 = already exists (OK)
            logger.warning("Steady | register app failed: %d %s", r.status_code, r.text[:200])

    async def _upload_dependencies(
        self,
        client: httpx.AsyncClient,
        group_id: str,
        artifact_id: str,
        version: str,
        root: Path,
    ) -> None:
        """Upload declared dependencies from pom.xml so Steady can check reachability."""
        deps = self._parse_pom_deps(root)
        if not deps:
            return
        url = f"/backend/apps/{group_id}/{artifact_id}/{version}/deps"
        r = await client.post(url, json=deps)
        if r.status_code not in (200, 201):
            logger.debug("Steady | upload deps response: %d", r.status_code)

    async def _trigger_reachability(
        self,
        client: httpx.AsyncClient,
        group_id: str,
        artifact_id: str,
        version: str,
    ) -> None:
        url = f"/backend/apps/{group_id}/{artifact_id}/{version}/reachability"
        r = await client.post(url)
        if r.status_code not in (200, 201, 202):
            logger.warning("Steady | trigger reachability failed: %d %s",
                           r.status_code, r.text[:200])

    async def _wait_for_analysis(
        self,
        client: httpx.AsyncClient,
        group_id: str,
        artifact_id: str,
        version: str,
    ) -> bool:
        """Poll until analysis completes or we hit max polls."""
        url = f"/backend/apps/{group_id}/{artifact_id}/{version}/reachability"
        for _ in range(_MAX_POLLS):
            await asyncio.sleep(_POLL_INTERVAL)
            try:
                r = await client.get(url)
                if r.status_code == 200:
                    data = r.json()
                    status = (data.get("status") or "").upper()
                    if status in ("DONE", "COMPLETE", "FINISHED"):
                        return True
                    if status in ("ERROR", "FAILED"):
                        logger.warning("Steady | analysis failed with status=%s", status)
                        return False
            except Exception as exc:
                logger.debug("Steady | poll error: %s", exc)
        return False

    async def _fetch_verdicts(
        self,
        client: httpx.AsyncClient,
        group_id: str,
        artifact_id: str,
        version: str,
    ) -> dict[str, SteadyVerdict]:
        """Fetch per-vulnerability reachability verdicts."""
        url = f"/backend/apps/{group_id}/{artifact_id}/{version}/vulndeps"
        verdicts: dict[str, SteadyVerdict] = {}
        try:
            r = await client.get(url, timeout=30)
            if r.status_code != 200:
                return verdicts
            data = r.json()
            # Steady returns a list of VulnDepItem objects
            for item in (data if isinstance(data, list) else data.get("vulnDeps", [])):
                vuln_id  = item.get("bugId") or item.get("cve") or ""
                pkg      = item.get("dep", {}).get("lib", {}).get("libraryId", {})
                pkg_name = f"{pkg.get('mvnGroup','')}:{pkg.get('artifact','')}" if pkg else ""
                reach_raw = (item.get("reachable") or "").upper()

                verdict_str = {
                    "TRUE":        "REACHABLE",
                    "FALSE":       "NOT_REACHABLE",
                    "UNKNOWN":     "UNKNOWN",
                    "POTENTIALLY": "LIKELY_REACHABLE",
                }.get(reach_raw, "UNKNOWN")

                # Build call chain from constructPath if available
                call_chain = None
                path = item.get("constructPath") or item.get("callPath")
                if path and isinstance(path, list):
                    call_chain = " → ".join(
                        c.get("fqn", str(c)) for c in path
                    )
                elif path and isinstance(path, str):
                    call_chain = path

                confidence = 0.95 if verdict_str in ("REACHABLE", "NOT_REACHABLE") else 0.6

                if vuln_id:
                    verdicts[vuln_id] = SteadyVerdict(
                        vulnerability_id=vuln_id,
                        package_name=pkg_name,
                        verdict=verdict_str,
                        call_chain=call_chain,
                        confidence=confidence,
                    )
        except Exception as exc:
            logger.warning("Steady | fetch verdicts error: %s", exc)
        return verdicts

    def _read_pom_coords(self, root: Path) -> Optional[tuple[str, str, str]]:
        """Read groupId, artifactId, version from root pom.xml."""
        pom = root / "pom.xml"
        if not pom.exists():
            return None
        try:
            tree = ET.parse(pom)
            root_el = tree.getroot()
            ns = {"m": "http://maven.apache.org/POM/4.0.0"}

            def _text(tag: str) -> str:
                el = root_el.find(f"m:{tag}", ns)
                if el is None:
                    el = root_el.find(tag)
                return (el.text or "").strip() if el is not None else ""

            group_id    = _text("groupId")
            artifact_id = _text("artifactId")
            version     = _text("version")

            # Fallback: groupId may be in parent
            if not group_id:
                parent = root_el.find("m:parent", ns) or root_el.find("parent")
                if parent is not None:
                    g = parent.find("m:groupId", ns) or parent.find("groupId")
                    if g is not None and g.text:
                        group_id = g.text.strip()

            if group_id and artifact_id and version:
                return group_id, artifact_id, version
        except Exception as exc:
            logger.debug("Steady | pom parse error: %s", exc)
        return None

    def _parse_pom_deps(self, root: Path) -> list[dict]:
        """Parse pom.xml <dependencies> into Steady dep format."""
        pom = root / "pom.xml"
        if not pom.exists():
            return []
        try:
            tree = ET.parse(pom)
            root_el = tree.getroot()
            ns = {"m": "http://maven.apache.org/POM/4.0.0"}
            deps = []
            for dep in (root_el.findall(".//m:dependency", ns) or root_el.findall(".//dependency")):
                def _t(tag: str) -> str:
                    el = dep.find(f"m:{tag}", ns) or dep.find(tag)
                    return (el.text or "").strip() if el is not None else ""
                g, a, v = _t("groupId"), _t("artifactId"), _t("version")
                if g and a and v and not v.startswith("${"):
                    deps.append({
                        "lib": {
                            "libraryId": {"mvnGroup": g, "artifact": a, "version": v}
                        }
                    })
            return deps
        except Exception:
            return []

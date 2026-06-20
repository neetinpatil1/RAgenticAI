"""
tools/steady_tool.py
=====================
Eclipse Steady (SAP) — call-graph-based CVE reachability for Java.

Unlike our Phase 1 heuristic reachability (JAR bytecode string search + import scan),
Steady traces the *actual execution path* from the application's entry point to
the vulnerable library method. Evidence is a full call chain:
  App.m() → Parent.foo() → VulnerableClass.vuln()

Integration:
  - Steady runs as a local server (Docker). Default: localhost:8033
  - Registration flow (discovered via bytecode analysis of Steady 3.2.5):
      1. For each pom.xml dep: POST /backend/libs (pre-create Library + LibraryId)
         → Must happen BEFORE app registration or dep upload fails (JPA transient error)
      2. POST /backend/apps with "dependencies" list (NOT "libs") + "constructIds"
         → "dependencies" is the correct JSON field name (not "libs")
         → LibraryId uses "group" (NOT "mvnGroup") for the Maven groupId
         → constructIds must be non-empty (else NPE in updateLibraries)
      3. GET /backend/apps/{g}/{a}/{v}/vulndeps → per-CVE reachability verdicts

  - vulndeps returns [] until the Steady bug database is populated.
    Full reachability requires the CIA (Code Impact Analyzer) service. Without it,
    the heuristic reachability fallback takes over automatically.

  - If the Steady server is unreachable, returns {} silently.

Setup:
  docker compose -f docker/steady/docker-compose.yml up -d

Steady 3.2.5 API quirks fixed in this file:
  - POST /backend/apps must use "dependencies" (not "libs") — from Application.java bytecode
  - LibraryId JSON uses "group" (not "mvnGroup") — @JsonProperty("group") on mvnGroup field
  - At least one constructId required or updateLibraries() NPEs (null.iterator())
  - /apps/{g}/{a}/{v}/deps is GET-only — deps go via POST /backend/libs + POST /backend/apps
  - Libraries must be pre-created via POST /backend/libs before they can be referenced in deps
    (LibraryId is a separate JPA entity; passing it inline causes TransientPropertyValueException)
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

import asyncpg
import httpx

logger = logging.getLogger(__name__)

_STEADY_URL = os.getenv("STEADY_URL", "http://localhost:8033")
_STEADY_TIMEOUT = int(os.getenv("STEADY_TIMEOUT", "300"))


from dataclasses import dataclass

@dataclass
class SteadyVerdict:
    vulnerability_id:  str
    package_name:      str
    verdict:           str          # REACHABLE | NOT_REACHABLE | UNKNOWN
    call_chain:        Optional[str]
    confidence:        float


_CIA_URL         = os.getenv("CIA_URL",          "http://localhost:8033/cia")
_STEADY_DB_HOST  = os.getenv("STEADY_DB_HOST",  "localhost")
_STEADY_DB_PORT  = int(os.getenv("STEADY_DB_PORT",  "8032"))
_STEADY_DB_NAME  = os.getenv("STEADY_DB_NAME",  "vulas")
_STEADY_DB_USER  = os.getenv("STEADY_DB_USER",  "steady")
_STEADY_DB_PASS  = os.getenv("STEADY_DB_PASS",  "steadypass")


class SteadyTool:
    """
    Calls Eclipse Steady REST API to get call-graph-based reachability verdicts.
    Returns {} (empty dict) if Steady is unavailable or the bug DB has no CVE data.
    """

    def __init__(self):
        self._base = _STEADY_URL.rstrip("/")
        self._cia  = _CIA_URL.rstrip("/")
        self._space_token: Optional[str] = None
        self._tenant_token: Optional[str] = None

    async def _get_tokens(self, client: httpx.AsyncClient) -> bool:
        """Fetch default space and tenant tokens from Steady."""
        try:
            spaces_r  = await client.get("/backend/spaces")
            tenants_r = await client.get("/backend/tenants")
            if spaces_r.status_code == 200:
                for s in spaces_r.json():
                    if s.get("default"):
                        self._space_token = s["spaceToken"]
                        break
                if not self._space_token and spaces_r.json():
                    self._space_token = spaces_r.json()[0]["spaceToken"]
            if tenants_r.status_code == 200:
                for t in tenants_r.json():
                    if t.get("default"):
                        self._tenant_token = t["tenantToken"]
                        break
            return bool(self._space_token)
        except Exception:
            return False

    def _auth_headers(self) -> dict:
        h: dict = {}
        if self._space_token:
            h["X-Vulas-Space"]  = self._space_token
        if self._tenant_token:
            h["X-Vulas-Tenant"] = self._tenant_token
        return h

    async def is_available(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=3) as client:
                r = await client.get(f"{self._base}/backend/spaces")
                return r.status_code == 200
        except Exception:
            return False

    async def analyze(
        self,
        scan_path:   str,
        run_id:      str,
        known_vulns: list[dict] | None = None,
    ) -> dict[str, SteadyVerdict]:
        """
        known_vulns: list of dicts from dependency_findings, each with keys:
          vulnerability_id, package_name, installed_version, description
          (used to seed Steady's bug database so vulndeps can return results)
        """
        """
        Register the app (constructs + deps), then return per-CVE vulndep verdicts.
        Returns {} if Steady is unavailable or the bug database is empty.
        """
        root = Path(scan_path).resolve()

        if not await self.is_available():
            logger.info("Steady | server not available at %s — skipping", self._base)
            return {}

        coords = self._read_pom_coords(root)
        if not coords:
            logger.info("Steady | no pom.xml found — Steady only supports Maven projects")
            return {}

        group_id, artifact_id, version = coords
        app_key = f"{group_id}/{artifact_id}/{version}"
        logger.info("Steady | START | app=%s run=%s", app_key, run_id)

        try:
            async with httpx.AsyncClient(timeout=60, base_url=self._base) as client:
                if not await self._get_tokens(client):
                    logger.warning("Steady | could not fetch space/tenant tokens — skipping")
                    return {}

                # Step 1: extract app constructs and dep metadata from pom.xml
                construct_ids = self._extract_construct_ids(root, group_id)
                pom_deps      = self._parse_pom_deps(root)

                # Step 2: pre-create each Library record in Steady so that the
                # subsequent app registration can reference them by digest.
                # (POST /backend/libs must precede POST /backend/apps with deps.)
                steady_deps = await self._ensure_libraries(client, pom_deps)

                # Step 3: register the application with constructs + deps
                registered = await self._register_app(
                    client, group_id, artifact_id, version, construct_ids, steady_deps
                )
                if not registered:
                    return {}

                # Step 4: seed Steady bug database with known CVEs so vulndeps can match
                if known_vulns:
                    await self._seed_vulnerabilities(client, known_vulns)
                    # Small delay to allow Steady to commit seeded data before vulndeps query
                    import asyncio as _aio
                    await _aio.sleep(1)

                # Step 5: fetch per-CVE vulndep verdicts
                verdicts = await self._fetch_verdicts(client, group_id, artifact_id, version)
                if verdicts:
                    logger.info("Steady | COMPLETE | app=%s verdicts=%d", app_key, len(verdicts))
                else:
                    logger.info(
                        "Steady | COMPLETE | app=%s verdicts=0 "
                        "(Steady bug database empty — CIA service not configured; "
                        "heuristic reachability fallback will be used instead)",
                        app_key,
                    )
                return verdicts

        except Exception as exc:
            logger.warning("Steady | analysis error: %s", exc)
            return {}

    # -------------------------------------------------------------------------
    # CIA — construct lookup
    # -------------------------------------------------------------------------

    async def _get_cia_constructs(
        self,
        group:    str,
        artifact: str,
        version:  str,
        filter_classes: list[str] | None = None,
    ) -> list[dict]:
        """
        Ask CIA for all METH/CONS constructs of a library version, optionally
        filtered to specific class names (the affected classes for a CVE).

        CIA fetches the JAR from Maven Central on first call (cached afterwards).
        Returns list of constructChange dicts ready for POST /backend/bugs.

        filter_classes: e.g. ["org.dom4j.DocumentHelper", "org.dom4j.io.SAXReader"]
        If provided, only methods belonging to those classes are returned.
        If None/empty, returns the first 30 methods from the whole library
        (last-resort fallback so Steady has *something* to trace).
        """
        url = f"{self._cia}/artifacts/{group}/{artifact}/{version}/jar/constructIds"
        try:
            async with httpx.AsyncClient(timeout=60) as cia_client:
                r = await cia_client.get(url)
                if r.status_code != 200:
                    logger.warning("Steady | CIA constructs %d for %s:%s:%s",
                                   r.status_code, group, artifact, version)
                    return []
                all_constructs = r.json()
        except Exception as exc:
            logger.warning("Steady | CIA constructs error: %s", exc)
            return []

        if not all_constructs:
            return []

        # Filter to affected classes when provided
        if filter_classes:
            matching = [
                c for c in all_constructs
                if c.get("type") in ("METH", "CONS")
                and any(
                    c.get("qname", "").startswith(cls + "(")   # exact class match
                    or c.get("qname", "").startswith(cls + ".")  # inner class / nested
                    for cls in filter_classes
                )
            ]
            if matching:
                logger.info("Steady | CIA found %d constructs for classes %s in %s:%s:%s",
                            len(matching), filter_classes, group, artifact, version)
                return [
                    {"constructId": {"lang": "JAVA", "type": c["type"], "qname": c["qname"]},
                     "constructChangeType": "MOD", "repoType": "CVS"}
                    for c in matching[:100]   # cap at 100 methods
                ]

        # Fallback: no class filter or no match — take first 30 METH constructs
        fallback = [c for c in all_constructs if c.get("type") == "METH"][:30]
        logger.info("Steady | CIA fallback: %d constructs for %s:%s:%s",
                    len(fallback), group, artifact, version)
        return [
            {"constructId": {"lang": "JAVA", "type": c["type"], "qname": c["qname"]},
             "repoType": "CVS"}
            for c in fallback
        ]

    # -------------------------------------------------------------------------
    # Direct DB construct seeding (bypasses REST API PUT limitation)
    # -------------------------------------------------------------------------

    async def _seed_constructs_direct(
        self,
        bug_id:     str,
        constructs: list[dict],
    ) -> int:
        """
        Insert constructChanges directly into Steady's PostgreSQL when the
        REST API PUT /backend/bugs/{id} returns 500.

        Steady's PUT endpoint fails on existing bugs because it tries to
        re-insert duplicate (lang, type, qname) rows in construct_id without
        ON CONFLICT handling. Direct DB insert uses ON CONFLICT DO NOTHING.

        Returns the number of construct_change rows inserted.
        """
        if not constructs:
            return 0
        try:
            conn = await asyncpg.connect(
                host=_STEADY_DB_HOST, port=_STEADY_DB_PORT,
                database=_STEADY_DB_NAME, user=_STEADY_DB_USER,
                password=_STEADY_DB_PASS,
            )
            inserted = 0
            async with conn.transaction():
                for c in constructs:
                    cid  = c.get("constructId", {})
                    lang = cid.get("lang", "JAVA")
                    typ  = cid.get("type", "METH")
                    qname = cid.get("qname", "")
                    if not qname:
                        continue

                    # 1. Insert construct_id row.
                    #    construct_id.id has NO DEFAULT (Hibernate manages IDs via
                    #    hibernate_sequence), so we must supply nextval() explicitly.
                    #    ON CONFLICT DO NOTHING is safe for existing rows.
                    #    Then SELECT to get the actual id (inserted or pre-existing).
                    await conn.execute(
                        """INSERT INTO construct_id (id, lang, type, qname)
                           VALUES (nextval('hibernate_sequence'), $1, $2, $3)
                           ON CONFLICT (lang, type, qname) DO NOTHING""",
                        lang, typ, qname,
                    )
                    cid_row = await conn.fetchrow(
                        "SELECT id FROM construct_id WHERE lang=$1 AND type=$2 AND qname=$3",
                        lang, typ, qname,
                    )
                    if not cid_row:
                        continue
                    construct_db_id = cid_row["id"]

                    # 2. Insert bug_construct_change (idempotent via ON CONFLICT)
                    result = await conn.execute(
                        """INSERT INTO bug_construct_change
                             (id, bug, construct_id, construct_change_type, repo, commit, repo_path)
                           VALUES (
                             nextval('hibernate_sequence'),
                             $1, $2, 'MOD', 'manual', 'manual', '/'
                           )
                           ON CONFLICT (bug, repo, commit, repo_path, construct_id) DO NOTHING""",
                        bug_id, construct_db_id,
                    )
                    if result and result != "INSERT 0 0":
                        inserted += 1

            await conn.close()
            logger.info("Steady | DB seeded %d constructs for bug %s", inserted, bug_id)
            return inserted

        except Exception as exc:
            logger.warning("Steady | DB construct seed error for %s: %s", bug_id, exc)
            return 0

    # -------------------------------------------------------------------------
    # CVE / bug database seeding
    # -------------------------------------------------------------------------

    async def _seed_vulnerabilities(
        self,
        client:      httpx.AsyncClient,
        known_vulns: list[dict],
    ) -> None:
        """
        Seed Steady's bug database with CVEs from our dependency_findings table.

        With CIA running this now does:
          1. POST /backend/bugs — with constructChanges populated from CIA
             (specific methods of the affected class from the vulnerable JAR).
             This gives Steady concrete call-graph targets to trace against app code.
          2. PUT  /backend/bugs/{id}/affectedLibIds?source=MANUAL — mark affected version.
          3. PUT  /backend/bugs/{id} — update existing bug's constructChanges if already seeded.

        constructChanges are fetched from CIA filtered to the known affected_classes
        (from cve_enricher). Falls back to first-N methods of the library if no class info.
        """
        # Deduplicate: one bug entry per vulnerability_id × package coordinates
        seen_bugs:    set[str] = set()
        seen_affects: set[str] = set()

        for row in known_vulns:
            vuln_id  = row.get("vulnerability_id") or ""
            pkg_name = row.get("package_name") or ""   # e.g. "dom4j:dom4j"
            version  = row.get("installed_version") or ""
            desc     = row.get("description") or f"Vulnerability in {pkg_name}"

            if not vuln_id or not pkg_name:
                continue

            # Parse group:artifact from package_name
            parts = pkg_name.split(":", 1)
            if len(parts) != 2:
                continue
            group, artifact = parts[0], parts[1]

            # --- Step 1: get CIA constructs for this library/version ---
            # affected_classes is a JSON string e.g. '["org.dom4j.DocumentHelper"]'
            affected_classes: list[str] = []
            raw_classes = row.get("affected_classes")
            if raw_classes:
                try:
                    import json as _json
                    parsed = _json.loads(raw_classes) if isinstance(raw_classes, str) else raw_classes
                    if isinstance(parsed, list):
                        affected_classes = [c for c in parsed if c]
                except Exception:
                    pass

            construct_changes: list[dict] = []
            if vuln_id not in seen_bugs:
                # Only call CIA once per (group, artifact, version) per bug
                construct_changes = await self._get_cia_constructs(
                    group, artifact, version, affected_classes or None
                )
                logger.info(
                    "Steady | CIA constructs for %s: %d (classes=%s)",
                    vuln_id, len(construct_changes), affected_classes or "fallback"
                )

            # --- Step 2: create or update bug entry ---
            if vuln_id not in seen_bugs:
                seen_bugs.add(vuln_id)
                try:
                    r = await client.post(
                        "/backend/bugs",
                        json={
                            "bugId":            vuln_id,
                            "maturity":         "READY",
                            "origin":           "PUBLIC",
                            "description":      desc[:512],
                            "constructChanges": construct_changes,
                        },
                        headers=self._auth_headers(),
                    )
                    if r.status_code == 201:
                        logger.debug("Steady | seeded bug %s constructs=%d",
                                     vuln_id, len(construct_changes))
                    elif r.status_code == 409:
                        # Bug exists — REST PUT fails on duplicates, use direct DB insert
                        if construct_changes:
                            await self._seed_constructs_direct(vuln_id, construct_changes)
                    else:
                        logger.warning("Steady | seed bug %s failed: %d", vuln_id, r.status_code)
                        continue
                except Exception as exc:
                    logger.warning("Steady | seed bug error %s: %s", vuln_id, exc)
                    continue

            # --- Step 3: mark affected library version ---
            affect_key = f"{vuln_id}|{group}:{artifact}:{version}"
            if affect_key in seen_affects or not version:
                continue
            seen_affects.add(affect_key)
            try:
                r = await client.put(
                    f"/backend/bugs/{vuln_id}/affectedLibIds",
                    params={"source": "MANUAL"},
                    json=[{
                        "libraryId": {"group": group, "artifact": artifact, "version": version},
                        "affected":  True,
                        "source":    "MANUAL",
                    }],
                    headers=self._auth_headers(),
                )
                if r.status_code in (200, 201):
                    logger.debug("Steady | seeded affectedLib %s → %s:%s:%s",
                                 vuln_id, group, artifact, version)
                else:
                    logger.warning("Steady | affectedLib failed %s: %d %s",
                                   vuln_id, r.status_code, r.text[:100])
            except Exception as exc:
                logger.warning("Steady | affectedLib error: %s", exc)

        logger.info("Steady | seeded %d bugs / %d affected-lib entries",
                    len(seen_bugs), len(seen_affects))

    # -------------------------------------------------------------------------
    # Library pre-creation
    # -------------------------------------------------------------------------

    async def _ensure_libraries(
        self,
        client:   httpx.AsyncClient,
        pom_deps: list[dict],
    ) -> list[dict]:
        """
        Pre-create each Library record in Steady via POST /backend/libs.

        This step is required because Steady's JPA model treats Library and LibraryId
        as separate persistent entities. If a Library is included in POST /backend/apps
        but has never been saved, Hibernate throws TransientPropertyValueException
        (Library.libraryId → LibraryId unsaved). Pre-creating via /backend/libs fixes this.

        Returns a list of dep dicts augmented with the digest, ready for app registration.
        """
        steady_deps: list[dict] = []

        for dep in pom_deps:
            lib_id = dep["libraryId"]   # {"group": g, "artifact": a, "version": v}
            digest = dep["digest"]
            scope  = dep.get("scope", "COMPILE")
            transitive = dep.get("transitive", False)

            payload = {
                "digest":          digest,
                "digestAlgorithm": "SHA1",
                "libraryId":       lib_id,
            }
            try:
                r = await client.post(
                    "/backend/libs",
                    json=payload,
                    headers=self._auth_headers(),
                )
                # 201 = created, 409 = already exists (both OK)
                if r.status_code not in (200, 201, 409):
                    logger.warning(
                        "Steady | /backend/libs failed: %d %s | lib=%s:%s:%s",
                        r.status_code, r.text[:100],
                        lib_id["group"], lib_id["artifact"], lib_id["version"],
                    )
                    continue
            except Exception as exc:
                logger.warning("Steady | /backend/libs error: %s", exc)
                continue

            steady_deps.append({
                "lib": {
                    "digest":          digest,
                    "digestAlgorithm": "SHA1",
                    "libraryId":       lib_id,
                },
                "scope":      scope,
                "transitive": transitive,
            })

        logger.debug("Steady | pre-created %d/%d libraries", len(steady_deps), len(pom_deps))
        return steady_deps

    # -------------------------------------------------------------------------
    # App registration
    # -------------------------------------------------------------------------

    async def _register_app(
        self,
        client:       httpx.AsyncClient,
        group_id:     str,
        artifact_id:  str,
        version:      str,
        construct_ids: list[dict],
        deps:         list[dict],
    ) -> bool:
        """
        Register the application via POST /backend/apps.

        Steady 3.2.5 requirements (discovered via bytecode analysis):
          - Body field "dependencies" (NOT "libs") — from Application.java bytecode
          - "constructIds" must have ≥1 entry — else updateLibraries() NPEs on null.iterator()
          - LibraryId uses "group" (NOT "mvnGroup") — @JsonProperty("group") on mvnGroup field
          - 409 = already exists. If an existing app has 0 deps (e.g. from a previous
            broken registration), we DELETE and re-register so that deps are populated.
        """
        payload = {
            "group":        group_id,
            "artifact":     artifact_id,
            "version":      version,
            "constructIds": construct_ids,
            "dependencies": deps,
        }
        r = await client.post(
            "/backend/apps",
            json=payload,
            headers=self._auth_headers(),
        )

        if r.status_code in (200, 201):
            logger.info(
                "Steady | app registered | status=%d constructs=%d deps=%d",
                r.status_code, len(construct_ids), len(deps),
            )
            return True

        if r.status_code == 409:
            # App already exists — use PUT to update constructs and deps in place.
            # DELETE /apps/{g}/{a}/{v} is not supported (405) in Steady 3.2.5;
            # PUT /apps/{g}/{a}/{v} with the full body is the correct update path.
            logger.info(
                "Steady | app already exists (409) — updating via PUT | deps=%d",
                len(deps),
            )
            try:
                put_r = await client.put(
                    f"/backend/apps/{group_id}/{artifact_id}/{version}",
                    json=payload,
                    headers=self._auth_headers(),
                )
                if put_r.status_code in (200, 201):
                    logger.info(
                        "Steady | app updated via PUT | status=%d constructs=%d deps=%d",
                        put_r.status_code, len(construct_ids), len(deps),
                    )
                    return True
                logger.warning(
                    "Steady | PUT update failed: %d %s",
                    put_r.status_code, put_r.text[:200],
                )
                # Fall back: assume existing app is usable as-is
                return True
            except Exception as exc:
                logger.warning("Steady | PUT update error: %s", exc)
                return True   # Best-effort: assume existing app is usable

        logger.warning(
            "Steady | register app failed: %d %s | constructs=%d deps=%d",
            r.status_code, r.text[:200], len(construct_ids), len(deps),
        )
        return False

    # -------------------------------------------------------------------------
    # Vulndep fetch
    # -------------------------------------------------------------------------

    async def _fetch_verdicts(
        self,
        client:      httpx.AsyncClient,
        group_id:    str,
        artifact_id: str,
        version:     str,
    ) -> dict[str, SteadyVerdict]:
        """Fetch per-CVE reachability verdicts from Steady."""
        url = f"/backend/apps/{group_id}/{artifact_id}/{version}/vulndeps"
        verdicts: dict[str, SteadyVerdict] = {}
        try:
            r = await client.get(url, timeout=60, headers=self._auth_headers())
            if r.status_code != 200:
                logger.debug("Steady | vulndeps status=%d for %s/%s/%s",
                             r.status_code, group_id, artifact_id, version)
                return verdicts
            data = r.json()
            logger.debug("Steady | vulndeps raw response (first 500 chars): %s",
                         str(data)[:500])
            for item in (data if isinstance(data, list) else data.get("vulnDeps", [])):
                # Steady 3.2.5 nests the bug under item["bug"]["bugId"] (not flat).
                bug_obj   = item.get("bug") or {}
                vuln_id   = (
                    bug_obj.get("bugId") or bug_obj.get("cveId")
                    or item.get("bugId") or item.get("cve")
                    or ""
                )
                pkg       = item.get("dep", {}).get("lib", {}).get("libraryId", {})
                # LibraryId response uses "group" (not "mvnGroup")
                grp       = pkg.get("group") or pkg.get("mvnGroup") or ""
                pkg_name  = f"{grp}:{pkg.get('artifact','')}" if pkg else ""

                # Steady 3.2.5 returns reachable as an integer:
                #   1  = confirmed reachable (call-graph traced)
                #  -1  = confirmed NOT reachable
                #   0  = unknown (no CIA service / call-graph analysis not run)
                # Older API versions used string enum: "TRUE" / "FALSE" / "POTENTIALLY"
                reach_raw = item.get("reachable")
                reach_str = item.get("reachability") or ""

                if reach_raw == 1 or str(reach_raw).upper() in ("TRUE", "POTENTIALLY"):
                    verdict_str = "REACHABLE"
                    confidence  = 0.95
                elif reach_raw == -1 or str(reach_raw).upper() == "FALSE":
                    verdict_str = "NOT_REACHABLE"
                    confidence  = 0.95
                elif str(reach_str).upper() == "POTENTIALLY":
                    verdict_str = "LIKELY_REACHABLE"
                    confidence  = 0.70
                else:
                    # reachable == 0: CIA service did not run — no call-graph analysis performed.
                    # Steady only confirmed the library version is affected (version-match only).
                    # This is NOT a call-graph result — we mark as UNKNOWN so the heuristic
                    # analysis (import-scan + JAR bytecode) is preserved instead.
                    verdict_str = "UNKNOWN"
                    confidence  = 0.0

                call_chain = None
                path = item.get("constructPath") or item.get("callPath")
                if path and isinstance(path, list):
                    call_chain = " → ".join(c.get("fqn", str(c)) for c in path)
                elif path and isinstance(path, str):
                    call_chain = path

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

    # -------------------------------------------------------------------------
    # Construct ID extraction
    # -------------------------------------------------------------------------

    def _extract_construct_ids(self, root: Path, group_id: str) -> list[dict]:
        """
        Build a list of Steady construct IDs for the application.

        Steady needs ≥1 constructId in POST /backend/apps to avoid the updateLibraries
        NPE (null.iterator() on Application.getDependencies() when both constructIds
        and dependencies are empty). PACK + CLAS constructs are sufficient for
        dep-level matching without full bytecode upload.

        Strategy (in priority order):
        1. Compiled .class files in target/classes/ — most accurate
        2. Java source package declarations — good fallback
        3. Group ID as minimal PACK construct — last resort
        """
        # --- Strategy 1: compiled .class files ---
        classes_dir = root / "target" / "classes"
        if classes_dir.exists():
            constructs = self._constructs_from_classes(classes_dir)
            if constructs:
                logger.debug("Steady | %d constructs from .class files", len(constructs))
                return constructs

        # --- Strategy 2: source package declarations ---
        constructs = self._constructs_from_sources(root)
        if constructs:
            logger.debug("Steady | %d constructs from Java sources", len(constructs))
            return constructs

        # --- Strategy 3: minimal fallback ---
        logger.debug("Steady | using group ID as minimal construct ID")
        return [{"lang": "JAVA", "type": "PACK", "qname": group_id}]

    def _constructs_from_classes(self, classes_dir: Path) -> list[dict]:
        """Extract PACK + CLAS construct IDs from compiled .class files via javap."""
        constructs: list[dict] = []
        seen_packs: set[str] = set()
        for cf in list(classes_dir.rglob("*.class"))[:200]:
            try:
                result = subprocess.run(
                    ["javap", str(cf)],
                    capture_output=True, text=True, timeout=5,
                )
                m = re.search(r"(?:class|interface|enum)\s+([\w.$]+)", result.stdout)
                if not m:
                    continue
                fqn = m.group(1)
                constructs.append({"lang": "JAVA", "type": "CLAS", "qname": fqn})
                pkg = fqn.rsplit(".", 1)[0] if "." in fqn else fqn
                if pkg not in seen_packs:
                    seen_packs.add(pkg)
                    constructs.append({"lang": "JAVA", "type": "PACK", "qname": pkg})
            except Exception:
                continue
        return constructs

    def _constructs_from_sources(self, root: Path) -> list[dict]:
        """Extract PACK construct IDs from Java source file package declarations."""
        constructs: list[dict] = []
        seen: set[str] = set()
        for java_file in root.rglob("*.java"):
            try:
                text = java_file.read_text(errors="ignore")
                m = re.search(r"^\s*package\s+([\w.]+)\s*;", text, re.MULTILINE)
                if m and m.group(1) not in seen:
                    seen.add(m.group(1))
                    constructs.append({"lang": "JAVA", "type": "PACK", "qname": m.group(1)})
            except Exception:
                continue
        return constructs

    # -------------------------------------------------------------------------
    # pom.xml parsing
    # -------------------------------------------------------------------------

    def _read_pom_coords(self, root: Path) -> Optional[tuple[str, str, str]]:
        """Read groupId, artifactId, version from root pom.xml."""
        pom = root / "pom.xml"
        if not pom.exists():
            return None
        try:
            tree    = ET.parse(pom)
            root_el = tree.getroot()
            ns      = {"m": "http://maven.apache.org/POM/4.0.0"}

            def _text(tag: str) -> str:
                # NOTE: use `is not None` not boolean truthiness — an Element with
                # only text content (no child elements) is falsy in Python 3.9 ET.
                el = root_el.find(f"m:{tag}", ns)
                if el is None:
                    el = root_el.find(tag)
                return (el.text or "").strip() if el is not None else ""

            group_id    = _text("groupId")
            artifact_id = _text("artifactId")
            version     = _text("version")

            if not group_id:
                parent = root_el.find("m:parent", ns)
                if parent is None:
                    parent = root_el.find("parent")
                if parent is not None:
                    g = parent.find("m:groupId", ns)
                    if g is None:
                        g = parent.find("groupId")
                    if g is not None and g.text:
                        group_id = g.text.strip()

            if group_id and artifact_id and version:
                return group_id, artifact_id, version
        except Exception as exc:
            logger.debug("Steady | pom parse error: %s", exc)
        return None

    def _parse_pom_deps(self, root: Path) -> list[dict]:
        """
        Parse pom.xml <dependencies> into enriched dicts with:
          - libraryId: {"group": g, "artifact": a, "version": v}
              Note: "group" is the correct JSON key — @JsonProperty("group") on LibraryId.mvnGroup
          - digest: real SHA1 from local Maven cache, or synthetic SHA1 of coordinates
          - scope, transitive, optional

        The digest is used to pre-create Library records in Steady via POST /backend/libs
        before they are referenced in POST /backend/apps. Without a pre-created Library
        record, the dep reference causes a JPA TransientPropertyValueException.
        """
        pom = root / "pom.xml"
        if not pom.exists():
            return []
        try:
            tree    = ET.parse(pom)
            root_el = tree.getroot()
            ns      = {"m": "http://maven.apache.org/POM/4.0.0"}
            deps: list[dict] = []

            dep_els = root_el.findall(".//m:dependency", ns)
            if not dep_els:
                dep_els = root_el.findall(".//dependency")

            for dep in dep_els:
                def _t(tag: str, _dep=dep, _ns=ns) -> str:
                    # Use `is not None` — ET elements with only text are falsy in Py 3.9
                    el = _dep.find(f"m:{tag}", _ns)
                    if el is None:
                        el = _dep.find(tag)
                    return (el.text or "").strip() if el is not None else ""

                g, a, v = _t("groupId"), _t("artifactId"), _t("version")
                scope    = _t("scope") or "COMPILE"
                optional = _t("optional").lower() == "true"

                if not (g and a and v) or v.startswith("${"):
                    continue

                digest = self._get_jar_digest(g, a, v)

                deps.append({
                    "libraryId": {"group": g, "artifact": a, "version": v},
                    "digest":    digest,
                    "scope":     scope.upper(),
                    "transitive": False,
                    "optional":  optional,
                })
            return deps
        except Exception:
            return []

    def _get_jar_digest(self, group_id: str, artifact_id: str, version: str) -> str:
        """
        Return the SHA1 digest for a Maven artifact.

        Tries the local Maven repository (~/.m2/repository/) first — this gives
        Steady the real digest it needs to match against its vulnerability database.
        Falls back to a deterministic synthetic SHA1 of "group:artifact:version".

        The real digest matters for Steady's CIA-based vulnerability lookup:
        the CIA maps SHA1 digests of known-vulnerable JARs to CVE records.
        """
        # Build the expected JAR path in local Maven cache
        group_path = group_id.replace(".", "/")
        m2_jar = (
            Path.home()
            / ".m2" / "repository"
            / group_path / artifact_id / version
            / f"{artifact_id}-{version}.jar"
        )
        if m2_jar.exists():
            try:
                sha1 = hashlib.sha1()
                with open(m2_jar, "rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        sha1.update(chunk)
                return sha1.hexdigest()
            except Exception:
                pass

        # Synthetic: deterministic hash of Maven coordinates
        synthetic = hashlib.sha1(f"{group_id}:{artifact_id}:{version}".encode()).hexdigest()
        logger.debug(
            "Steady | no local JAR for %s:%s:%s — using synthetic digest %s",
            group_id, artifact_id, version, synthetic,
        )
        return synthetic

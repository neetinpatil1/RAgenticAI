# Network Security Scanner — Technical Implementation Plan

## Architecture Pattern

The network scanner follows the same patterns as the existing code scanner agents. Reference implementations:
- **Workflow pattern:** `workflows/spotbugs_workflow.py` (simple, no FP pipeline)
- **Table creation:** `workflows/secret_scan_workflow.py:43-56`
- **JSONB metadata merge:** `workflows/spotbugs_workflow.py:153-177`
- **CVE lookup:** `tools/cve_enricher.py`
- **FP Layer 3 LLM:** `core/fp_pipeline/layer3_llm.py`
- **Orchestration wiring:** `api/agent_gateway.py:226-282`

---

## File Structure

### New Files

```
tools/network/
├── __init__.py
├── port_scanner_tool.py        # nmap/masscan wrapper
├── tls_scanner_tool.py         # testssl.sh/sslyze wrapper
├── web_vuln_tool.py            # nuclei wrapper
└── cve_correlator_tool.py      # OSV.dev + NVD API lookup for service versions

workflows/network/
├── __init__.py
├── port_scan_workflow.py       # LangGraph: port scanning agent
├── tls_scan_workflow.py        # LangGraph: TLS analysis agent
├── web_vuln_workflow.py        # LangGraph: web vulnerability agent
└── cve_correlator_workflow.py  # LangGraph: CVE enrichment after port scan

core/fp_pipeline/
└── network_layer1.py           # Network-specific Layer 1 FP rules

agents/security/network/
├── fp_rules.yml                # Network FP YAML rule definitions
└── nuclei_templates/
    ├── spring-boot-actuator.yaml
    ├── exposed-debug-ports.yaml
    └── h2-console.yaml

prompts/network_agent/
└── v1.0/
    └── fp_analysis.yml         # LLM prompt for network FP analysis
```

### Modified Files

```
api/agent_gateway.py            # New endpoint + _run_network_agents()
core/config.py                  # Add NetworkScannerConfig dataclass
db/schema.sql                   # Add network_findings table + indexes
```

---

## 1. Configuration (`core/config.py`)

Add after `SemgrepConfig`:

```python
@dataclass
class NetworkScannerConfig:
    """Network security scanner settings."""
    enabled: bool = field(default_factory=lambda: os.getenv("NETWORK_SCAN_ENABLED", "true").lower() == "true")
    nmap_path: str = field(default_factory=lambda: os.getenv("NMAP_PATH", "nmap"))
    masscan_path: str = field(default_factory=lambda: os.getenv("MASSCAN_PATH", "masscan"))
    testssl_path: str = field(default_factory=lambda: os.getenv("TESTSSL_PATH", "testssl"))
    nuclei_path: str = field(default_factory=lambda: os.getenv("NUCLEI_PATH", "nuclei"))
    nuclei_templates_path: str = field(default_factory=lambda: os.getenv(
        "NUCLEI_TEMPLATES_PATH", "./agents/security/network/nuclei_templates"
    ))
    fp_rules_path: str = field(default_factory=lambda: os.getenv(
        "NETWORK_FP_RULES_PATH", "./agents/security/network/fp_rules.yml"
    ))
    quick_timeout: int = 120       # seconds
    standard_timeout: int = 600    # seconds
    deep_timeout: int = 3600       # seconds
    nvd_api_key: str = field(default_factory=lambda: os.getenv("NVD_API_KEY", ""))
```

Add `network: NetworkScannerConfig` field to `AppConfig`.

---

## 2. Database Schema (`db/schema.sql`)

```sql
-- Network scan findings (port exposure, TLS, web vulns, CVE matches)
CREATE TABLE IF NOT EXISTS network_findings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id          TEXT NOT NULL REFERENCES workflow_runs(run_id),
    host            TEXT NOT NULL,                 -- IP or resolved hostname
    port            INT,                           -- NULL for host-level findings
    protocol        TEXT,                          -- tcp | udp
    service         TEXT,                          -- http | ssh | ftp | tls | etc.
    service_version TEXT,                          -- "OpenSSH 7.4p1 Ubuntu"
    check_id        TEXT NOT NULL,                 -- rule/template/NSE script ID
    severity        TEXT NOT NULL,                 -- CRITICAL|HIGH|MEDIUM|LOW|INFO
    description     TEXT NOT NULL,
    evidence        TEXT,                          -- raw tool output snippet
    remediation     TEXT,
    cve_ids         JSONB DEFAULT '[]',            -- ["CVE-2021-44228", ...]
    cvss_score      REAL,                          -- highest CVSS from cve_ids
    category        TEXT,                          -- port-exposure|tls-weakness|web-vuln|cve-match
    fp_verdict      TEXT,                          -- REAL|FP|ESCALATED (from FP pipeline)
    fp_confidence   REAL,
    fp_category     TEXT,                          -- expected-web-service|dev-environment|etc.
    fp_reasoning    TEXT,
    scan_profile    TEXT,                          -- quick|standard|deep
    is_baseline     BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_network_findings_run      ON network_findings(run_id);
CREATE INDEX IF NOT EXISTS idx_network_findings_severity ON network_findings(severity);
CREATE INDEX IF NOT EXISTS idx_network_findings_host     ON network_findings(host);
CREATE INDEX IF NOT EXISTS idx_network_findings_category ON network_findings(category);
```

---

## 3. Tool: Port Scanner (`tools/network/port_scanner_tool.py`)

```python
"""
tools/network/port_scanner_tool.py
====================================
nmap/masscan wrapper for port scanning and service detection.

Strategy:
  - masscan for fast host discovery on large CIDR ranges (>= /24)
  - nmap -sV for service version detection on discovered hosts
  - NSE scripts based on scan profile (none | safe,auth | vuln,exploit)
  - Parses nmap XML output → list[PortFinding]

Requires: nmap installed (brew install nmap)
Optional: masscan for large CIDR ranges (brew install masscan)
"""
from __future__ import annotations
import asyncio
import logging
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional
from core.config import settings

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    23: "CRITICAL",    # Telnet
    21: "HIGH",        # FTP
    512: "HIGH", 513: "HIGH", 514: "HIGH",  # rsh/rlogin/rexec
    3389: "MEDIUM",    # RDP
    5900: "MEDIUM",    # VNC
    27017: "HIGH",     # MongoDB no-auth
    6379: "HIGH",      # Redis no-auth
    9200: "MEDIUM",    # Elasticsearch
}


@dataclass
class PortFinding:
    host: str
    port: int
    protocol: str
    state: str
    service: str
    service_version: str
    severity: str
    check_id: str
    description: str
    evidence: str
    remediation: str = ""
    cve_ids: list[str] = field(default_factory=list)
    nse_findings: list[dict] = field(default_factory=list)


class PortScannerTool:
    def __init__(self):
        self.nmap = settings.network.nmap_path
        self.masscan = settings.network.masscan_path

    async def scan(
        self,
        target: str,
        profile: str = "standard",
        authorized: bool = False,
    ) -> list[PortFinding]:
        """Run nmap against target. Never raises — returns [] on tool failure."""
        nmap_args = self._build_nmap_args(profile, authorized)
        timeout = {
            "quick": settings.network.quick_timeout,
            "standard": settings.network.standard_timeout,
            "deep": settings.network.deep_timeout,
        }.get(profile, settings.network.standard_timeout)

        try:
            xml_output = await self._run_nmap(target, nmap_args, timeout)
            return self._parse_xml(xml_output, profile)
        except Exception as exc:
            logger.warning("PortScannerTool | failed: %s", exc)
            return []

    def _build_nmap_args(self, profile: str, authorized: bool) -> list[str]:
        base = ["-sV", "-oX", "-"]   # service detection, XML to stdout
        if profile == "quick":
            return base + ["--top-ports", "1000"]
        elif profile == "standard":
            return base + ["--top-ports", "10000", "--script=safe,auth"]
        elif profile == "deep" and authorized:
            return base + ["-p-", "--script=vuln,exploit", "-T4"]
        else:
            logger.warning("PortScannerTool | deep scan requested without authorization — using standard")
            return base + ["--top-ports", "10000", "--script=safe,auth"]

    async def _run_nmap(self, target: str, args: list[str], timeout: int) -> str:
        cmd = [self.nmap] + args + [target]
        logger.info("PortScannerTool | running: %s", " ".join(cmd))
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            raise RuntimeError(f"nmap timed out after {timeout}s")
        if proc.returncode not in (0, 1):  # nmap returns 1 when hosts are down
            raise RuntimeError(f"nmap exited {proc.returncode}: {stderr.decode()[:200]}")
        return stdout.decode()

    def _parse_xml(self, xml: str, profile: str) -> list[PortFinding]:
        findings = []
        try:
            root = ET.fromstring(xml)
        except ET.ParseError:
            return []

        for host in root.findall("host"):
            addr_el = host.find("address[@addrtype='ipv4']")
            if addr_el is None:
                addr_el = host.find("address[@addrtype='ipv6']")
            if addr_el is None:
                continue
            host_ip = addr_el.get("addr", "unknown")

            for port_el in host.findall(".//port"):
                state = port_el.find("state")
                if state is None or state.get("state") != "open":
                    continue
                port_num = int(port_el.get("portid", 0))
                proto = port_el.get("protocol", "tcp")
                svc = port_el.find("service")
                svc_name = svc.get("name", "unknown") if svc is not None else "unknown"
                svc_ver = " ".join(filter(None, [
                    svc.get("product", "") if svc is not None else "",
                    svc.get("version", "") if svc is not None else "",
                    svc.get("extrainfo", "") if svc is not None else "",
                ])).strip()

                severity = SEVERITY_MAP.get(port_num, "INFO")
                description = f"Port {port_num}/{proto} open — {svc_name}"
                if svc_ver:
                    description += f" ({svc_ver})"

                findings.append(PortFinding(
                    host=host_ip,
                    port=port_num,
                    protocol=proto,
                    state="open",
                    service=svc_name,
                    service_version=svc_ver,
                    severity=severity,
                    check_id=f"open-port-{port_num}",
                    description=description,
                    evidence=f"nmap detected {svc_name} on {host_ip}:{port_num}/{proto}",
                ))
        return findings
```

---

## 4. Tool: TLS Scanner (`tools/network/tls_scanner_tool.py`)

```python
"""
tools/network/tls_scanner_tool.py
====================================
testssl.sh wrapper for TLS/SSL configuration analysis.
Falls back to sslyze (Python) if testssl.sh is unavailable.

Parses testssl.sh JSON output → list[TLSFinding].
"""
from __future__ import annotations
import asyncio
import json
import logging
from dataclasses import dataclass
from typing import Optional
from core.config import settings

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "OK": "INFO",
    "INFO": "INFO",
    "WARN": "MEDIUM",
    "NOT ok": "HIGH",
}


@dataclass
class TLSFinding:
    host: str
    port: int
    check_id: str
    severity: str
    description: str
    evidence: str
    remediation: str
    cve_id: Optional[str] = None


class TLSScannerTool:
    async def scan(self, host: str, port: int = 443) -> list[TLSFinding]:
        """
        Run testssl.sh against host:port.
        Falls back to sslyze if testssl.sh unavailable.
        Returns [] on failure.
        """
        try:
            return await self._run_testssl(host, port)
        except FileNotFoundError:
            logger.info("TLSScannerTool | testssl.sh not found — trying sslyze")
            try:
                return await self._run_sslyze(host, port)
            except Exception as exc:
                logger.warning("TLSScannerTool | sslyze also failed: %s", exc)
                return []
        except Exception as exc:
            logger.warning("TLSScannerTool | failed: %s", exc)
            return []

    async def _run_testssl(self, host: str, port: int) -> list[TLSFinding]:
        cmd = [
            settings.network.testssl_path,
            "--jsonfile", "/dev/stdout",
            "--quiet",
            "--color", "0",
            f"{host}:{port}",
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
        return self._parse_testssl_json(json.loads(stdout.decode()), host, port)

    def _parse_testssl_json(self, data: dict, host: str, port: int) -> list[TLSFinding]:
        findings = []
        for item in data if isinstance(data, list) else data.get("scanResult", [{}])[0].get("serverDefaults", []):
            severity_raw = item.get("severity", "INFO").upper()
            if severity_raw in ("OK", "INFO", "DEBUG"):
                continue
            severity = SEVERITY_MAP.get(severity_raw, "INFO")
            check_id = item.get("id", "unknown")
            finding_text = item.get("finding", "")
            cve = item.get("cve", None)

            findings.append(TLSFinding(
                host=host,
                port=port,
                check_id=check_id,
                severity=severity,
                description=f"TLS check failed: {check_id} — {finding_text}",
                evidence=finding_text,
                remediation=self._get_remediation(check_id),
                cve_id=cve if cve and cve != " " else None,
            ))
        return findings

    def _get_remediation(self, check_id: str) -> str:
        remediations = {
            "SSLv2":           "Disable SSLv2 — it is critically broken. Enable only TLS 1.2+.",
            "SSLv3":           "Disable SSLv3 (POODLE vulnerability). Enable only TLS 1.2+.",
            "TLS1":            "Disable TLS 1.0 — deprecated since 2020. Use TLS 1.2+.",
            "TLS1_1":          "Disable TLS 1.1 — deprecated since 2021. Use TLS 1.2+.",
            "HEARTBLEED":      "Patch OpenSSL immediately — CVE-2014-0160. All private keys should be considered compromised.",
            "POODLE_SSL":      "Disable SSLv3. Consider TLS_FALLBACK_SCSV to prevent downgrade attacks.",
            "cert_expired":    "Renew TLS certificate immediately. Use Let's Encrypt for automated renewal.",
            "cert_selfSigned": "Replace self-signed certificate with one from a trusted CA.",
        }
        return remediations.get(check_id, "Review TLS configuration and follow Mozilla SSL Configuration Generator recommendations.")

    async def _run_sslyze(self, host: str, port: int) -> list[TLSFinding]:
        """sslyze fallback — not yet implemented."""
        raise NotImplementedError("sslyze fallback not yet implemented")
```

---

## 5. Tool: CVE Correlator (`tools/network/cve_correlator_tool.py`)

```python
"""
tools/network/cve_correlator_tool.py
======================================
Looks up CVEs for service+version pairs detected by the port scanner.
Reuses the existing cve_enricher.py pattern but queries OSV.dev
with ecosystem=Linux/general rather than Maven/npm.

Also queries NVD API for CVSS scores (optional, requires NVD_API_KEY).
"""
from __future__ import annotations
import httpx
import logging
from dataclasses import dataclass
from typing import Optional
from core.config import settings

logger = logging.getLogger(__name__)


@dataclass
class ServiceCVE:
    cve_id: str
    cvss_score: Optional[float]
    severity: str
    description: str
    fixed_version: Optional[str]
    published: Optional[str]


class CVECorrelatorTool:
    """Takes (service_name, version_string) → list[ServiceCVE]."""

    async def lookup(self, service: str, version: str) -> list[ServiceCVE]:
        """Query OSV.dev and NVD for CVEs matching service+version. Returns [] on failure."""
        cves = []
        try:
            cves = await self._query_osv(service, version)
        except Exception as exc:
            logger.debug("CVECorrelatorTool | OSV failed for %s %s: %s", service, version, exc)

        if not cves and settings.network.nvd_api_key:
            try:
                cves = await self._query_nvd(service, version)
            except Exception as exc:
                logger.debug("CVECorrelatorTool | NVD failed for %s %s: %s", service, version, exc)

        return cves

    async def _query_osv(self, service: str, version: str) -> list[ServiceCVE]:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                "https://api.osv.dev/v1/query",
                json={"version": version, "package": {"name": service, "ecosystem": "OSS-Fuzz"}},
            )
            if resp.status_code != 200:
                return []
            data = resp.json()
            return [
                ServiceCVE(
                    cve_id=vuln.get("id", "UNKNOWN"),
                    cvss_score=self._extract_cvss(vuln),
                    severity=self._cvss_to_severity(self._extract_cvss(vuln)),
                    description=vuln.get("summary", ""),
                    fixed_version=self._extract_fix_version(vuln),
                    published=vuln.get("published"),
                )
                for vuln in data.get("vulns", [])
            ]

    async def _query_nvd(self, service: str, version: str) -> list[ServiceCVE]:
        headers = {"apiKey": settings.network.nvd_api_key} if settings.network.nvd_api_key else {}
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"keywordSearch": f"{service} {version}", "resultsPerPage": 10},
                headers=headers,
            )
            if resp.status_code != 200:
                return []
            data = resp.json()
            results = []
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                metrics = cve.get("metrics", {})
                cvss_data = (
                    metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                    or metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {})
                    or {}
                )
                score = cvss_data.get("baseScore")
                results.append(ServiceCVE(
                    cve_id=cve.get("id", "UNKNOWN"),
                    cvss_score=float(score) if score else None,
                    severity=self._cvss_to_severity(float(score) if score else None),
                    description=next(
                        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), ""
                    ),
                    fixed_version=None,
                    published=cve.get("published"),
                ))
            return results

    def _extract_cvss(self, vuln: dict) -> Optional[float]:
        for sev in vuln.get("severity", []):
            if sev.get("type") == "CVSS_V3":
                try:
                    return float(sev.get("score", "").split("/")[0].split(":")[-1])
                except Exception:
                    pass
        return None

    def _cvss_to_severity(self, score: Optional[float]) -> str:
        if score is None:
            return "MEDIUM"
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        return "LOW"

    def _extract_fix_version(self, vuln: dict) -> Optional[str]:
        for affected in vuln.get("affected", []):
            for rng in affected.get("ranges", []):
                for event in rng.get("events", []):
                    if "fixed" in event:
                        return event["fixed"]
        return None
```

---

## 6. Workflow: Port Scan (`workflows/network/port_scan_workflow.py`)

```python
"""
workflows/network/port_scan_workflow.py
========================================
LangGraph workflow for port scanning.
Follows spotbugs_workflow.py pattern (simple, no FP pipeline).
"""
from __future__ import annotations
import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional, TypedDict

import asyncpg
from tools.network.port_scanner_tool import PortScannerTool
from tools.network.cve_correlator_tool import CVECorrelatorTool

logger = logging.getLogger(__name__)


class PortScanState(TypedDict):
    run_id: str
    target: str
    scan_profile: str
    authorized: bool
    findings_count: int
    hosts_scanned: int
    error: Optional[str]


async def run_port_scan_workflow(
    run_id: str,
    target: str,
    pool: asyncpg.Pool,
    scan_profile: str = "standard",
    authorized: bool = False,
) -> None:
    """Entry point — called from _run_network_agents() in parallel."""
    import time as _t
    _start = _t.time()
    logger.info("PortScan | START | run=%s target=%s profile=%s", run_id, target, scan_profile)

    try:
        # Run port scan
        scanner = PortScannerTool()
        findings = await scanner.scan(target, profile=scan_profile, authorized=authorized)
        logger.info("PortScan | found %d open ports | run=%s", len(findings), run_id)

        # Enrich with CVEs for detected service versions
        correlator = CVECorrelatorTool()
        for f in findings:
            if f.service_version:
                cves = await correlator.lookup(f.service, f.service_version)
                if cves:
                    f.cve_ids = [c.cve_id for c in cves]
                    max_score = max((c.cvss_score or 0) for c in cves)
                    cve_severity = correlator._cvss_to_severity(max_score) if max_score else None
                    _rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
                    if cve_severity and _rank.get(cve_severity, 0) > _rank.get(f.severity, 0):
                        f.severity = cve_severity

        # Write to DB
        if findings:
            async with pool.acquire() as conn:
                for f in findings:
                    await conn.execute(
                        """
                        INSERT INTO network_findings
                            (id, run_id, host, port, protocol, service, service_version,
                             check_id, severity, description, evidence, remediation,
                             cve_ids, category, scan_profile)
                        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'port-exposure',$14)
                        ON CONFLICT DO NOTHING
                        """,
                        str(uuid.uuid4()), run_id,
                        f.host, f.port, f.protocol, f.service, f.service_version,
                        f.check_id, f.severity, f.description, f.evidence, f.remediation,
                        json.dumps(f.cve_ids), scan_profile,
                    )

        # Update workflow_runs metadata (JSONB merge — safe for concurrent writes)
        elapsed = _t.time() - _start
        patch = json.dumps({"network_port_scan": {
            "findings_count": len(findings),
            "hosts_scanned": len(set(f.host for f in findings)),
            "scan_profile": scan_profile,
            "elapsed_s": round(elapsed, 1),
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }})
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE workflow_runs SET metadata = COALESCE(metadata,'{}') || $1::jsonb WHERE run_id=$2",
                patch, run_id,
            )
        logger.info("PortScan | COMPLETE | run=%s findings=%d elapsed=%.1fs", run_id, len(findings), elapsed)

    except Exception as exc:
        logger.error("PortScan | FATAL | run=%s error=%s", run_id, exc)
```

---

## 7. Network FP Layer 1 Rules (`agents/security/network/fp_rules.yml`)

```yaml
# Network security scanner FP rules — Layer 1 deterministic filtering
# Format mirrors agents/security/sast/fp_rules.yml

rules:
  # ── Host-level rules ──────────────────────────────────────────────────────

  - id: loopback-host
    description: "Loopback addresses are not externally reachable"
    match:
      host_patterns:
        - "^127\\..*"
        - "^::1$"
        - "^localhost$"
    fp_category: "local-loopback"
    reasoning: "Loopback address — not accessible from external networks"
    applies_to_severities: [LOW, MEDIUM, HIGH]  # Never suppress CRITICAL

  - id: rfc1918-dev-environment
    description: "RFC-1918 private addresses in dev/staging environments"
    match:
      host_patterns:
        - "^10\\..*"
        - "^172\\.(1[6-9]|2[0-9]|3[01])\\..*"
        - "^192\\.168\\..*"
      metadata_env: ["dev", "development", "staging", "local", "test"]
      severities: [LOW, MEDIUM]
    fp_category: "non-production"
    reasoning: "Private IP in non-production environment — not internet-exposed"

  # ── Port-level rules ──────────────────────────────────────────────────────

  - id: expected-http-ports
    description: "HTTP/HTTPS ports expected on web servers"
    match:
      ports: [80, 443, 8080, 8443, 8000, 8888]
      services: ["http", "https", "http-alt"]
      severities: [INFO, LOW, MEDIUM]
      check_ids_prefix: ["open-port-"]
    fp_category: "expected-web-service"
    reasoning: "HTTP/HTTPS port is expected to be open on web servers"

  - id: authorized-ssh
    description: "SSH on standard port (22) is expected on managed servers"
    match:
      ports: [22]
      services: ["ssh"]
      severities: [INFO, LOW, MEDIUM]
      check_ids_prefix: ["open-port-"]
    fp_category: "expected-admin-access"
    reasoning: "SSH port 22 is expected on managed infrastructure. Verify key-based auth and MFA separately."

  - id: internal-monitoring-ports
    description: "Monitoring tool ports expected on internal infrastructure"
    match:
      ports: [9090, 9091, 9093, 3000, 9200, 5601, 8086, 9000]
      # Prometheus, Alertmanager, Grafana, Elasticsearch, Kibana, InfluxDB, Minio
      metadata_env: ["dev", "staging", "internal"]
      severities: [INFO, LOW, MEDIUM]
    fp_category: "internal-monitoring"
    reasoning: "Monitoring port on internal network — expected infrastructure tooling"

  - id: smtp-standard
    description: "Standard SMTP port open on mail servers"
    match:
      ports: [25, 587, 465]
      services: ["smtp", "smtps", "submission"]
      severities: [INFO, LOW]
    fp_category: "expected-mail-service"
    reasoning: "SMTP port expected on mail servers. Verify authentication configuration separately."

  # ── TLS rules ─────────────────────────────────────────────────────────────

  - id: tls-staging-selfsigned
    description: "Self-signed certificates on non-production environments are acceptable"
    match:
      check_ids: ["cert_selfSigned"]
      metadata_env: ["dev", "staging", "local", "test"]
      severities: [LOW, MEDIUM]
    fp_category: "non-production"
    reasoning: "Self-signed cert in non-production environment is acceptable. Ensure prod uses CA-signed cert."

  # NOTE: cert_expired is NEVER suppressed, even in staging — expiry affects
  #       automated renewal and signals broken cert rotation.
```

---

## 8. API Endpoint (`api/agent_gateway.py` additions)

### Request Model

```python
class NetworkScanRequest(BaseModel):
    """Request body for POST /api/v1/network-scan"""
    target: str = Field(..., description="IP address, domain, CIDR range, or URL")
    scan_profile: str = Field("standard", description="quick | standard | deep")
    include_web: bool = Field(False, description="Run web vulnerability checks (nuclei)")
    authorized: bool = Field(False, description="Must be true for deep profile (intrusive scans)")
    metadata: dict = Field(default_factory=dict, description="Optional context: project, environment, team")
```

### Orchestration Function

```python
async def _run_network_agents(
    run_id: str,
    target: str,
    scan_profile: str,
    include_web: bool,
    authorized: bool,
    pool: asyncpg.Pool,
    deps: dict,
) -> None:
    """
    Network scan orchestration — called as background task.
    Step 1 (parallel): Port scan + TLS scan
    Step 2 (sequential): Web vuln scan (if include_web=True)
    """
    logger.info("[NET] START | run=%s target=%s profile=%s", run_id, target, scan_profile)

    # Step 1 — parallel: port scan + TLS scan
    step1 = await asyncio.gather(
        run_port_scan_workflow(run_id=run_id, target=target, pool=pool,
                               scan_profile=scan_profile, authorized=authorized),
        run_tls_scan_workflow(run_id=run_id, target=target, pool=pool),
        return_exceptions=True,
    )
    for i, r in enumerate(step1):
        if isinstance(r, Exception):
            logger.error("[NET] Step1[%d] failed: %s | run=%s", i, r, run_id)

    # Step 2 — web vuln scan (optional)
    if include_web:
        try:
            await run_web_vuln_workflow(run_id=run_id, target=target,
                                        pool=pool, scan_profile=scan_profile)
        except Exception as exc:
            logger.error("[NET] WebVuln failed: %s | run=%s", exc, run_id)

    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE workflow_runs SET state='completed', completed_at=NOW() WHERE run_id=$1",
            run_id,
        )
    logger.info("[NET] COMPLETE | run=%s", run_id)
```

### Endpoints

```python
@app.post("/api/v1/network-scan", status_code=202)
async def submit_network_scan(
    request: NetworkScanRequest,
    pool: asyncpg.Pool = Depends(get_pool),
):
    """Submit a network security scan. Returns run_id immediately."""
    if request.scan_profile not in ("quick", "standard", "deep"):
        raise HTTPException(400, f"Invalid scan_profile: {request.scan_profile}. Use: quick|standard|deep")
    if request.scan_profile == "deep" and not request.authorized:
        raise HTTPException(400, "deep profile requires authorized=true (intrusive probes)")

    import time, hashlib
    ts = time.strftime("%Y%m%d_%H%M%S")
    h  = hashlib.md5(request.target.encode()).hexdigest()[:6]
    run_id = f"netscan_{ts}_{h}"

    async with pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO workflow_runs (run_id, scan_path, state, metadata)
               VALUES ($1, $2, 'running', $3::jsonb)""",
            run_id,
            request.target,
            json.dumps({"target": request.target, "scan_profile": request.scan_profile,
                        "include_web": request.include_web, **request.metadata}),
        )

    asyncio.create_task(_run_network_agents(
        run_id=run_id, target=request.target, scan_profile=request.scan_profile,
        include_web=request.include_web, authorized=request.authorized,
        pool=pool, deps=_build_workflow_deps(),
    ))

    return {
        "run_id": run_id,
        "status": "accepted",
        "message": f"Network scan started. Poll GET /api/v1/network-scan/{run_id} for status.",
    }


@app.get("/api/v1/network-scan/{run_id}")
async def get_network_scan_status(run_id: str, pool: asyncpg.Pool = Depends(get_pool)):
    async with pool.acquire() as conn:
        run = await conn.fetchrow(
            "SELECT run_id, state, scan_path, created_at, completed_at, metadata FROM workflow_runs WHERE run_id=$1",
            run_id,
        )
        if not run:
            raise HTTPException(404, f"Run {run_id} not found")
        counts = await conn.fetchrow(
            """SELECT
                COUNT(*) FILTER (WHERE severity='CRITICAL') AS critical,
                COUNT(*) FILTER (WHERE severity='HIGH')     AS high,
                COUNT(*) FILTER (WHERE severity='MEDIUM')   AS medium,
                COUNT(*) FILTER (WHERE severity='LOW')      AS low,
                COUNT(*)                                     AS total
               FROM network_findings WHERE run_id=$1""",
            run_id,
        )
    return {
        "run_id": run["run_id"],
        "status": run["state"],
        "target": run["scan_path"],
        "created_at": run["created_at"],
        "completed_at": run["completed_at"],
        "findings": dict(counts) if counts else {},
        "metadata": run["metadata"] or {},
    }


@app.get("/api/v1/network-findings/{run_id}")
async def get_network_findings(
    run_id: str,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    pool: asyncpg.Pool = Depends(get_pool),
):
    conditions = ["run_id = $1"]
    params = [run_id]
    if severity:
        params.append(severity.upper())
        conditions.append(f"severity = ${len(params)}")
    if category:
        params.append(category)
        conditions.append(f"category = ${len(params)}")
    params.extend([limit, offset])
    where = " AND ".join(conditions)

    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"""SELECT id, host, port, protocol, service, service_version,
                       check_id, severity, description, evidence, remediation,
                       cve_ids, cvss_score, category, fp_verdict, fp_confidence,
                       fp_reasoning, scan_profile, created_at
                FROM network_findings
                WHERE {where}
                ORDER BY
                    CASE severity
                        WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                        WHEN 'MEDIUM'   THEN 3 WHEN 'LOW'  THEN 4
                        ELSE 5
                    END,
                    created_at DESC
                LIMIT ${len(params)-1} OFFSET ${len(params)}""",
            *params,
        )
    return [dict(r) for r in rows]
```

---

## 9. LLM Prompt (`prompts/network_agent/v1.0/fp_analysis.yml`)

```yaml
name: network_fp_analysis
version: "1.0"
description: "Layer 3 FP analysis for network security findings"

system: |
  You are a network security analyst reviewing automated scan findings.
  Your job is to determine if a finding is a real security issue or a false positive.

  Be conservative — when in doubt, mark as REAL. Only mark as FP when the finding
  clearly represents expected, authorized, or low-risk network behavior.

  Respond ONLY with valid JSON. No markdown, no explanation outside the JSON.

user: |
  FINDING TO ANALYSE:
  Host:     {{ finding.host }}
  Port:     {{ finding.port }} / {{ finding.protocol }}
  Service:  {{ finding.service }} {{ finding.service_version }}
  Check:    {{ finding.check_id }}
  Severity: {{ finding.severity }}
  Description: {{ finding.description }}
  Evidence: {{ finding.evidence }}
  CVEs: {{ finding.cve_ids | join(", ") or "none" }}
  Environment: {{ metadata.get("environment", "unknown") }}

  {% if similar %}
  SIMILAR PAST DECISIONS:
  {% for p in similar %}
  [{{ loop.index }}] verdict={{ p.verdict }} category={{ p.fp_category or "N/A" }}
  Reasoning: {{ p.reasoning }}
  ---
  {% endfor %}
  {% endif %}

  Respond with valid JSON:
  {
    "verdict": "REAL" | "FP" | "ESCALATED",
    "confidence": 0.0-1.0,
    "fp_category": "expected-web-service" | "non-production" | "local-loopback" | "expected-admin-access" | "internal-monitoring" | null,
    "reasoning": "brief explanation"
  }
```

---

## 10. Implementation Order (Phase 1)

1. `core/config.py` — Add `NetworkScannerConfig` dataclass + field on `AppConfig`
2. `db/schema.sql` — Add `network_findings` table + 4 indexes
3. `tools/network/port_scanner_tool.py` — nmap wrapper
4. `tools/network/tls_scanner_tool.py` — testssl.sh wrapper
5. `tools/network/cve_correlator_tool.py` — OSV.dev + NVD
6. `workflows/network/port_scan_workflow.py` — LangGraph workflow
7. `workflows/network/tls_scan_workflow.py` — LangGraph workflow
8. `agents/security/network/fp_rules.yml` — Layer 1 FP rules
9. `core/fp_pipeline/network_layer1.py` — Layer 1 rule engine (mirrors `layer1_rules.py`)
10. `prompts/network_agent/v1.0/fp_analysis.yml` — LLM prompt
11. `api/agent_gateway.py` — `NetworkScanRequest` model + 3 endpoints + `_run_network_agents()`

---

## 11. Verification Steps

```bash
# 1. Start the API
python main.py serve

# 2. Quick scan on localhost
curl -X POST http://localhost:8080/api/v1/network-scan \
  -H "Content-Type: application/json" \
  -d '{"target": "127.0.0.1", "scan_profile": "quick"}'
# → {"run_id": "netscan_20260620_...", "status": "accepted"}

# 3. Poll for completion
curl http://localhost:8080/api/v1/network-scan/netscan_20260620_...
# → {"status": "completed", "findings": {"total": N, "high": N, ...}}

# 4. List findings
curl http://localhost:8080/api/v1/network-findings/netscan_20260620_...

# 5. TLS test against known-bad cert
curl -X POST http://localhost:8080/api/v1/network-scan \
  -H "Content-Type: application/json" \
  -d '{"target": "expired.badssl.com", "scan_profile": "quick"}'
# → expect CRITICAL finding for expired cert

# 6. Verify FP suppression
# Port 80 open on localhost → expect fp_verdict=FP, fp_category=expected-web-service

# 7. Check DB directly
psql -d ssdlc -c "SELECT host, port, severity, fp_verdict FROM network_findings WHERE run_id='...'"
```

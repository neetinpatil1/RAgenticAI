# Network Security Scanner — Scope Document

## Overview

RAgenticAI currently performs code-level security analysis (SAST, SCA, secrets, bytecode). This document defines the scope for a new **Network Security Scanner** capability that analyses live infrastructure targets — IP addresses, domains, CIDR ranges, and URLs — for network-layer vulnerabilities.

Network scanning is a fundamentally different discipline from code scanning:
- **Code scanner** reads files from a local path, finds bugs in source code
- **Network scanner** probes live systems over the network, finds exposed services, weak configurations, and known CVEs in running software

Both capabilities are part of the same platform but operate independently via separate API endpoints.

---

## Problem Statement

A codebase can be vulnerability-free at the source level but still be exposed at the network layer due to:
- Unnecessary open ports (attack surface expansion)
- Outdated service versions with known CVEs (e.g. OpenSSH 7.4 with CVE-2018-15473)
- Weak TLS configurations (expired certs, RC4 ciphers, POODLE/HEARTBLEED)
- Exposed admin panels, debug ports, or sensitive endpoints
- Default credentials on internal services

This scanner closes that gap.

---

## In Scope

### What Will Be Scanned
| Target Type | Example | Notes |
|-------------|---------|-------|
| Single IP | `192.168.1.10` | Full port + service scan |
| Domain | `example.com` | Resolves to IP, scans resolved host |
| CIDR Range | `10.0.0.0/24` | Scans all live hosts in range |
| URL | `https://app.example.com` | Web layer checks on specified endpoint |

### Vulnerability Categories
| Category | What It Finds | Tool |
|----------|--------------|------|
| **Port Exposure** | Open ports, services, versions, OS | nmap / masscan |
| **TLS/SSL Weaknesses** | Expired certs, weak ciphers, BEAST/POODLE/HEARTBLEED | testssl.sh / sslyze |
| **Service CVEs** | Known CVEs for detected service versions | OSV.dev + NVD API |
| **Web Misconfigurations** | Exposed admin panels, .git, env files, default creds | nuclei |
| **Web CVEs** | CVE-specific HTTP checks (Spring4Shell, Log4Shell, etc.) | nuclei community templates |

### Scan Profiles
| Profile | Port Range | NSE Scripts | Web Checks | Est. Duration |
|---------|-----------|-------------|------------|--------------|
| `quick` | Top 1,000 ports | None | No | ~60 seconds |
| `standard` | Top 10,000 ports | `safe`, `auth` | Optional | ~5 minutes |
| `deep` | All 65,535 ports | `vuln`, `exploit` | Optional | ~30 minutes |

> **Authorization required for `deep` profile** — `vuln`/`exploit` NSE scripts send intrusive probes. Requires explicit confirmation via `authorized: true` in request.

---

## Out of Scope (Phase 1)

- Authenticated scanning (scanning behind login sessions)
- Active exploitation / proof-of-concept generation
- Cloud provider API scanning (AWS Security Hub, Azure Defender)
- Container image scanning (separate capability — use Trivy)
- DNS enumeration / subdomain discovery
- Wireless network scanning
- Social engineering / phishing simulation

These may be added in future phases.

---

## Agents

### Agent 1 — Port Scanner
Scans TCP/UDP ports, identifies running services and their versions, optionally runs NSE vulnerability scripts.

**Powered by:** nmap (primary), masscan (for large CIDR ranges)
**Outputs:** Open port list with service name, version string, protocol, and NSE script results

### Agent 2 — TLS/SSL Scanner
Analyses TLS configuration on detected HTTPS/SMTPS/IMAPS and any other TLS-wrapped services.

**Powered by:** testssl.sh (primary), sslyze (Python fallback)
**Checks:** Protocol versions (SSLv2/v3, TLS 1.0/1.1 deprecated), cipher suites, certificate validity, HSTS, known attacks (BEAST, POODLE, HEARTBLEED, DROWN, ROBOT, LUCKY13)

### Agent 3 — Service CVE Correlator
Takes service/version pairs from the Port Scanner (e.g. "OpenSSH 7.4", "Apache httpd 2.4.6") and looks up known CVEs.

**Powered by:** OSV.dev API (already integrated), NVD NIST API
**Outputs:** CVE IDs, CVSS scores, fix versions, enriched onto port findings

### Agent 4 — Web Vulnerability Scanner *(optional, requires `include_web: true`)*
Runs active web vulnerability checks against HTTP/HTTPS services discovered by the Port Scanner.

**Powered by:** nuclei with ProjectDiscovery community templates (10,000+)
**Template categories:** CVEs, exposures, misconfigurations, technology detection, default credentials

### Agent 5 — Network FP Pipeline
Filters false positives from all network findings using:
- **Layer 1:** YAML rules (loopback hosts, expected ports, dev environment exemptions)
- **Layer 3:** Qwen 14B LLM for ambiguous findings (same model already used for SAST)

---

## False Positive Strategy

Network scanners generate significant noise. The FP pipeline suppresses common false positives:

| FP Pattern | Example | Rule ID |
|-----------|---------|---------|
| Loopback addresses | `127.0.0.1` port 8080 open | `loopback-host` |
| Expected web ports | Port 80/443 open on a web server | `expected-http-ports` |
| Non-production environment | SSH open on staging host | `rfc1918-dev-environment` |
| Expected admin protocols | SSH port 22 on a bastion host | `authorized-ssh` |
| Internal monitoring | Prometheus 9090 on internal network | `internal-monitoring-ports` |

High-stakes findings (open Telnet, expired production TLS cert, default credentials) are **never suppressed** by Layer 1 and always escalate to the LLM.

---

## Severity Mapping

| Severity | Network Examples |
|----------|----------------|
| **CRITICAL** | Open Telnet (cleartext), default credentials accepted, CVE CVSS ≥ 9.0, expired TLS on production |
| **HIGH** | SSLv3/TLS 1.0 enabled, POODLE/HEARTBLEED vulnerable, CVE CVSS 7.0–8.9, self-signed cert |
| **MEDIUM** | TLS 1.1 deprecated, weak cipher suites (RC4/3DES), CVE CVSS 4.0–6.9, missing HSTS |
| **LOW** | Unnecessary open port, information disclosure, CVE CVSS < 4.0 |
| **INFO** | Open ports on expected services, technology fingerprinting |

---

## API Surface

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `POST /api/v1/network-scan` | POST | Submit a new network scan |
| `GET /api/v1/network-scan/{run_id}` | GET | Get scan status and summary |
| `GET /api/v1/network-findings/{run_id}` | GET | List all findings (paginated) |
| `GET /api/v1/network-scan/{run_id}/stream` | GET | SSE live progress stream |

---

## Implementation Phases

### Phase 1 — Foundation
Port scanning + TLS analysis + CVE correlation. Core value delivered.

Deliverables:
- `POST /api/v1/network-scan` endpoint (quick + standard profiles)
- Port scanner (nmap) + TLS scanner (testssl.sh) running in parallel
- Service CVE correlation via OSV.dev
- `network_findings` database table
- Layer 1 FP rules (loopback, expected ports, non-prod)
- Basic findings list UI (host / port / severity table)

### Phase 2 — Web Vulnerability Scanning
Add nuclei for active web checks.

Deliverables:
- nuclei tool wrapper
- Web vuln workflow (optional, gated by `include_web: true`)
- Custom nuclei templates (Spring Boot actuator, H2 console, debug port 5005)
- Layer 3 LLM FP analysis for web findings

### Phase 3 — Intelligence & Learning
Add LLM enrichment and feedback loop.

Deliverables:
- LLM-generated remediation steps per finding
- Risk narrative (business impact + exploitability)
- pgvector embeddings for network findings (similar-finding retrieval)
- Human label capture for network FP decisions
- FP Challenger re-analysis for network findings

---

## Tools & Licenses

| Tool | License | Install |
|------|---------|---------|
| nmap | GPL-2.0 | `brew install nmap` |
| masscan | AGPL-3.0 | `brew install masscan` |
| testssl.sh | GPL-2.0 | `brew install testssl` |
| sslyze | Apache-2.0 | `pip install sslyze` |
| nuclei | MIT | `brew install nuclei` |

All tools are open source. No commercial licenses required.

---

## Risks & Mitigations

| Risk | Mitigation |
|------|-----------|
| Scanning unauthorized targets (legal) | Input validation: warn on public IPs, require `authorized: true` for deep profile |
| nmap/masscan blocked by firewalls | Graceful timeout handling; tool returns empty results, not crash |
| testssl.sh not installed | sslyze fallback; if both unavailable, TLS agent skips with warning |
| nuclei template updates breaking parsing | Pin nuclei version; parse `jsonl` output format (stable schema) |
| Large CIDR scans timing out | masscan for discovery pass, nmap only for live hosts; configurable timeout |
| FP pipeline misclassifying real findings | High-stakes CWEs never suppressed by Layer 1; Layer 3 always runs for CRITICAL/HIGH |

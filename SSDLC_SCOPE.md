# SSDLC Multi-Agent Platform — Project Scope & Tracking
> Based on: `SSDLC_Design_v3.2.docx` | Status: In Progress | Started: June 2025

---

## 1. Project Overview

An AI-powered, **air-gapped** Secure Software Development Lifecycle (SSDLC) platform for a regulated financial environment. It automates security scanning, code review, false-positive detection, and risk assessment using local LLMs — no internet dependency in production.

### Three Governing Rules
| # | Rule | Implication |
|---|---|---|
| 1 | Components earned by measured bottlenecks only | Start as a 6-component monolith on PostgreSQL. Add Kafka/Redis/K8s only when specific metrics demand it. |
| 2 | Organizational mechanisms are design artifacts | Governance charter, labeling flywheel, gate integrity policies are signed documents — not appendix items. Signed before code is written. |
| 3 | Hardware must match software reality | Design for actual hardware available, not aspirational server specs. |

### Three Sentences That Matter
1. Architecture is sound; residual risks are **organizational** — labeling discipline, gate integrity, human-review capacity — no further architecture iteration will fix those.
2. **Start simpler** than the full design: PostgreSQL + Ollama + Python monolith. Prove value. Add components when measurements demand them.
3. The **critical path** is the labeling flywheel and the Phase 0 gate credibility. Protect both contractually.

---

## 2. Hardware Setup

### Current: Single Mac (Development & Phase 0/1)
> Split to multiple machines when Phase 2 RAM pressure demands it.

| Component | Spec |
|---|---|
| Machine | Apple Silicon Mac (M4 or M3, 16GB unified memory) |
| Hostname | `localhost` (swap to `ssdlc-llm.local` when splitting) |
| LLM Runtime | Ollama (native Metal GPU — **no Docker layer**) |
| Database | PostgreSQL via brew |
| Agent | Python monolith (FastAPI) |

### Future: Two-Mac Split
| Mac | Chip | Role |
|---|---|---|
| Mac 1 (`ssdlc-llm.local`) | M4 16GB | Ollama + LLMs, Agent Monolith, FastAPI, tool sandboxes |
| Mac 2 (`ssdlc-platform.local`) | M3 16GB | PostgreSQL, Gitea, Vault, Grafana, Verdaccio, Nexus, ZAP |

Connected via Thunderbolt 4 bridge (40 Gbps) or 2.5GbE switch.

**Split trigger:** Phase 2 RAM pressure (ZAP + full monitoring stack) or team growth.

---

## 3. Technology Stack

### What Runs Natively (No Docker)
| Service | Install | Notes |
|---|---|---|
| Ollama + LLMs | `brew install ollama` | Metal GPU — faster without Docker overhead |
| PostgreSQL 16 + pgvector | `brew install postgresql@16` | Primary data store for everything |
| Python Agent Monolith | `.venv` (already set up) | FastAPI, LangGraph, all agents |
| Grafana + Prometheus | `brew install grafana prometheus` | Add in Phase 1 |
| HashiCorp Vault | `brew install vault` | Use env vars in Phase 0, Vault in Phase 1 |
| Gitea | Binary / `brew` | Defer to Phase 1 — use local filesystem in Phase 0 |

### What Uses Docker (Security Tool Sandboxing Only)
> Security scanners run against untrusted code. Isolation prevents malicious repos from escaping to host.

| Tool | Purpose |
|---|---|
| Semgrep | SAST scanning |
| Grype | SCA / CVE scanning |
| Trivy | Container / dependency scanning |
| Checkov | IaC security |
| Kubescape | K8s security |
| OWASP ZAP | DAST API scanning (Phase 2) |

### Package / npm Mirrors (Phase 1+, air-gap)
| Service | Purpose |
|---|---|
| Nexus OSS | PyPI proxy mirror |
| Verdaccio | npm registry mirror |

---

## 4. LLM Models

| Tier | Model | Quant | RAM | Speed (M4) | Role |
|---|---|---|---|---|---|
| Tier 1 — Primary | `qwen2.5-coder:14b` | Q4_K_M | ~10 GB | ~35 tok/sec | SAST, code review, FP arbitration, CSRA, Arch Review |
| Tier 2 — Fast | `llama3.2:3b` | Q4_K_M | ~2.5 GB | ~95 tok/sec | Classification, routing, extraction, overflow |
| Classifier | CodeBERT (FP32) | — | ~0.5 GB | <50ms | FP Layer 2 (Neural Engine) |
| Embedding | UniXcoder (FP32) | — | ~0.5 GB | <20ms | pgvector semantic search |

### Two-Tier Routing
- **~80% of calls → Tier 1** (Qwen 14B): SAST analysis, code review, FP arbitration, CSRA, Arch Review
- **~20% of calls → Tier 2** (Llama 3B): classification, structured extraction, routing decisions
- **Escalation rule:** if structured output invalid, self-confidence <0.6, or finding touches high-stakes CWE (crypto, authz, injection in payment path) → re-run on Tier 1
- **Weekly divergence check:** 25 random Tier 2 outputs re-run on Tier 1. Divergence >15% per task type → routing table update

---

## 5. Agent Roster

| Phase | Agent | Purpose |
|---|---|---|
| 0 | SAST Agent | Semgrep scan + LLM triage |
| 1 | SCA Agent | Grype/Trivy CVE scan |
| 1 | Code Review Agent | Correlates SAST + SCA, enriches with ADR context |
| 1 | FP Challenger Agent | 3-layer FP pipeline |
| 2 | DAST Agent | ZAP API/OpenAPI scanning |
| 2 | K8s Security Agent | Kubescape + Checkov |
| 2 | Arch Review Agent | Threat modelling, structured threat list |
| 2 | CSRA Agent | Aggregates all findings, risk register |
| 2 | VAPT Agent | Consolidated VAPT report |
| 3 | Dev Fix Agent | Auto-generates fix PRs |
| 3 | Test Design Agent | Test case generation |
| 3 | Test Automation Agent | Test script generation |
| 3 | Regression Agent | Regression detection |
| 3 | DevOps Agent | Config/pipeline security (4–8 wk) |
| 3 | UI/UX Security Agent | Frontend security review (4–8 wk) |

---

## 6. False Positive Pipeline

| Layer | Mechanism | Activation Gate | Coverage | Latency |
|---|---|---|---|---|
| Layer 1 | YAML rule-based pre-filter | Always active from Day 1. Rules in `security-rules/fp-rules/`. Spring Boot + Angular rules at launch. | ~30% resolved | <5ms |
| Layer 2 | CodeBERT classifier (Neural Engine) | Segment-gated: ≥150 human-confirmed labels for segment + holdout accuracy ≥85% + weekly PSI drift check green. New apps bypass L2. | ~50% of remainder | <50ms |
| Layer 3 | Qwen2.5-Coder:14b + pgvector hybrid retrieval | Ambiguous findings only (~20% of total). All findings in Phase 0 (no L2 yet). | ~20% overall | 2–8 sec |

### Layer 3 Retrieval
```sql
-- SQL pre-filter
WHERE cwe_id = :cwe AND framework = :framework AND label_status != 'QUARANTINED'
-- pgvector ANN similarity on (finding + code context) via UniXcoder
-- Re-rank: human-confirmed x1.0, human-audit x0.8, agent-only x0.4
-- Inject top-5 into prompt with labels and confidence tier
```

### Poison Control
- Retracted/overturned decision → `label_status = QUARANTINED` — excluded from retrieval and training immediately
- Quarterly: sample retrieved-precedent chains for FP-propagation patterns

---

## 7. Storage Architecture

| Data Type | Storage | Why |
|---|---|---|
| CVE / NVD / packages | Grype DB + OSV (SQLite, weekly offline) | Structured CVE-ID lookup — 50x faster than semantic search |
| OWASP controls, CWE, checklists | PostgreSQL structured tables | Versioned, deterministic, exact match |
| Historical findings, FP decisions, fix patterns, ADRs | PostgreSQL + pgvector | Atomic transactions with metadata. Eliminates separate vector store. |
| Workflow state, finding lifecycle, audit trail | PostgreSQL append-only ledger | Regulatory compliance. Authoritative truth. Never in Kafka or Redis. |
| Agent session state | PostgreSQL session tables (TTL cleanup job) | Eliminates Redis until measured bottleneck |
| Prompt templates, eval golden sets | Local YAML files (Phase 0) → Gitea (Phase 1+) | Versioned, reviewable, rollback capable |

---

## 8. Choreography Flow

No central orchestrator. Agents communicate via PostgreSQL job queue.

```
Input: local path (Phase 0) or Git repo (Phase 1+)
        ↓
Job inserted → pg_jobs  [code.batch.submitted]
        ↓
SAST Agent + SCA Agent  (parallel, SKIP LOCKED)
        ↓
Write findings → pg findings_reports
Insert next job: code_review.pending
        ↓
Code Review Agent
Correlates SAST + SCA, enriches with ADR context
Insert jobs: fp_challenge.pending
        ↓
FP Challenger Agent     Dev Fix Agent (parallel)
3-layer FP pipeline     Fix suggestions
        ↓
FP verdict → PG
        ↓
DISMISSED → auto-close
UPHELD → severity check
DEADLOCK → human queue + Grafana alert
        ↓
HIGH/CRITICAL (new findings only — baseline excluded)
        ↓
HUMAN GATE → security.gate.passed
        ↓
DAST Agent + K8s Security Agent (parallel, Phase 2+)
        ↓
CSRA Agent aggregates → CRITICAL → Human CISO dashboard

WATCHDOG (5-min scheduled job):
  SELECT runs WHERE state_age > sla_for(state)
  → alert + auto-replay if eligible
```

### State Ownership
| Domain | Owner |
|---|---|
| Intra-agent state | LangGraph (per agent — tool retries, LLM timeouts, reasoning steps) |
| Inter-agent events | PG job queue `FOR UPDATE SKIP LOCKED` (Phase 0/1) → Kafka when graduated |
| Workflow truth | PostgreSQL (always authoritative) |

---

## 9. Phases

### Phase 0 — Prove It
> **Duration:** Months 1–2 | **Gate:** ≥75% LLM–human agreement on 200 labeled findings

**Scope Adaptation:** Local path scanning (no Git), native installs (no Docker for infra), Layer 3 FP only (no CodeBERT yet).

#### Deliverables
- [x] PostgreSQL setup with pgvector extension
- [x] Ollama running `qwen2.5-coder:14b` natively
- [x] SAST Agent — accepts `--scan /local/path`, runs Semgrep (Docker sandbox), writes findings to PG
- [x] Finding enrichment — class, method, fix suggestion, OWASP category, ref URLs, likelihood, impact
- [x] Scan coverage stats — files scanned/skipped, packages by build file type
- [x] Layer 1 FP rules (YAML, Spring Boot + Angular rules)
- [x] Layer 3 FP via Qwen LLM + pgvector retrieval
- [x] Pydantic output contracts (`sast_report.py`, `fp_decision.py`)
- [x] Labeling-as-exhaust: human approve/dismiss in minimal HTML UI writes label to PG
- [x] Audit trail in PostgreSQL (append-only ledger)
- [x] Watchdog job (5-min scheduled, SLA alerts)
- [x] FastAPI endpoints: `POST /api/v1/scan`, `GET /api/v1/scan/{run_id}`, `GET /api/v1/findings`, `GET /api/v1/scan/{run_id}/stream` (SSE)
- [x] React scan UI (ScanInput + animated ScanProgress + ScanResults with expandable findings table) — served on port 8080
- [x] Air-gap setup scripts (Semgrep rules local, Grype DB local)
- [ ] Governance charter signed (before code ships to staging)

#### Still Needed for Phase 0 Gate
- [ ] Run against 200 real findings and label them via UI
- [ ] Measure ≥75% LLM–human agreement
- [ ] Sign governance charter

#### Gate Criteria
- [ ] ≥75% LLM–human agreement on 200 labeled findings
- [ ] On failure: ONE 6-week remediation sprint, then re-test
- [ ] Second failure = project stops or descopes to "AI-assisted triage tool, no autonomy"
- [ ] Hardware for Phase 1 NOT procured until this gate passes

---

### Phase 1 — Two Agents
> **Duration:** Months 3–5 | **Gate:** ≥85% L2 accuracy on ≥2 segments. FP challenge <5 min p50.

#### Deliverables
- [ ] SCA Agent (Grype + Trivy)
- [ ] Code Review Agent (correlates SAST + SCA)
- [ ] FP Challenger Agent (full 3-layer pipeline)
- [ ] PG job queue (no Kafka yet)
- [ ] Layer 2 CodeBERT classifier (segment-gated)
- [ ] Online agreement monitoring (Grafana)
- [ ] Living golden dataset (quarterly refresh)
- [ ] First kappa calibration cycle (Cohen's kappa, monthly)
- [ ] Gitea for prompts/rules versioning
- [ ] HashiCorp Vault for secrets
- [ ] React UI: `/console/findings`, `/console/labeling`, `/console/challenges`
- [ ] Git repo input support (`--repo git@...` alongside local path)

#### Gate Criteria
- [ ] ≥85% L2 accuracy on ≥2 active segments
- [ ] FP challenge round-trip <5 min p50
- [ ] Label velocity ≥ segment-activation rate
- [ ] kappa ≥0.7 (calibration meeting if below before labels enter training)

---

### Phase 2 — Security Guild
> **Duration:** Months 6–9 | **Gate:** <4h end-to-end assessment. Under-routing divergence <15%.

#### Deliverables
- [ ] DAST Agent (ZAP, API/OpenAPI mode)
- [ ] K8s Security Agent (Kubescape + Checkov)
- [ ] Arch Review Agent
- [ ] CSRA Agent + VAPT consolidation
- [ ] Baseline vs. new-finding gating live
- [ ] Routing table learning loop (weekly divergence check)
- [ ] Kafka evaluation (graduate if: PG queue p95 >30s OR >5 services need fan-out)
- [ ] Mac 2 split (if RAM pressure demands it)
- [ ] CISO Dashboard + CSRA sign-off UI

#### Gate Criteria
- [ ] End-to-end assessment <4h for standard Spring Boot microservice
- [ ] Under-routing divergence <15% all task types

---

### Phase 3 — Dev + Quality
> **Duration:** Months 10–13 | **Gate:** Human-agreement >80% all agents. Model refresh complete.

#### Deliverables
- [ ] Dev Fix Agent (PR generation)
- [ ] Test Design Agent
- [ ] Test Automation Agent
- [ ] Regression Agent
- [ ] DevOps Agent (config/pipeline security, 4–8 wk)
- [ ] UI/UX Security Agent (frontend security, 4–8 wk)
- [ ] First model refresh cycle (Qwen → newer model via golden eval)
- [ ] Full metrics dashboard
- [ ] Settings UI (FP rules editor, routing table, model manifest)

#### Gate Criteria
- [ ] Human-agreement >80% sustained across all agents
- [ ] Model refresh cycle executed (SHA-256 verified, 2-week shadow run before cutover)

---

## 10. Air-Gap Compliance

| # | Component | Gap | Resolution |
|---|---|---|---|
| 1 | Grype / Trivy DB | Nightly sync assumes internet | Weekly offline DB refresh via jump workstation → hash-verify → Nexus OSS internal URL |
| 2 | Semgrep Rules | Pulls from registry.semgrep.dev | Rules in Gitea `security-rules/semgrep/`. Invoke with `--config=file:///opt/semgrep-rules/` |
| 3 | Kubescape Frameworks | Downloads from ARMO cloud | Download on jump WS → transfer JSON → `kubescape scan --use-from /opt/kubescape/nsa.json` |
| 4 | Checkov Policies | Pulls from Bridgecrew cloud | `--external-checks-dir /opt/checkov-policies/` — policies in Gitea |
| 5 | HuggingFace Models | Downloads at runtime | `snapshot_download()` on jump WS → transfer → `local_files_only=True`. SHA-256 in `model_manifest.json` |
| 6 | Ollama LLM Weights | Reaches HuggingFace/Meta | `ollama pull` on jump WS → copy `~/.ollama/models/` via approved transfer. `OLLAMA_MODELS=/opt/ollama-models` |
| 7 | Docker Images | Pulls from Docker Hub | `docker save | gzip` on jump WS → transfer → `docker load`. `imagePullPolicy: Never` |
| 8 | pip / npm packages | Reaches PyPI / npmjs | `pip download` → Nexus OSS PyPI mirror. `npm pack` → Verdaccio. All deps pinned with `--require-hashes` |

> **Phase 0 note:** For local development, internet access is acceptable. Air-gap enforcement applies when moving to production/staging environment.

---

## 11. Governance Charter

> Signed by executive sponsor **before Phase 0 begins**. CISO explicitly empowered to fail any phase gate regardless of hardware purchased or OKRs written.

### Phase Gates
| Gate | Criteria |
|---|---|
| Phase 0 | ≥75% LLM–human agreement on 200 labeled findings. Charter-protected. |
| Hardware policy | Phase 1+ hardware NOT procured until Phase 0 gate passes. |
| Phase 1 | ≥85% L2 accuracy on ≥2 segments. FP challenge <5 min p50. |
| Phase 2 | End-to-end assessment <4h. Under-routing divergence <15%. |
| Phase 3 | Human-agreement >80% all agents. Model refresh complete. |

### Baseline vs. New Finding Policy
| Policy | Detail |
|---|---|
| First scan of any app | ALL findings recorded as BASELINE. Does NOT block releases. Enters managed remediation: monthly burn-down targets, CISO dashboard. |
| Subsequent scans | Diff vs baseline via fingerprint matching. Only NEW HIGH/CRITICAL gate releases and enter human review queue. |
| SLAs | CRITICAL: 24h. HIGH: 72h. Breach auto-escalates via Grafana alert. |
| Capacity safety valve | Review utilization >80% sustained → new app onboarding PAUSES. Explicit policy, not judgment call. |

### Agent Effort Estimate (Official)
> Each new agent role: **4–8 weeks** (~20% YAML config, 80% tool integration, output contracts, prompts, golden eval data). "Config-only scaling" is not promised.

---

## 12. Web Command Centre

**Served by FastAPI on Mac 1, port 8080. React 18 + Vite. All data from PostgreSQL.**

### User Personas & Screens
| Persona | Primary Screens |
|---|---|
| CISO | `/dashboard` — KPI tiles, gate status, critical findings requiring sign-off, reviewer capacity |
| Security Engineer | `/console/findings`, `/console/labeling`, `/console/challenges`, `/console/csra`, `/agents`, `/settings` |
| Developer / Architect | `/apps`, `/apps/:id`, `/assessments/:id` |

### Screen Inventory
| Route | Persona | Purpose |
|---|---|---|
| `/dashboard` | CISO | KPI tiles, gate status, CRITICAL findings, capacity utilization |
| `/console/findings` | Security Eng | Review queue, expandable reasoning, approve/FP with justification |
| `/console/labeling` | Security Eng | 30-min duty queue, one finding at a time, kappa + velocity shown |
| `/console/challenges` | Security Eng | FP deadlock resolution — agent vs challenger side-by-side |
| `/console/csra` | Security Eng | CSRA/VAPT outputs awaiting sign-off, risk register |
| `/apps` + `/apps/:id` | Developer | Portfolio grid → single app: pipeline, SSDLC checklist, findings, fix suggestions |
| `/assessments/:id` | All | Full assessment detail, audit trail, exportable PDF |
| `/agents` | Security Eng | Agent health, config viewer (read-only YAML), routing stats |
| `/settings` | Security Eng | FP rules editor, Semgrep sync, routing table, model manifest |

### Technical Stack
| Component | Spec |
|---|---|
| Frontend | React 18 + Vite. `shadcn/ui` + Tailwind. Recharts for dashboards. |
| Real-time | WebSocket (FastAPI native). `/ws/activity` + `/ws/alerts` |
| API | FastAPI routers on Agent Monolith. Routes: `/api/v1/dashboard`, `/findings`, `/challenges`, etc. |
| Auth | Session-token (no OAuth — air-gapped). Roles: `CISO`, `SECURITY_ENGINEER`, `DEVELOPER`. bcrypt passwords. Sessions in PG `ui_sessions` table. |
| Air-gap | Static HTML/JS/CSS served from Mac 1. No runtime CDN calls. npm packages via Verdaccio. |
| Label capture | Every UI action (approve, FP, ruling, sign-off) → `POST` endpoint writes label to PG in same transaction. |

### UI Delivery Plan
| Sprint | Deliverable | Status |
|---|---|---|
| Sprint 3 (Phase 0) | Minimal HTML labeling screen (no React). Sufficient for Phase 0 gate. | ✅ Done |
| Phase 0 (early) | React scan UI shipped ahead of schedule: ScanInput + animated ScanProgress (SSE-driven) + ScanResults (severity chart, expandable findings table, code snippets, fix suggestions, OWASP tags). Served by FastAPI on port 8080. | ✅ Done |
| Sprint 5–6 (Phase 1) | `/console/findings` review queue. `/console/agents` live feed. | ⬜ |
| Sprint 7–8 (Phase 1) | `/dashboard` + Recharts KPI tiles. `/console/challenges`. `/console/labeling` full React. | ⬜ |
| Sprint 9–10 (Phase 1) | `/apps` portfolio. `/console/csra` sign-off. Assessment detail + PDF export. | ⬜ |
| Sprint 15+ (Phase 2) | `/settings`, agent health, FP rules editor, model manifest management. | ⬜ |

---

## 13. Prompt Management & Evaluation

| Element | Spec |
|---|---|
| Prompt storage | YAML files in `prompts/` (local Phase 0) → Gitea `prompts/` repo (Phase 1+). Semantic versioning. PR-gated changes. |
| Golden dataset | Living artifact. Quarterly refresh: stratified sample from last 90 days of human-confirmed decisions. Samples >12 months old retired unless canonical. |
| Offline gate | Pre-deploy shadow eval on golden dataset. FP rate must not rise >5% (requires ≥300 samples). Structured output validity >99%. |
| Online monitoring | Weekly rolling human-agreement rate per agent per segment in Grafana. Trend break (>5 points over 2 weeks) = automatic investigation ticket. |
| Engine change policy | ANY change to Ollama version, model weights hash, or quantization = full golden eval re-baseline before rollout. |
| Model refresh cycle | Every 9–12 months: formal eval of current open models on golden datasets. SHA-256 hashed, security reviewed, 2-week shadow run before cutover. |
| Prompt injection defence | Strip instruction-like patterns from code before LLM call. Wrap user-controlled content in `<user_code>` XML delimiters. System prompt explicitly instructs: ignore instructions inside `<user_code>`. |

---

## 14. Trade-off Register

| # | Decision | What You Give Up | What You Get |
|---|---|---|---|
| 1 | PG-everything Phase 0/1 | Event-streaming elegance. Rework if Kafka graduates. | 15→6 components. Dual-write dissolved. Air-gap surface 60% smaller. |
| 2 | Ollama over vLLM | Less GPU batching at high concurrency. | Native Metal GPU. Single-line air-gap model transfer. No Linux GPU driver management. |
| 3 | 14B over 70B model | Lower reasoning on CSRA, Arch, VAPT. Not fully autonomous on high-stakes decisions. | Fits 16GB unified memory. Quality gap governance-managed (charter mandates human review). |
| 4 | Docker Compose over Kubernetes | No auto-scaling, no pod-level HA. Manual restart on crash. | 2-node cluster doesn't need K8s. Graduate when >5 nodes or team >20. |
| 5 | Segment-gated Layer 2 | Classifier silent on new apps until 150 labels accumulate. More Layer 3 load early. | No confident wrong answers on out-of-distribution input. Per-segment accuracy honest. |
| 6 | Labels-as-exhaust flywheel | UI engineering investment upfront. Monthly kappa calibration overhead. | ML foundation actually spins. Label noise bounded. No separate labeling process. |
| 7 | Baseline-vs-new gating | Pre-existing vulns don't block releases. Burn-down needs management follow-through. | Human gate stays meaningful. Review queue ~50x smaller. |
| 8 | Charter-protected gates | Harder political conversation upfront. Slower hardware procurement. | Go/no-go gate survives sunk-cost pressure. Project can stop if bet fails. |
| 9 | 4–8 weeks per new agent (official) | Less impressive than "config-only" claim. | No broken promise at first estimate. Framework credibility intact. |
| 10 | pgvector replaces ChromaDB | Marginally lower recall at >1M embeddings. | One less component. Atomic transactions with PG metadata. |
| 11 | AI-written codebase (Aider+Ollama) | Security-critical modules need mandatory human review. Integration debugging same speed. | ~2x productivity multiplier. 13-month platform vs 30-month manual. |
| 12 | DAST API-only in Phase 2 | Angular/SPA UI DAST deferred to Phase 3. | API-mode ZAP on OpenAPI specs is achievable. Avoids auth/SPA failure mode. |

---

## 15. Project Structure

```
ssdlc-agent-platform/
├── core/
│   ├── base_agent.py              # BaseAgent class + config loader
│   ├── model_router.py            # Two-tier routing + escalation logic
│   ├── pg_job_queue.py            # PG SKIP LOCKED job bus
│   ├── watchdog.py                # SLA monitor + auto-replay
│   ├── drift_monitor.py           # PSI per segment (weekly)
│   ├── audit_logger.py            # Append-only PG ledger
│   ├── prompt_manager.py          # Local YAML loader (Phase 0) → Gitea-backed (Phase 1+)
│   ├── tool_sandbox.py            # Docker isolation wrapper (security tools only)
│   ├── state/
│   │   ├── workflow_state.py      # PG workflow truth (authoritative)
│   │   ├── session_state.py       # PG session tables with TTL
│   │   └── vector_memory.py       # pgvector hybrid retrieval
│   ├── fp_pipeline/
│   │   ├── layer1_rules.py        # YAML rule-based pre-filter (<5ms)
│   │   ├── layer2_classifier.py   # Segment-gated CodeBERT wrapper
│   │   └── layer3_llm.py          # LLM + hybrid retrieval context
│   └── output_contracts/          # Pydantic v2 models — every LLM output
│       ├── sast_report.py
│       ├── fp_decision.py
│       ├── arch_review.py
│       └── csra_finding.py
├── tools/                         # Air-gapped security tool wrappers (Docker sandboxed)
│   ├── semgrep_tool.py            # --config=file:///opt/semgrep-rules/
│   ├── grype_tool.py              # GRYPE_DB_UPDATE_URL=internal-nexus
│   ├── trivy_tool.py              # TRIVY_DB_REPOSITORY=internal-registry
│   ├── zap_tool.py                # API mode, OpenAPI-driven (Phase 2)
│   ├── checkov_tool.py            # --external-checks-dir /opt/checkov/
│   └── kubescape_tool.py          # --use-from /opt/kubescape/nsa.json
├── agents/                        # Config-only specialisation
│   ├── security/sast/config.yml + fp_rules.yml
│   ├── security/dast/config.yml
│   ├── security/sca/config.yml
│   ├── security/csra/config.yml
│   ├── security/vapt/config.yml
│   ├── security/k8s_security/config.yml
│   ├── development/code_review/config.yml
│   ├── development/arch_review/config.yml
│   ├── development/fp_challenger/config.yml
│   ├── development/dev_fix/config.yml
│   ├── quality/test_design/config.yml
│   ├── quality/test_automation/config.yml
│   ├── devops/config.yml
│   └── uiux/config.yml
├── prompts/                       # Local YAML prompt store (Phase 0)
│   ├── sast_agent/v1.0/
│   ├── code_review_agent/v1.0/
│   └── golden_datasets/           # Living — quarterly refresh
├── classifier/                    # CodeBERT training + drift pipeline (Phase 1+)
│   ├── train.py
│   ├── evaluate.py
│   ├── drift_check.py
│   └── models/
├── workflows/                     # LangGraph per-agent graphs
│   ├── sast_workflow.py
│   ├── dast_workflow.py
│   └── csra_workflow.py
├── api/
│   └── agent_gateway.py           # FastAPI (port 8080)
├── ui/                            # React 18 + Vite (Phase 1+)
├── db/
│   └── migrations/                # PostgreSQL schema migrations
├── scripts/
│   └── airgap/                    # Air-gap setup scripts
├── SSDLC_SCOPE.md                 # This file
├── SSDLC_Design_v3.2.docx         # Source design document
├── main.py                        # Entry point: python main.py --scan /path
├── requirements.txt
└── pyproject.toml
```

---

## Adaptations from Original Design (v3.2)

| Original | This Implementation | Reason |
|---|---|---|
| Two-Mac deployment | Single Mac (Phase 0/1) | Simplify start; split when RAM demands it |
| Docker Compose for all infra | Native brew/binary for infra; Docker only for security scanners | Ollama + PG run better natively on Apple Silicon |
| CI/CD-triggered scans | `--scan /local/path` input (Phase 0) | Remove Git dependency for initial development |
| Gitea from Day 1 | Gitea deferred to Phase 1 | Use local filesystem for prompts/rules in Phase 0 |
| Kubernetes option | Deferred until >5 nodes or team >20 | No operational need at current scale |
| vLLM | Replaced by Ollama | Native Metal GPU; no Linux GPU driver management on macOS |

---

*Last updated: June 2026 | Source: SSDLC_Design_v3.2.docx*

# SSDLC Platform — Implementation Tracker
> Reference: `SSDLC_SCOPE.md` | Branch: `phase1` | Last Updated: Jun 2026

## Legend
| Symbol | Meaning |
|---|---|
| ✅ | Done |
| 🔄 | In Progress |
| ⬜ | Not Started |
| ❌ | Blocked |

---

## Phase 0 — Prove It (Months 1–2)
> Gate: ≥75% LLM–human agreement on 200 labeled findings

### 0.1 Infrastructure Setup
| # | Task | File(s) | Status |
|---|---|---|---|
| 0.1.1 | PostgreSQL schema (findings, jobs, audit, embeddings, labels, sessions) | `db/schema.sql` | ✅ |
| 0.1.2 | Config loader (env vars, YAML) | `core/config.py` | ✅ |
| 0.1.3 | Append-only audit logger | `core/audit_logger.py` | ✅ |
| 0.1.4 | PG job queue (SKIP LOCKED) | `core/pg_job_queue.py` | ✅ |
| 0.1.5 | Watchdog (5-min SLA monitor) | `core/watchdog.py` | ✅ |
| 0.1.6 | Workflow state (PG-backed) | `core/state/workflow_state.py` | ✅ |
| 0.1.7 | pgvector memory (hybrid retrieval) | `core/state/vector_memory.py` | ✅ |
| 0.1.8 | Prompt manager (local YAML loader) | `core/prompt_manager.py` | ✅ |

### 0.2 Output Contracts (Pydantic v2)
| # | Task | File(s) | Status |
|---|---|---|---|
| 0.2.1 | SAST report contract | `core/output_contracts/sast_report.py` | ✅ |
| 0.2.2 | FP decision contract | `core/output_contracts/fp_decision.py` | ✅ |

### 0.3 False Positive Pipeline
| # | Task | File(s) | Status |
|---|---|---|---|
| 0.3.1 | Layer 1 — YAML rule-based pre-filter | `core/fp_pipeline/layer1_rules.py` | ✅ |
| 0.3.2 | Layer 3 — LLM + pgvector hybrid retrieval | `core/fp_pipeline/layer3_llm.py` | ✅ |
| 0.3.3 | Spring Boot FP rules (YAML) | `agents/security/sast/fp_rules.yml` | ✅ |

### 0.4 Security Tools
| # | Task | File(s) | Status |
|---|---|---|---|
| 0.4.1 | Semgrep Docker sandbox wrapper | `tools/semgrep_tool.py` | ✅ |
| 0.4.2 | Finding enrichment — `class_name`, `method_name`, `fix_suggestion`, `owasp_category`, `ref_urls`, `likelihood`, `impact` | `tools/semgrep_tool.py` | ✅ |
| 0.4.3 | Code snippet reader — reads file directly; marks vulnerable lines with `>>>` | `tools/semgrep_tool.py` | ✅ |
| 0.4.4 | Scan coverage stats — files_scanned, files_skipped, packages_total, packages_by_file | `tools/semgrep_tool.py` | ✅ |

### 0.5 SAST Agent
| # | Task | File(s) | Status |
|---|---|---|---|
| 0.5.1 | SAST agent config | `agents/security/sast/config.yml` | ✅ |
| 0.5.2 | SAST LangGraph workflow | `workflows/sast_workflow.py` | ✅ |
| 0.5.3 | Prompt: system + FP analysis | `prompts/sast_agent/v1.0/` | ✅ |
| 0.5.4 | Workflow stores scan coverage in `workflow_runs.metadata` JSONB | `workflows/sast_workflow.py` | ✅ |
| 0.5.5 | INSERT all enrichment columns | `workflows/sast_workflow.py` | ✅ |

### 0.6 API & Entry Point
| # | Task | File(s) | Status |
|---|---|---|---|
| 0.6.1 | FastAPI gateway (scan, findings, label endpoints) | `api/agent_gateway.py` | ✅ |
| 0.6.2 | CLI entry point (`python main.py serve`) | `main.py` | ✅ |
| 0.6.3 | `GET /api/v1/scan/{run_id}` returns `scan_coverage` from metadata | `api/agent_gateway.py` | ✅ |
| 0.6.4 | `GET /api/v1/scan/{run_id}/stream` — SSE per-file progress, ETA, done event | `api/agent_gateway.py` | ✅ |
| 0.6.5 | `GET /api/v1/findings` — all enrichment columns; JSONB ref_urls decoded | `api/agent_gateway.py` | ✅ |
| 0.6.6 | FastAPI serves built React UI from `ui/dist/` on port 8080 | `api/agent_gateway.py` | ✅ |

### 0.7 Minimal Labeling UI
| # | Task | File(s) | Status |
|---|---|---|---|
| 0.7.1 | Plain HTML labeling screen | `api/templates/labeling.html` | ✅ |
| 0.7.2 | Label capture endpoint | `api/agent_gateway.py` | ✅ |

### 0.8 React Scan UI
| # | Task | File(s) | Status |
|---|---|---|---|
| 0.8.1 | React 18 + Vite + Tailwind + Framer Motion + Recharts scaffold | `ui/` | ✅ |
| 0.8.2 | `ScanInput` — folder path input, submit to POST /api/v1/scan | `ui/src/components/ScanInput.tsx` | ✅ |
| 0.8.3 | `ScanProgress` — animated ring, spring file counter, filename fade, ETA, SSE-driven | `ui/src/components/ScanProgress.tsx` | ✅ |
| 0.8.4 | `ScanResults` — SAST findings, expandable cards, code snippet, fix suggestion, refs | `ui/src/components/ScanResults.tsx` | ✅ |
| 0.8.5 | `CodeBlock` — line-numbered viewer, vulnerable lines highlighted | `ui/src/components/CodeBlock.tsx` | ✅ |
| 0.8.6 | `SeverityBadge` — color-coded CRITICAL/HIGH/MEDIUM/LOW/INFO pill | `ui/src/components/SeverityBadge.tsx` | ✅ |
| 0.8.7 | API client (`submitScan`, `getScanStatus`, `getFindings`, `openSseStream`) | `ui/src/lib/api.ts` | ✅ |
| 0.8.8 | TypeScript types for `Finding`, `ScanStatus`, `SseEvent`, `ScanCoverage` | `ui/src/types.ts` | ✅ |
| 0.8.9 | React build served by FastAPI on port 8080 | `api/agent_gateway.py`, `ui/dist/` | ✅ |

### 0.9 DB Schema & Migrations
| # | Task | File(s) | Status |
|---|---|---|---|
| 0.9.1 | `findings_reports` enrichment columns | `db/schema.sql` | ✅ |
| 0.9.2 | `_add_columns_if_missing()` — idempotent ALTER TABLE on startup | `db/migrations.py` | ✅ |
| 0.9.3 | `SASTFinding` Pydantic contract with all enrichment fields | `core/output_contracts/sast_report.py` | ✅ |

### 0.10 Gate Verification
| # | Task | Status |
|---|---|---|
| 0.10.1 | Run against 200 real findings | ⬜ |
| 0.10.2 | ≥75% LLM–human agreement measured | ⬜ |
| 0.10.3 | Governance charter signed | ⬜ |
| 0.10.4 | Air-gap setup scripts | ✅ |

---

## Phase 1 — Multi-Agent (Months 3–5)
> Gate: ≥85% L2 accuracy on ≥2 segments. FP challenge <5 min p50.

### 1.1 Secret Scanner Agent ✅ COMPLETE
| # | Task | File(s) | Status |
|---|---|---|---|
| 1.1.1 | Secret scanner tool — regex + Shannon entropy (22 patterns: AWS, GitHub, GitLab, Stripe, JWT, PEM, DB strings, etc.) | `tools/secret_scanner_tool.py` | ✅ |
| 1.1.2 | Secret scan LangGraph workflow | `workflows/secret_scan_workflow.py` | ✅ |
| 1.1.3 | `secret_findings` DB table + migration | `db/migrations.py` | ✅ |
| 1.1.4 | `GET /api/v1/secrets/{run_id}` endpoint | `api/agent_gateway.py` | ✅ |
| 1.1.5 | Secrets tab in React UI — summary cards, expandable rows, redacted match preview, rotation advice | `ui/src/components/ScanResults.tsx` | ✅ |

### 1.2 SCA Agent ✅ COMPLETE
> Note: Implemented with pip-audit + npm audit + OSV API (not Grype/Trivy as originally planned — no Docker dependency)

| # | Task | File(s) | Status |
|---|---|---|---|
| 1.2.1 | SCA tool — pip-audit (Python), npm audit (Node.js), OSV batch API (Maven) run concurrently | `tools/sca_tool.py` | ✅ |
| 1.2.2 | SCA LangGraph workflow | `workflows/sca_workflow.py` | ✅ |
| 1.2.3 | `dependency_findings` DB table + migration | `db/migrations.py` | ✅ |
| 1.2.4 | `GET /api/v1/dependencies/{run_id}` endpoint | `api/agent_gateway.py` | ✅ |
| 1.2.5 | Dependencies tab in React UI — ecosystem filter (ALL/python/npm/maven), CVE cards, installed/fixed version | `ui/src/components/ScanResults.tsx` | ✅ |

### 1.3 Code Review Agent ✅ COMPLETE
| # | Task | File(s) | Status |
|---|---|---|---|
| 1.3.1 | Code review agent config | `agents/development/code_review/config.yml` | ✅ |
| 1.3.2 | Code review LangGraph workflow — file enumeration, chunking, LLM review, DB store | `workflows/code_review_workflow.py` | ✅ |
| 1.3.3 | Prompt: system for code review | `prompts/code_review_agent/v1.0/system.md` | ✅ |
| 1.3.4 | `code_review_findings` DB table + migration | `db/migrations.py` | ✅ |
| 1.3.5 | `code_review_status` table — real-time progress tracking per file | `db/migrations.py` | ✅ |
| 1.3.6 | `POST /api/v1/review/{run_id}` — trigger code review | `api/agent_gateway.py` | ✅ |
| 1.3.7 | `GET /api/v1/review/{run_id}` — return findings + summary | `api/agent_gateway.py` | ✅ |
| 1.3.8 | `GET /api/v1/review/{run_id}/progress` — live progress (files done, pct, current file) | `api/agent_gateway.py` | ✅ |
| 1.3.9 | Code Review tab in React UI — trigger button, live progress bar, category filter, findings | `ui/src/components/ScanResults.tsx` | ✅ |
| 1.3.10 | Concurrent review — `Semaphore(2)` + `asyncio.gather` + `OLLAMA_NUM_PARALLEL=2` | `workflows/code_review_workflow.py` | ✅ |
| 1.3.11 | Performance tuning — `num_gpu:99`, `num_ctx:4096`, `num_predict:512`, 50-file cap, skip test/generated files | `workflows/code_review_workflow.py` | ✅ |

### 1.4 Parallel Agent Execution ✅ COMPLETE
| # | Task | File(s) | Status |
|---|---|---|---|
| 1.4.1 | `_run_all_agents()` — SAST + Secret + SCA run via `asyncio.gather(return_exceptions=True)` | `api/agent_gateway.py` | ✅ |
| 1.4.2 | SAST takes ~10s, Secrets ~2s, SCA ~30–40s — all parallel, no blocking | `api/agent_gateway.py` | ✅ |

### 1.5 Scan History ✅ COMPLETE
| # | Task | File(s) | Status |
|---|---|---|---|
| 1.5.1 | `GET /api/v1/runs` — list recent scans with per-run severity counts | `api/agent_gateway.py` | ✅ |
| 1.5.2 | `ScanHistory` component — table of past runs, click to view results | `ui/src/components/ScanHistory.tsx` | ✅ |
| 1.5.3 | `NavBar` — New Scan / History navigation | `ui/src/components/NavBar.tsx` | ✅ |

### 1.6 React UI — Full Multi-Agent Dashboard ✅ COMPLETE
| # | Task | File(s) | Status |
|---|---|---|---|
| 1.6.1 | 4-tab layout: SAST / Secrets / Dependencies / Code Review | `ui/src/components/ScanResults.tsx` | ✅ |
| 1.6.2 | Combined severity pie chart — all agents (SAST + Secrets + Deps + Code Review) | `ui/src/components/ScanResults.tsx` | ✅ |
| 1.6.3 | Severity filter applies to active tab; per-tab counts in filter buttons | `ui/src/components/ScanResults.tsx` | ✅ |
| 1.6.4 | Per-severity breakdown mini-cards (all agents combined) | `ui/src/components/ScanResults.tsx` | ✅ |
| 1.6.5 | Agent progress panel — all 4 agents with live status, progress bars, done/running state | `ui/src/components/ScanResults.tsx` | ✅ |
| 1.6.6 | SCA/Secrets tabs show animated "running" placeholder while agents are still scanning | `ui/src/components/ScanResults.tsx` | ✅ |
| 1.6.7 | Summary cards: Files Scanned / SAST Findings / Vulnerable Deps / Secrets Found | `ui/src/components/ScanResults.tsx` | ✅ |
| 1.6.8 | Deps + Secrets polling (retry every 5s) until parallel agents complete | `ui/src/components/ScanResults.tsx` | ✅ |
| 1.6.9 | TypeScript types for `SecretFinding`, `SecretSummary`, `DependencyFinding`, `DependencySummary` | `ui/src/types.ts` | ✅ |
| 1.6.10 | API client functions for secrets, deps, code review, progress | `ui/src/lib/api.ts` | ✅ |

### 1.7 Semgrep Rule Fixes ✅ COMPLETE
| # | Task | File(s) | Status |
|---|---|---|---|
| 1.7.1 | Fixed YAML parse error: quoted mutable default arg pattern (`def $FUNC(..., $PARAM=[], ...)`) | `agents/security/sast/rules/custom/performance_quality.yml` | ✅ |
| 1.7.2 | Fixed YAML parse error: quoted dangerouslySetInnerHTML patterns | `agents/security/sast/rules/custom/javascript_security.yml` | ✅ |
| 1.7.3 | Semgrep exit code 2 treated as warn-and-continue (not fatal) if stdout non-empty | `tools/semgrep_tool.py` | ✅ |

### 1.8 — In Progress
| # | Task | File(s) | Status |
|---|---|---|---|
| 1.8.1 | FP Challenger Agent — LangGraph workflow (L1→L3 second pass), fp_challenge_status table, 3 API endpoints, auto-enqueue from SAST | `workflows/fp_challenger_workflow.py`, `db/migrations.py`, `workflows/sast_workflow.py`, `api/agent_gateway.py` | ✅ |
| 1.8.2 | Layer 2 CodeBERT classifier | `core/fp_pipeline/layer2_classifier.py` | ⬜ |
| 1.8.3 | Online agreement monitoring (Grafana) | `core/drift_monitor.py` | ⬜ |
| 1.8.4 | Living golden dataset | `prompts/golden_datasets/` | ⬜ |
| 1.8.5 | Gitea integration for prompts/rules | `core/prompt_manager.py` | ⬜ |
| 1.8.6 | HashiCorp Vault secrets | config | ⬜ |
| 1.8.7 | Git repo input support | `main.py` | ⬜ |

---

## Phase 2 — Security Guild (Months 6–9)
> Gate: <4h end-to-end. Under-routing divergence <15%.

| # | Task | File(s) | Status |
|---|---|---|---|
| 2.1 | DAST Agent (ZAP, API mode) | `agents/security/dast/`, `tools/zap_tool.py` | ⬜ |
| 2.2 | K8s Security Agent (Kubescape + Checkov) | `agents/security/k8s_security/` | ⬜ |
| 2.3 | Arch Review Agent | `agents/development/arch_review/` | ⬜ |
| 2.4 | CSRA Agent | `agents/security/csra/` | ⬜ |
| 2.5 | VAPT consolidation | `agents/security/vapt/` | ⬜ |
| 2.6 | Baseline vs. new-finding gating | `core/pg_job_queue.py` | ⬜ |
| 2.7 | Routing table learning loop | `core/model_router.py` | ⬜ |
| 2.8 | Mac 2 split (if RAM demands) | infra | ⬜ |

---

## Phase 3 — Dev + Quality (Months 10–13)
> Gate: Human-agreement >80% all agents. Model refresh complete.

| # | Task | File(s) | Status |
|---|---|---|---|
| 3.1 | Dev Fix Agent (PR generation) | `agents/development/dev_fix/` | ⬜ |
| 3.2 | Test Design Agent | `agents/quality/test_design/` | ⬜ |
| 3.3 | Test Automation Agent | `agents/quality/test_automation/` | ⬜ |
| 3.4 | Regression Agent | `agents/quality/regression/` | ⬜ |
| 3.5 | DevOps Agent | `agents/devops/` | ⬜ |
| 3.6 | UI/UX Security Agent | `agents/uiux/` | ⬜ |
| 3.7 | First model refresh cycle | ops runbook | ⬜ |
| 3.8 | Full React Command Centre | `ui/` | ⬜ |

---

## Decisions & Notes Log

| Date | Decision | Reason |
|---|---|---|
| Jun 2026 | SCA implemented with pip-audit + npm audit + OSV API instead of Grype/Trivy | Avoids Docker for SCA; pip-audit and OSV API give same CVE coverage for Python/Node/Maven without container overhead |
| Jun 2026 | Secret scanner is custom Python (regex + Shannon entropy) — not a third-party tool | No third-party scanner had the right balance of zero-FP on placeholder values and high entropy detection needed |
| Jun 2026 | `OLLAMA_NUM_PARALLEL=2` set in Ollama launchd plist (not shell env) | Brew service restarts Ollama via launchd; shell env vars are not inherited — must set in plist EnvironmentVariables |
| Jun 2026 | Code review runs 2 files concurrently (`Semaphore(2)`) matching `OLLAMA_NUM_PARALLEL=2` | Throughput doubles on Apple Silicon without exceeding Ollama's parallel slots |
| Jun 2026 | `num_gpu:99` in Ollama options forces all model layers onto Metal GPU | Without this flag some layers stay on CPU; GPU-only path gives ~3× throughput on M-series |
| Jun 2026 | Code review skips test/spec/mock/migration/generated files, caps at 50 files | Reduces review time from 30+ min to ~8 min; high-value files reviewed first |
| Jun 2026 | React scan UI (ScanInput + ScanProgress + ScanResults) shipped in Phase 0 ahead of schedule | User needed working UI to view enriched findings |
| Jun 2026 | FastAPI serves React `ui/dist/` on port 8080 — single port | Simplify dev and prod; no cross-origin issues |
| Jun 2026 | SSE chosen for real-time scan progress over WebSocket | Simpler one-way stream; WebSocket reserved for Phase 1 bidirectional agent activity |
| Jun 2026 | `references` column renamed to `ref_urls` | PostgreSQL reserved keyword conflict |
| Jun 2026 | asyncpg JSONB columns decoded manually before API response | asyncpg returns JSONB as raw string; `.map()` on string crashes React silently |
| Jun 2026 | Phase 0 code-complete — 0.10.1–0.10.3 are operational gates (run real scans, measure agreement, sign charter) | — |
| Jun 2025 | Local path scanning for Phase 0 (no Git) | Remove Git dependency for initial dev |
| Jun 2025 | Single Mac setup | Simplify start; split when RAM demands |
| Jun 2025 | Native installs (no Docker for infra) | Ollama + PG run better natively on Apple Silicon |
| Jun 2025 | Docker only for security tool sandboxes | Scanners run against untrusted code — isolation needed |
| Jun 2025 | Gitea deferred to Phase 1 | Use local YAML files in Phase 0 |

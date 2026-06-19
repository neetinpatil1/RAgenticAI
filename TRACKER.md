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

### 1.9 CVE Reachability Analyzer — Not Started
> Determines whether a CVE found in a dependency is actually reachable from application code.
> Handles direct imports, transitive deps (parent lib calls child lib), and multi-hop call chains.
> Triggered automatically after SCA completes when CVE count > 0. Results written back to dependency_findings.
> Tech: pure Python — javatools (1 new pip dep), zipfile stdlib, mvn/npm subprocess, existing Tree-sitter call graph, Ollama llama3.2:3b.

#### Phase A — CVE Enrichment
| # | Task | File(s) | Status |
|---|---|---|---|
| 1.9.1 | CVE Enricher — fetch full OSV.dev record per CVE; extract `affected_functions` (class/method) when present; fall back to LLM extraction from CVE description for the ~70% of CVEs with no structured class data | `tools/cve_enricher.py` | ⬜ |
| 1.9.2 | Hardcoded known-CVE map for famous CVEs (Log4Shell → `JndiLookup.lookup`, SpringShell → `SerializationUtils.deserialize`, etc.) | `tools/cve_enricher.py` | ⬜ |

#### Phase B — Dependency Tree (Multi-Ecosystem)
| # | Task | File(s) | Status |
|---|---|---|---|
| 1.9.3 | Maven dep tree — parse `pom.xml` with `xml.etree` (stdlib); no Maven required; extracts direct + declared transitive deps | `tools/reachability/dep_tree.py` | ⬜ |
| 1.9.4 | Maven transitive tree — subprocess `mvn dependency:tree -DoutputType=json` when Maven available; fall back to pom.xml parse only | `tools/reachability/dep_tree.py` | ⬜ |
| 1.9.5 | npm dep tree — parse `package-lock.json` with stdlib `json`; full transitive tree without requiring npm | `tools/reachability/dep_tree.py` | ⬜ |
| 1.9.6 | Python dep tree — parse `requirements.txt`, `Pipfile.lock`, `pyproject.toml` with stdlib | `tools/reachability/dep_tree.py` | ⬜ |
| 1.9.7 | Gradle dep tree — best-effort parse of `build.gradle`; mark UNKNOWN if can't resolve | `tools/reachability/dep_tree.py` | ⬜ |

#### Phase C — Library Internal Call Analysis
| # | Task | File(s) | Status |
|---|---|---|---|
| 1.9.8 | JAR unpacker — stdlib `zipfile` to extract `.class` files from JARs/WARs into temp dir | `tools/reachability/jar_analyzer.py` | ⬜ |
| 1.9.9 | Java bytecode analyzer — `javatools` (1 new pip dep) to parse `.class` constant pool; extract `invokevirtual`/`invokestatic`/`invokeinterface` call refs; builds internal call map: Parent method → Child class/method | `tools/reachability/jar_analyzer.py` | ⬜ |
| 1.9.10 | JS/npm source analyzer — read `node_modules/<parent>/` JS source; regex + grep for calls to child package's vulnerable export; handles `require()` and ES6 `import` | `tools/reachability/js_analyzer.py` | ⬜ |
| 1.9.11 | Python source analyzer — stdlib `ast.parse()` on `site-packages/<parent>/` source; walk AST for calls to child package's vulnerable function | `tools/reachability/py_analyzer.py` | ⬜ |
| 1.9.12 | Spring/AOP/reflection detector — flag when `.class` bytecode contains `java.lang.reflect` or Spring AOP patterns; mark affected chain segments as UNKNOWN | `tools/reachability/jar_analyzer.py` | ⬜ |

#### Phase D — App Call Graph → Reachability Chain
| # | Task | File(s) | Status |
|---|---|---|---|
| 1.9.13 | Import scanner — scan app source for direct imports of vulnerable class (fastest path); handles direct import, wildcard import, aliased import | `tools/reachability/import_scanner.py` | ⬜ |
| 1.9.14 | Call chain assembler — join: app call graph (existing Tree-sitter) + parent lib internal calls (Phase C) + CVE vulnerable method (Phase A) → full evidence chain `App.method() → Parent.x() → Child.vulnerable()` | `tools/reachability/chain_assembler.py` | ⬜ |
| 1.9.15 | Transitive depth limit — cap chain traversal at 5 hops; beyond that mark UNKNOWN (avoid infinite loops in circular dep graphs) | `tools/reachability/chain_assembler.py` | ⬜ |
| 1.9.16 | LLM verdict for UNKNOWN cases — send CVE description + app usage snippets to `llama3.2:3b`; ask if vulnerable functionality is triggered; return `LIKELY_REACHABLE`/`LIKELY_NOT_REACHABLE` with confidence | `tools/reachability/llm_verdict.py` | ⬜ |

#### Phase E — Storage, API, Workflow, UI
| # | Task | File(s) | Status |
|---|---|---|---|
| 1.9.17 | DB migration — add columns to `dependency_findings`: `affected_classes TEXT[]`, `reachability TEXT`, `reach_evidence TEXT`, `reach_confidence FLOAT`, `reach_source TEXT` | `db/migrations.py` | ⬜ |
| 1.9.18 | Reachability LangGraph workflow — orchestrates Phase A→D; triggered after SCA; writes verdict per CVE as each completes (progressive results) | `workflows/reachability_workflow.py` | ⬜ |
| 1.9.19 | Workflow trigger — in `_run_all_agents()`: after SCA gather, if `sca_result.findings_count > 0` launch `reachability_workflow` as background task | `api/agent_gateway.py` | ⬜ |
| 1.9.20 | `GET /api/v1/dependencies/{run_id}` — extend response to include `reachability`, `reach_evidence`, `reach_source`, `affected_classes` per finding | `api/agent_gateway.py` | ⬜ |
| 1.9.21 | `GET /api/v1/scan/{run_id}` — add `agents.reachability_done` flag (written to `workflow_runs.metadata` when workflow completes) | `api/agent_gateway.py`, `workflows/reachability_workflow.py` | ⬜ |
| 1.9.22 | UI — Reachability agent card in pipeline status grid (6th card); shows `not started → running → done` | `ui/src/components/ScanResults.tsx` | ⬜ |
| 1.9.23 | UI — Reachability badge on each CVE row: `⚡ REACHABLE`, `✓ NOT_REACHABLE`, `? UNKNOWN`, `~ LIKELY_NOT_REACHABLE (LLM)` | `ui/src/components/ScanResults.tsx` | ⬜ |
| 1.9.24 | UI — Expandable evidence panel per CVE: full call chain `App.method() → Parent.x() [spring-web.jar] → Child.vuln() [CVE class]`, source file + line | `ui/src/components/ScanResults.tsx` | ⬜ |
| 1.9.25 | Add `javatools` to `requirements.txt` — only new pip dependency for the entire feature | `requirements.txt` | ⬜ |

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

### 2.9 Deep Reachability Analysis — SpotBugs + FindSecBugs + Eclipse Steady
> Replaces/augments heuristic jar-bytecode string search with call-graph-based reachability.
> Prerequisite: project must be compilable (Maven/Gradle build succeeds locally).
> See SSDLC_SCOPE.md §13b Decision #13 for full rationale and concerns.

| # | Task | File(s) | Status |
|---|---|---|---|
| 2.9.1 | FindSecBugs runner — wrap `spotbugs -plugin findsecbugs.jar` as subprocess; parse XML output → `SASTFinding` list; runs on compiled `target/classes/` or WAR | `tools/spotbugs_tool.py` | ✅ |
| 2.9.2 | FindSecBugs findings → DB — deduplicate against Semgrep findings (same file/line/rule); insert net-new findings only; tag `source=findsecbugs` | `workflows/spotbugs_workflow.py` | ✅ |
| 2.9.3 | Build detection — before invoking SpotBugs, check if `target/classes/` or `*.war` exists; if not, attempt `mvn compile -q`; if build fails skip SpotBugs gracefully | `tools/spotbugs_tool.py` | ✅ |
| 2.9.4 | Eclipse Steady integration — REST API client against local Steady server (Docker); extract `reachability` verdict per CVE from call-graph analysis | `tools/steady_tool.py` | ✅ |
| 2.9.5 | Steady verdict writer — update `dependency_findings.reachability` + `reach_evidence` with Steady call-chain evidence; override heuristic verdict when Steady confidence > current | `workflows/reachability_workflow.py` | ✅ |
| 2.9.6 | SpotBugs + Steady always-on — run in parallel with SAST/Secrets/SCA on every scan (not gated on `--deep`); skip gracefully for non-Java projects | `api/agent_gateway.py` | ✅ |
| 2.9.7 | Steady server Docker setup — `docker/steady/docker-compose.yml` with haproxy + rest-backend + postgresql; OrbStack for macOS ARM64 | `docker/steady/docker-compose.yml` | ✅ |
| 2.9.8 | FindSecBugs CLI bundling — auto-download `findsecbugs-cli-1.14.0.zip` to `tools/vendor/` at first scan; CRLF fix; two-pass javac fallback for Java EE projects | `tools/spotbugs_tool.py`, `tools/vendor/` | ✅ |

### 2.10 Deep Code Analysis — CodeQL
> Interprocedural SAST via full data-flow + taint analysis. Finds injection chains Semgrep misses (cross-method, cross-file).
> Requires CodeQL CLI installed (`brew install codeql`). Triggered only via `deep=true` scan param.
> See SSDLC_SCOPE.md §13c for rationale and licence concerns.

| # | Task | File(s) | Status |
|---|---|---|---|
| 2.10.1 | CodeQL CLI wrapper — auto-detect CLI, create DB (with Maven build), run security query pack, parse SARIF → SASTFinding | `tools/codeql_tool.py` | ✅ |
| 2.10.2 | CodeQL LangGraph workflow — runs after SAST; inserts net-new findings (dedup by file/line/rule); writes codeql_done flag | `workflows/codeql_workflow.py` | ✅ |
| 2.10.3 | `deep=true` scan param — triggers CodeQL + SpotBugs + Steady; normal scans unaffected | `api/agent_gateway.py` | ✅ |
| 2.10.4 | `codeql_done` agent flag in scan status | `api/agent_gateway.py`, `ui/src/types.ts` | ✅ |
| 2.10.5 | CodeQL install doc — brew install steps, licence note, query pack setup | `docs/codeql_setup.md` | ✅ |

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

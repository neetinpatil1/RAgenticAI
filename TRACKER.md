# SSDLC Platform — Implementation Tracker
> Reference: `SSDLC_SCOPE.md` | Branch: `phase1` | Started: June 2025

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

### 0.5 SAST Agent
| # | Task | File(s) | Status |
|---|---|---|---|
| 0.5.1 | SAST agent config | `agents/security/sast/config.yml` | ✅ |
| 0.5.2 | SAST LangGraph workflow | `workflows/sast_workflow.py` | ✅ |
| 0.5.3 | Prompt: system + FP analysis | `prompts/sast_agent/v1.0/` | ✅ |

### 0.6 API & Entry Point
| # | Task | File(s) | Status |
|---|---|---|---|
| 0.6.1 | FastAPI gateway (`POST /api/v1/scan`) | `api/agent_gateway.py` | ✅ |
| 0.6.2 | CLI entry point (`--scan /path`) | `main.py` | ✅ |

### 0.7 Minimal Labeling UI
| # | Task | File(s) | Status |
|---|---|---|---|
| 0.7.1 | Plain HTML labeling screen (no React) | `api/templates/labeling.html` | ⬜ |
| 0.7.2 | Label capture endpoint (`POST /api/v1/label`) | `api/agent_gateway.py` | ⬜ |

### 0.8 Gate Verification
| # | Task | Status |
|---|---|---|
| 0.8.1 | Run against 200 real findings | ⬜ |
| 0.8.2 | ≥75% LLM–human agreement measured | ⬜ |
| 0.8.3 | Governance charter signed | ⬜ |
| 0.8.4 | Air-gap setup scripts tested | ⬜ |

---

## Phase 1 — Two Agents (Months 3–5)
> Gate: ≥85% L2 accuracy on ≥2 segments. FP challenge <5 min p50.

| # | Task | File(s) | Status |
|---|---|---|---|
| 1.1 | SCA Agent (Grype + Trivy) | `agents/security/sca/`, `tools/grype_tool.py` | ⬜ |
| 1.2 | Code Review Agent | `agents/development/code_review/`, `workflows/code_review_workflow.py` | ⬜ |
| 1.3 | FP Challenger Agent | `agents/development/fp_challenger/`, `workflows/fp_challenger_workflow.py` | ⬜ |
| 1.4 | Layer 2 CodeBERT classifier | `core/fp_pipeline/layer2_classifier.py`, `classifier/` | ⬜ |
| 1.5 | Online agreement monitoring (Grafana) | `core/drift_monitor.py` | ⬜ |
| 1.6 | Living golden dataset | `prompts/golden_datasets/` | ⬜ |
| 1.7 | Gitea integration for prompts/rules | `core/prompt_manager.py` update | ⬜ |
| 1.8 | HashiCorp Vault secrets | config update | ⬜ |
| 1.9 | React UI foundation | `ui/` | ⬜ |
| 1.10 | Git repo input support | `main.py` update | ⬜ |

---

## Phase 2 — Security Guild (Months 6–9)
> Gate: <4h end-to-end. Under-routing divergence <15%.

| # | Task | File(s) | Status |
|---|---|---|---|
| 2.1 | DAST Agent (ZAP, API mode) | `agents/security/dast/`, `tools/zap_tool.py` | ⬜ |
| 2.2 | K8s Security Agent (Kubescape + Checkov) | `agents/security/k8s_security/`, `tools/kubescape_tool.py`, `tools/checkov_tool.py` | ⬜ |
| 2.3 | Arch Review Agent | `agents/development/arch_review/` | ⬜ |
| 2.4 | CSRA Agent | `agents/security/csra/` | ⬜ |
| 2.5 | VAPT consolidation | `agents/security/vapt/` | ⬜ |
| 2.6 | Baseline vs. new-finding gating | `core/pg_job_queue.py` update | ⬜ |
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
> Running log of implementation decisions. Add new entries at top.

| Date | Decision | Reason |
|---|---|---|
| Jun 2025 | Local path scanning for Phase 0 (no Git) | Remove Git dependency for initial dev |
| Jun 2025 | Single Mac setup | Simplify start; split when RAM demands |
| Jun 2025 | Native installs (no Docker for infra) | Ollama + PG run better natively on Apple Silicon |
| Jun 2025 | Docker only for security tool sandboxes | Scanners run against untrusted code — isolation needed |
| Jun 2025 | Gitea deferred to Phase 1 | Use local YAML files in Phase 0 |

-- =============================================================================
-- SSDLC Multi-Agent Platform — PostgreSQL Schema
-- Phase 0: Core tables for SAST findings, job queue, audit, labels, embeddings
-- =============================================================================
-- Run once:
--   psql -U postgres -c "CREATE DATABASE ssdlc;"
--   psql -U postgres -d ssdlc -f db/schema.sql
-- =============================================================================

-- Enable pgvector extension for semantic similarity search (Layer 3 FP pipeline)
CREATE EXTENSION IF NOT EXISTS vector;

-- Enable uuid generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =============================================================================
-- WORKFLOW RUNS
-- Master record for each scan job. One row per scan invocation.
-- =============================================================================
CREATE TABLE IF NOT EXISTS workflow_runs (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    run_id          TEXT UNIQUE NOT NULL,           -- human-readable: scan_20250617_143022
    scan_path       TEXT NOT NULL,                  -- local path or git repo URL
    state           TEXT NOT NULL DEFAULT 'pending',-- pending|running|completed|failed|cancelled
    agent           TEXT NOT NULL DEFAULT 'sast',   -- which agent owns this run
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    error_msg       TEXT,                           -- populated on failure
    metadata        JSONB DEFAULT '{}'              -- arbitrary run context
);

-- Index for watchdog SLA queries (finds stale runs quickly)
CREATE INDEX IF NOT EXISTS idx_workflow_runs_state_created
    ON workflow_runs (state, created_at);

-- =============================================================================
-- PG JOB QUEUE
-- Central choreography bus. Agents pick up jobs via FOR UPDATE SKIP LOCKED.
-- Replaces Kafka in Phase 0/1 — graduate to Kafka only when p95 dispatch >30s.
-- =============================================================================
CREATE TABLE IF NOT EXISTS pg_jobs (
    id              BIGSERIAL PRIMARY KEY,
    job_type        TEXT NOT NULL,                  -- code.batch.submitted | fp_challenge.pending | etc.
    run_id          TEXT NOT NULL,                  -- links to workflow_runs.run_id
    payload         JSONB NOT NULL DEFAULT '{}',    -- job-specific data
    state           TEXT NOT NULL DEFAULT 'pending',-- pending|processing|done|failed
    priority        INT NOT NULL DEFAULT 5,         -- 1=highest, 10=lowest
    attempt_count   INT NOT NULL DEFAULT 0,
    max_attempts    INT NOT NULL DEFAULT 3,
    scheduled_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    picked_at       TIMESTAMPTZ,
    done_at         TIMESTAMPTZ,
    error_msg       TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Critical: supports FOR UPDATE SKIP LOCKED — workers compete for pending jobs
CREATE INDEX IF NOT EXISTS idx_pg_jobs_pickup
    ON pg_jobs (state, priority, scheduled_at)
    WHERE state = 'pending';

CREATE INDEX IF NOT EXISTS idx_pg_jobs_run_id ON pg_jobs (run_id);

-- =============================================================================
-- FINDINGS REPORTS
-- Each row is one security finding from a SAST/SCA/DAST tool.
-- Fingerprint ensures deduplication across runs (baseline vs new logic).
-- =============================================================================
CREATE TABLE IF NOT EXISTS findings_reports (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    run_id          TEXT NOT NULL REFERENCES workflow_runs(run_id),
    fingerprint     TEXT NOT NULL,                  -- sha256(rule+file+line) for dedup
    tool            TEXT NOT NULL,                  -- semgrep|grype|trivy|zap|checkov
    rule_id         TEXT NOT NULL,                  -- e.g. java.spring.security.injection
    cwe_id          TEXT,                           -- e.g. CWE-89
    severity        TEXT NOT NULL,                  -- CRITICAL|HIGH|MEDIUM|LOW|INFO
    file_path       TEXT NOT NULL,
    line_start      INT,
    line_end        INT,
    code_snippet    TEXT,                           -- surrounding code context
    message         TEXT NOT NULL,                  -- tool's finding description
    framework       TEXT,                           -- spring-boot|angular|django|etc.
    is_baseline     BOOLEAN NOT NULL DEFAULT FALSE, -- TRUE = first scan, doesn't gate release
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_findings_run_id ON findings_reports (run_id);
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings_reports (fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings_reports (severity);
-- Supports Layer 3 pgvector SQL pre-filter
CREATE INDEX IF NOT EXISTS idx_findings_cwe_framework ON findings_reports (cwe_id, framework);

-- =============================================================================
-- FP DECISIONS
-- Outcome of the 3-layer FP pipeline for each finding.
-- verdict: REAL | FP | ESCALATED | DEADLOCK
-- source:  layer1 | layer3_llm | human
-- =============================================================================
CREATE TABLE IF NOT EXISTS fp_decisions (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    finding_id      UUID NOT NULL REFERENCES findings_reports(id),
    run_id          TEXT NOT NULL,
    verdict         TEXT NOT NULL,                  -- REAL|FP|ESCALATED|DEADLOCK
    source          TEXT NOT NULL,                  -- layer1|layer3_llm|human
    confidence      FLOAT,                          -- 0.0–1.0 from LLM self-assessment
    fp_category     TEXT,                           -- test-code|config-only|framework-safe|etc.
    reasoning       TEXT,                           -- LLM or rule explanation
    label_status    TEXT NOT NULL DEFAULT 'agent-only', -- agent-only|human-audit|human-confirmed|QUARANTINED
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reviewed_at     TIMESTAMPTZ                     -- set when human reviews
);

CREATE INDEX IF NOT EXISTS idx_fp_decisions_finding_id ON fp_decisions (finding_id);
-- Excludes quarantined records from Layer 3 retrieval (see vector_memory.py)
CREATE INDEX IF NOT EXISTS idx_fp_decisions_label_status ON fp_decisions (label_status)
    WHERE label_status != 'QUARANTINED';

-- =============================================================================
-- FINDING EMBEDDINGS
-- pgvector embeddings for Layer 3 semantic similarity retrieval.
-- Generated by UniXcoder on (finding message + code snippet).
-- 768 dimensions = UniXcoder default output size.
-- =============================================================================
CREATE TABLE IF NOT EXISTS finding_embeddings (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    finding_id      UUID NOT NULL REFERENCES findings_reports(id),
    fp_decision_id  UUID REFERENCES fp_decisions(id),
    embedding       vector(768) NOT NULL,           -- UniXcoder FP32 output
    label_status    TEXT NOT NULL DEFAULT 'agent-only',
    confidence_weight FLOAT NOT NULL DEFAULT 0.4,  -- human-confirmed=1.0, audit=0.8, agent=0.4
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- HNSW index for fast ANN similarity search (pgvector)
CREATE INDEX IF NOT EXISTS idx_finding_embeddings_hnsw
    ON finding_embeddings USING hnsw (embedding vector_cosine_ops);

CREATE INDEX IF NOT EXISTS idx_finding_embeddings_finding_id
    ON finding_embeddings (finding_id);

-- =============================================================================
-- HUMAN LABELS
-- Every human action in the platform automatically emits a label (exhaust model).
-- Labels are training data for Layer 2 CodeBERT classifier.
-- =============================================================================
CREATE TABLE IF NOT EXISTS human_labels (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    finding_id      UUID NOT NULL REFERENCES findings_reports(id),
    fp_decision_id  UUID REFERENCES fp_decisions(id),
    labeler_id      TEXT NOT NULL,                  -- reviewer username
    verdict         TEXT NOT NULL,                  -- REAL|FP
    fp_category     TEXT,                           -- populated if verdict=FP
    justification   TEXT,                           -- mandatory for FP dismissal
    confidence_tier TEXT NOT NULL DEFAULT 'human-confirmed', -- human-confirmed|human-audit
    weight          FLOAT NOT NULL DEFAULT 1.0,     -- 1.0=confirmed, 0.8=audit
    -- Segment key for Layer 2 gating (activates per app+ruleset+language)
    segment_app     TEXT,
    segment_ruleset TEXT,
    segment_lang    TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_human_labels_finding_id ON human_labels (finding_id);
-- Segment-based count for Layer 2 activation gate (needs ≥150 per segment)
CREATE INDEX IF NOT EXISTS idx_human_labels_segment
    ON human_labels (segment_app, segment_ruleset, segment_lang);

-- =============================================================================
-- AUDIT LOG
-- Append-only ledger. NEVER updated or deleted. Regulatory compliance.
-- Every agent action, human decision, and system event is recorded here.
-- =============================================================================
CREATE TABLE IF NOT EXISTS audit_log (
    id              BIGSERIAL PRIMARY KEY,
    event_type      TEXT NOT NULL,                  -- finding.created|fp.decided|label.captured|job.dispatched|etc.
    actor           TEXT NOT NULL,                  -- agent name or user id
    run_id          TEXT,
    entity_type     TEXT,                           -- finding|job|label|workflow_run
    entity_id       TEXT,
    payload         JSONB NOT NULL DEFAULT '{}',    -- full event context
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Audit log is append-only — no updates or deletes permitted
-- Queries by run or entity type for investigation
CREATE INDEX IF NOT EXISTS idx_audit_log_run_id ON audit_log (run_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_event_type ON audit_log (event_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_entity ON audit_log (entity_type, entity_id);

-- =============================================================================
-- AGENT SESSIONS
-- Short-lived intra-agent state. TTL-cleaned by watchdog.
-- Eliminates Redis until measured bottleneck demands it.
-- =============================================================================
CREATE TABLE IF NOT EXISTS agent_sessions (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id        TEXT NOT NULL,
    session_id      TEXT NOT NULL UNIQUE,
    run_id          TEXT,
    state_data      JSONB NOT NULL DEFAULT '{}',    -- agent's current state snapshot
    expires_at      TIMESTAMPTZ NOT NULL,           -- TTL: typically NOW() + interval '1 hour'
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agent_sessions_session_id ON agent_sessions (session_id);
-- Watchdog TTL cleanup: DELETE FROM agent_sessions WHERE expires_at < NOW()
CREATE INDEX IF NOT EXISTS idx_agent_sessions_expires ON agent_sessions (expires_at);

-- =============================================================================
-- UI SESSIONS (Phase 1+ — Command Centre auth)
-- Placeholder created now so schema is complete; used when React UI ships.
-- =============================================================================
CREATE TABLE IF NOT EXISTS ui_sessions (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id         TEXT NOT NULL,
    role            TEXT NOT NULL,                  -- CISO|SECURITY_ENGINEER|DEVELOPER
    token_hash      TEXT NOT NULL UNIQUE,           -- bcrypt hash of session token
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ui_sessions_token ON ui_sessions (token_hash);
CREATE INDEX IF NOT EXISTS idx_ui_sessions_expires ON ui_sessions (expires_at);

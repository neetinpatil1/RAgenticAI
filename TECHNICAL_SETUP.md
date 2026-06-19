# SSDLC Multi-Agent Platform — Technical Setup Guide

> Platform: macOS (Apple Silicon ARM64 primary; x86_64 supported)
> Branch: `phase1` | Last Updated: Jun 2026

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Prerequisites](#2-prerequisites)
3. [PostgreSQL Setup](#3-postgresql-setup)
4. [Python Environment](#4-python-environment)
5. [Ollama (Local LLM)](#5-ollama-local-llm)
6. [React UI Build](#6-react-ui-build)
7. [Environment Variables](#7-environment-variables)
8. [Semgrep (SAST Scanner)](#8-semgrep-sast-scanner)
9. [SpotBugs + FindSecBugs (Java Bytecode Analysis)](#9-spotbugs--findsecbugs-java-bytecode-analysis)
10. [Eclipse Steady (CVE Reachability)](#10-eclipse-steady-cve-reachability)
11. [Starting the Server](#11-starting-the-server)
12. [Quick Start Checklist](#12-quick-start-checklist)
13. [Graceful Degradation](#13-graceful-degradation)
14. [Air-Gap Deployment](#14-air-gap-deployment)
15. [Troubleshooting](#15-troubleshooting)

---

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     React UI (port 8080)                     │
│              Vite + TypeScript + Tailwind + Recharts         │
└────────────────────────┬────────────────────────────────────┘
                         │ HTTP / SSE
┌────────────────────────▼────────────────────────────────────┐
│              FastAPI Gateway  (api/agent_gateway.py)         │
│                     uvicorn on 0.0.0.0:8080                  │
└───┬──────────┬──────────┬──────────┬──────────┬────────────┘
    │          │          │          │          │
  SAST      Secrets     SCA     SpotBugs  Reachability
(Semgrep)  (Regex+     (pip-   (FindSec  (heuristic +
           Entropy)   audit/    Bugs)      Steady)
                      OSV API)
    │          │          │          │          │
    └──────────┴──────────┴──────────┴──────────┘
                         │
            ┌────────────▼─────────────┐
            │   PostgreSQL + pgvector  │
            │   (findings, jobs, audit,│
            │    embeddings, labels)   │
            └──────────────────────────┘
                         │
            ┌────────────▼─────────────┐
            │     Ollama (local LLM)   │
            │  qwen2.5-coder:14b       │
            │  llama3.2:3b             │
            └──────────────────────────┘
```

**Parallel scan pipeline (Step 2/5 in every scan):**
```
POST /api/v1/scan
  └── asyncio.gather(
        SAST (Semgrep)         → findings_reports
        Secret Scan (Regex)    → secret_findings
        SCA (pip-audit/OSV)    → dependency_findings
        SpotBugs (FindSecBugs) → findings_reports [tool=findsecbugs]
      )
  └── Reachability (heuristic + Eclipse Steady)
  └── FP Challenger (L1 rules → L3 LLM re-evaluation)
```

---

## 2. Prerequisites

### System Requirements

| Tool | Version | Install |
|------|---------|---------|
| Python | ≥ 3.9 | `brew install python@3.11` |
| Node.js | ≥ 18 LTS | `brew install node` |
| PostgreSQL | ≥ 11 | `brew install postgresql@14` |
| Java (JDK) | ≥ 11 | `brew install openjdk@17` |
| Maven | ≥ 3.6 | `brew install maven` |
| Docker / OrbStack | any | `brew install --cask orbstack` |
| Ollama | latest | `brew install ollama` |

> **macOS Apple Silicon note:** Use OrbStack instead of Docker Desktop — it provides faster QEMU emulation required for x86_64 Eclipse Steady images.

### Install all at once

```bash
brew install python@3.11 node postgresql@14 openjdk@17 maven ollama
brew install --cask orbstack
```

After installing Java, add to your shell profile (`~/.zshrc`):
```bash
export PATH="/opt/homebrew/opt/openjdk@17/bin:$PATH"
export JAVA_HOME=$(/usr/libexec/java_home -v 17)
```

---

## 3. PostgreSQL Setup

### 3.1 Start PostgreSQL

```bash
brew services start postgresql@14
```

Verify it's running:
```bash
psql -U postgres -c "SELECT version();"
```

### 3.2 Create the database

```bash
createdb -U postgres ssdlc
```

### 3.3 Install pgvector extension

pgvector is required for semantic similarity search in the FP pipeline (Layer 3 LLM).

```bash
brew install pgvector
```

Then enable it in the database:
```bash
psql -U postgres -d ssdlc -c "CREATE EXTENSION IF NOT EXISTS vector;"
psql -U postgres -d ssdlc -c "CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";"
```

### 3.4 Run schema migrations

The platform runs migrations automatically on startup (`db/migrations.py`), but you can also run the base schema manually:

```bash
psql -U postgres -d ssdlc -f db/schema.sql
```

### 3.5 Key tables

| Table | Purpose |
|-------|---------|
| `workflow_runs` | Master record for each scan — state, metadata, timing |
| `pg_jobs` | Central job queue with `SKIP LOCKED` (replaces Kafka in Phase 0) |
| `findings_reports` | SAST + SpotBugs findings with dedup by fingerprint |
| `finding_embeddings` | pgvector embeddings for semantic similarity (FP pipeline) |
| `fp_decisions` | Layer 1/3 FP verdicts per finding |
| `fp_challenge_status` | Real-time FP Challenger progress (polled by UI) |
| `secret_findings` | Credential/token findings from secret scanner |
| `dependency_findings` | SCA CVE findings with reachability verdicts |
| `code_review_findings` | Code review agent findings |
| `audit_log` | Append-only audit trail for all agent actions |

---

## 4. Python Environment

### 4.1 Create virtual environment

```bash
cd /path/to/RAgenticAI
python3.11 -m venv .venv
source .venv/bin/activate
```

### 4.2 Install dependencies

```bash
pip install -r requirements.txt
```

**What gets installed:**

| Package | Purpose |
|---------|---------|
| `langchain>=0.3.0` | LLM orchestration |
| `langgraph>=0.2.0` | Stateful multi-node workflows |
| `anthropic>=0.40.0` | Claude API (Phase 1+ cloud fallback) |
| `openai>=1.0.0` | OpenAI API (Phase 1+ cloud fallback) |
| `httpx>=0.27.0` | Async HTTP client (Ollama + Eclipse Steady) |
| `asyncpg>=0.29.0` | Async PostgreSQL driver |
| `psycopg2-binary>=2.9.0` | Sync PostgreSQL driver (migrations) |
| `transformers>=4.40.0` | HuggingFace UniXcoder embeddings |
| `torch>=2.0.0` | PyTorch (MPS GPU on Apple Silicon) |
| `numpy>=1.24.0` | Vector math |
| `fastapi>=0.115.0` | API server |
| `uvicorn[standard]>=0.30.0` | ASGI server |
| `pydantic>=2.0.0` | Output contracts / data validation |
| `jinja2>=3.1.0` | HTML template rendering |
| `aiofiles>=23.0.0` | Async static file serving |
| `python-dotenv>=1.0.0` | `.env` loader |
| `pyyaml>=6.0.0` | YAML config, prompt files, FP rules |
| `tenacity>=8.2.0` | Retry logic for LLM calls |
| `pytest>=8.0.0` | Test runner |
| `pytest-asyncio>=0.23.0` | Async test support |

---

## 5. Ollama (Local LLM)

The platform uses two Ollama models:

| Model | Role | Size | Use |
|-------|------|------|-----|
| `qwen2.5-coder:14b` | Tier 1 — Primary analysis | ~10 GB | FP pipeline Layer 3 (code understanding) |
| `llama3.2:3b` | Tier 2 — Fast classification | ~2.5 GB | Quick triage, summarization |

### 5.1 Pull models

```bash
ollama pull qwen2.5-coder:14b
ollama pull llama3.2:3b
```

> These are large downloads. Ensure you have ~15 GB free disk space and a stable connection.

### 5.2 Start Ollama

```bash
ollama serve
```

Ollama runs on `http://localhost:11434` by default.

Verify both models are available:
```bash
ollama list
```

> **Apple Silicon:** Ollama uses Metal GPU acceleration natively — no additional configuration needed. Expect ~2–8 seconds per LLM call depending on finding complexity.

---

## 6. React UI Build

The React UI is served by FastAPI from `ui/dist/` on the same port (8080).

### 6.1 Install npm dependencies

```bash
cd ui
npm install
```

**UI tech stack:**

| Package | Version | Purpose |
|---------|---------|---------|
| React | 18.3.x | UI framework |
| TypeScript | 5.4.x | Type safety |
| Vite | 5.2.x | Build tool + dev server |
| Tailwind CSS | 3.4.x | Utility-first styling |
| Recharts | 2.12.x | Scan result charts |
| Framer Motion | 11.x | Animations |
| Lucide React | 0.378.x | Icons |

### 6.2 Build for production

```bash
cd ui
npm run build
```

Output goes to `ui/dist/`. FastAPI serves this automatically from port 8080.

### 6.3 Development mode (UI hot-reload)

```bash
cd ui
npm run dev      # UI on http://localhost:5173 (proxies API to :8080)
```

Run the API server in a separate terminal when using dev mode.

---

## 7. Environment Variables

### 7.1 Create your `.env` file

```bash
cp .env.example .env
```

Edit `.env` with your values:

```bash
# ── PostgreSQL ────────────────────────────────────────────────
DB_HOST=localhost
DB_PORT=5432
DB_NAME=ssdlc
DB_USER=postgres
DB_PASSWORD=<your-postgres-password>

# ── Ollama (local LLM runtime) ────────────────────────────────
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_TIER1_MODEL=qwen2.5-coder:14b
OLLAMA_TIER2_MODEL=llama3.2:3b
OLLAMA_NUM_PARALLEL=2          # concurrent LLM generations

# ── Semgrep SAST ─────────────────────────────────────────────
SEMGREP_DETECTION_RULES_PATH=./agents/security/sast/rules
SEMGREP_RULES_PATH=./agents/security/sast/fp_rules.yml
SEMGREP_DOCKER_IMAGE=semgrep/semgrep:latest
SEMGREP_TIMEOUT=300            # seconds
SEMGREP_MAX_FINDINGS=1000      # circuit breaker

# ── API Server ────────────────────────────────────────────────
API_HOST=0.0.0.0
API_PORT=8080

# ── Prompts ───────────────────────────────────────────────────
PROMPTS_DIR=./prompts

# ── Watchdog (SLA monitoring) ─────────────────────────────────
WATCHDOG_INTERVAL=300          # check every 5 min
WATCHDOG_SLA_PENDING=1800      # 30 min max in pending state
WATCHDOG_SLA_PROCESSING=3600   # 1 hr max in processing state

# ── Phase 1+ (leave blank / commented for Phase 0) ────────────
# ANTHROPIC_API_KEY=your-key-here      # Claude API fallback
# OPENAI_API_KEY=your-key-here         # OpenAI API fallback
# GITEA_URL=http://ssdlc-platform.local:3000
# VAULT_ADDR=http://ssdlc-platform.local:8200
# VAULT_TOKEN=

# ── Air-gap (override model download paths) ───────────────────
# MODELS_PATH=/opt/models
# UNIXCODER_MODEL=microsoft/unixcoder-base
# STEADY_URL=http://localhost:8033      # default; override if Steady runs elsewhere
```

> **Never commit `.env`** — it is in `.gitignore`.

### 7.2 Config reference

All env vars are loaded in `core/config.py`. The `settings` singleton is imported by all workflow and tool modules.

---

## 8. Semgrep (SAST Scanner)

Semgrep runs inside a Docker sandbox for isolation.

### 8.1 Pull the Semgrep Docker image

```bash
docker pull semgrep/semgrep:latest
```

Verify:
```bash
docker run --rm semgrep/semgrep:latest semgrep --version
```

### 8.2 Detection rules

OWASP-mapped Semgrep YAML rules are committed in the repo:

```
agents/security/sast/rules/
  owasp/
    java-injection.yml
    java-xxe.yml
    java-ssrf.yml
    java-path-traversal.yml
    java-spring-security.yml
    ...
```

These are loaded at scan time via `SEMGREP_DETECTION_RULES_PATH`.

### 8.3 Layer 1 FP filter rules

The false-positive pre-filter rules (Python dict format, NOT Semgrep format):

```
agents/security/sast/fp_rules.yml
```

Loaded by `core/fp_pipeline/layer1_rules.py`. Pattern: `{rule_id: [fp_conditions]}`.

---

## 9. SpotBugs + FindSecBugs (Java Bytecode Analysis)

SpotBugs with the FindSecBugs plugin provides bytecode-level SAST for Java — it finds issues that Semgrep misses at the source level (reflection, bytecode manipulation, compiled JSP, etc.).

### 9.1 Requirements

- **Java 11+** must be on `PATH` (`java -version`)
- **Maven 3.6+** must be on `PATH` (`mvn --version`) — required to compile Java projects before analysis

### 9.2 Auto-download (no manual setup required)

The `tools/spotbugs_tool.py` auto-downloads the FindSecBugs CLI bundle on the **first scan of a Java project**:

```
tools/vendor/findsecbugs-cli/
  findsecbugs.sh          ← main runner
  lib/
    spotbugs-4.9.3.jar
    findsecbugs-plugin-1.14.0.jar
    *.jar                 ← full classpath
```

Downloaded from: `https://github.com/find-sec-bugs/find-sec-bugs/releases/download/version-1.14.0/findsecbugs-cli-1.14.0.zip`

The `tools/vendor/` directory is in `.gitignore` — JARs are never committed.

### 9.3 How it works

1. **Build detection**: Checks for `target/classes/` or `build/classes/java/main/`
2. **Auto-compile**: If bytecode is missing, runs `mvn compile -q -DskipTests -Dmaven.compiler.source=11 -Dmaven.compiler.target=11`
3. **Java EE fallback**: If compile fails due to missing `javax.servlet`, runs `mvn dependency:build-classpath` then `javac` directly with `javax.servlet-api-3.1.0.jar` added
4. **SpotBugs analysis**: Runs `findsecbugs.sh -xml:withMessages -effort:max -low -output <file> <classes_dir>`
5. **XML parsing**: Parses BugCollection XML, maps 30+ FindSecBugs patterns to CWE/OWASP
6. **Dedup**: Skips findings already in `findings_reports` for same `(file_path, line_start, cwe_id)`
7. **Insert**: Writes net-new findings with `tool='findsecbugs'`

### 9.4 Supported bug pattern mappings

| FindSecBugs Pattern | CWE | OWASP |
|--------------------|-----|-------|
| `SQL_INJECTION_*` | CWE-89 | A03 Injection |
| `COMMAND_INJECTION` | CWE-78 | A03 Injection |
| `XSS_*` | CWE-79 | A03 Injection |
| `PATH_TRAVERSAL_*` | CWE-22 | A01 Broken Access Control |
| `XXE_*` | CWE-611 | A05 Security Misconfiguration |
| `SSRF` | CWE-918 | A10 SSRF |
| `HARD_CODE_PASSWORD` | CWE-259 | A07 Auth Failures |
| `WEAK_MESSAGE_DIGEST_*` | CWE-327 | A02 Crypto Failures |
| `INSECURE_RANDOM` | CWE-330 | A02 Crypto Failures |
| `LDAP_INJECTION` | CWE-90 | A03 Injection |
| `XPATH_INJECTION` | CWE-643 | A03 Injection |
| (+ 20 more patterns) | | |

---

## 10. Eclipse Steady (CVE Reachability)

Eclipse Steady performs **call-graph-based reachability** — it traces the actual execution path from your application's entry point to a vulnerable library method, providing real call-chain evidence:

```
App.service() → BaseServlet.execute() → VulnerableClass.parse()
```

This replaces the Phase 1 heuristic (JAR bytecode string search) with true reachability analysis.

### 10.1 Requirements

- Docker (OrbStack) must be running
- ~2 GB disk for Steady images (x86_64 via QEMU on ARM64)
- ~1 GB RAM reserved for `rest-backend`

### 10.2 Start Eclipse Steady

```bash
docker compose -f docker/steady/docker-compose.yml up -d
```

Wait ~60 seconds for Spring Boot to finish starting, then verify:

```bash
curl http://localhost:8033/backend/spaces    # should return: []
```

### 10.3 Services

| Service | Image | Port | Role |
|---------|-------|------|------|
| `haproxy` | `haproxy:2.3-alpine` | 8033 → 8080 | Load balancer / entry point |
| `rest-backend` | `eclipse/steady-rest-backend:3.2.5` | 8091 (internal) | Steady analysis engine (Spring Boot) |
| `postgresql` | `postgres:11-alpine` | 8032 → 5432 | Steady's own database (`vulas`) |

> Note: This is a **separate** PostgreSQL instance from the main platform DB (`ssdlc`). Steady uses `vulas` database with its own credentials (`steady`/`steadypass`).

### 10.4 Stop Steady

```bash
docker compose -f docker/steady/docker-compose.yml down
```

### 10.5 How it integrates

Steady is called automatically during the **Reachability workflow** (`workflows/reachability_workflow.py`):

1. Heuristic reachability runs first (fast, no build required)
2. `SteadyTool.is_available()` probes `GET /backend/spaces`
3. If Steady is up: registers app from `pom.xml`, triggers call-graph analysis, polls until complete, fetches per-CVE verdicts
4. Steady verdicts override heuristic results for the same CVE when Steady's confidence > current

If Steady is **not running**, the workflow silently falls back to heuristic results — scans never fail due to Steady being unavailable.

### 10.6 Supported projects

Steady currently supports **Maven projects only** (reads `groupId`/`artifactId`/`version` from `pom.xml`). Gradle projects use heuristic reachability.

---

## 11. Starting the Server

### 11.1 Start everything in order

```bash
# 1. PostgreSQL (if not already running via brew services)
brew services start postgresql@14

# 2. Ollama
ollama serve &

# 3. Eclipse Steady (optional — for CVE reachability on Java projects)
docker compose -f docker/steady/docker-compose.yml up -d

# 4. Activate Python venv
source .venv/bin/activate

# 5. Start the API server
python main.py serve
```

Server starts at `http://localhost:8080`. The startup sequence:
- Initializes PostgreSQL connection pool (min=2, max=10)
- Runs idempotent DB migrations (`db/migrations.py`)
- Starts watchdog background task (SLA monitoring every 5 min)
- Serves React UI from `ui/dist/` at `/`

### 11.2 Available CLI modes

```bash
python main.py serve          # HTTP server (primary mode)
python main.py scan --path /path/to/project   # one-off CLI scan
python main.py health         # check all dependencies
```

### 11.3 Key API endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/scan` | Submit a path for scanning |
| `GET` | `/api/v1/scan/{run_id}` | Scan status + per-agent completion flags |
| `GET` | `/api/v1/scan/{run_id}/stream` | SSE stream for real-time progress |
| `GET` | `/api/v1/findings` | List findings (filter by run, severity, verdict) |
| `GET` | `/api/v1/secrets/{run_id}` | Secret scan results |
| `GET` | `/api/v1/dependencies/{run_id}` | SCA CVE findings |
| `GET` | `/api/v1/review/{run_id}` | Code review findings |
| `POST` | `/api/v1/label` | Submit human FP label |
| `POST` | `/api/v1/fp-challenge/{run_id}` | Manually trigger FP Challenger |
| `GET` | `/api/v1/fp-challenge/{run_id}` | FP Challenger progress |
| `GET` | `/api/v1/runs` | Recent workflow runs |
| `GET` | `/health` | Liveness probe |

### 11.4 Submit a scan

```bash
curl -X POST http://localhost:8080/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"path": "/Users/you/projects/JavaVulnerableLab"}'
```

Response:
```json
{
  "run_id": "scan_20260619_123456_abc123",
  "status": "pending",
  "message": "Scan queued"
}
```

Poll status:
```bash
curl http://localhost:8080/api/v1/scan/scan_20260619_123456_abc123
```

---

## 12. Quick Start Checklist

```bash
# ── System deps ──────────────────────────────────────────────
brew install python@3.11 node postgresql@14 openjdk@17 maven ollama
brew install --cask orbstack

# ── Java home ────────────────────────────────────────────────
echo 'export PATH="/opt/homebrew/opt/openjdk@17/bin:$PATH"' >> ~/.zshrc
echo 'export JAVA_HOME=$(/usr/libexec/java_home -v 17)' >> ~/.zshrc
source ~/.zshrc

# ── PostgreSQL ────────────────────────────────────────────────
brew services start postgresql@14
createdb -U postgres ssdlc
psql -U postgres -d ssdlc -c "CREATE EXTENSION IF NOT EXISTS vector;"
psql -U postgres -d ssdlc -c "CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";"

# ── Python env ────────────────────────────────────────────────
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# ── Ollama ────────────────────────────────────────────────────
ollama pull qwen2.5-coder:14b
ollama pull llama3.2:3b
ollama serve &

# ── React UI ──────────────────────────────────────────────────
cd ui && npm install && npm run build && cd ..

# ── Docker image for Semgrep ─────────────────────────────────
docker pull semgrep/semgrep:latest

# ── Eclipse Steady (optional — for Java CVE reachability) ────
docker compose -f docker/steady/docker-compose.yml up -d
# wait ~60s then verify:
curl http://localhost:8033/backend/spaces

# ── Environment ───────────────────────────────────────────────
cp .env.example .env
# Edit .env: set DB_PASSWORD, confirm OLLAMA_TIER1_MODEL, etc.

# ── Start server ──────────────────────────────────────────────
source .venv/bin/activate
python main.py serve
# → http://localhost:8080
```

---

## 13. Graceful Degradation

The platform is designed to keep scanning even when optional components are unavailable:

| Component | If unavailable | Behaviour |
|-----------|---------------|-----------|
| Eclipse Steady | Not running | Reachability uses heuristic (JAR string search + import scan) |
| SpotBugs CLI | Download fails | Skipped gracefully; only Semgrep findings returned |
| Ollama Tier 1 | Model not pulled | Layer 3 FP analysis skipped; Layer 1 rules still run |
| pgvector | Extension missing | Semantic similarity search disabled in FP pipeline |
| Maven | Not installed | SpotBugs skipped for Java projects; Semgrep still runs |
| Docker | Not running | Semgrep runs natively (if installed); Steady unavailable |

---

## 14. Air-Gap Deployment

For offline/air-gapped environments, use the bundling scripts on an internet-connected jump workstation:

### 14.1 Bundle Ollama models

```bash
./scripts/airgap/setup_ollama_models.sh --output-dir /tmp/ollama-bundle
```

Output: `ollama-models-bundle/` with SHA-256 manifest.

### 14.2 Bundle Semgrep rules

```bash
./scripts/airgap/setup_semgrep_rules.sh
```

Output: `agents/security/sast/rules/owasp/*.yml` — commit to git; no internet needed at scan time.

### 14.3 Bundle vulnerability databases

```bash
./scripts/airgap/setup_grype_db.sh --output-dir /tmp/grype-db
```

Update weekly (CVE data changes frequently).

### 14.4 Air-gap env vars

```bash
MODELS_PATH=/opt/models                    # path to transferred model files
UNIXCODER_MODEL=microsoft/unixcoder-base   # HuggingFace model for embeddings
STEADY_URL=http://steady.internal:8033     # if Steady runs on a dedicated host
```

---

## 15. Troubleshooting

### PostgreSQL connection refused

```bash
brew services restart postgresql@14
psql -U postgres -c "SELECT 1;"
```

If `psql` works but the app fails: check `DB_PASSWORD` in `.env`.

### pgvector not found

```bash
brew install pgvector
psql -U postgres -d ssdlc -c "CREATE EXTENSION IF NOT EXISTS vector;"
```

### Ollama model not found

```bash
ollama list                        # check what's installed
ollama pull qwen2.5-coder:14b      # re-pull if missing
```

### Docker / OrbStack not running

Launch OrbStack from Applications. Verify:
```bash
docker ps
```

### Semgrep scan returns 0 findings

1. Check that `semgrep/semgrep:latest` is pulled: `docker images | grep semgrep`
2. Check that rules path exists: `ls ./agents/security/sast/rules/`
3. Check scan path is readable by Docker (macOS: must be under `/Users/`)

### SpotBugs download fails

Manual download:
```bash
mkdir -p tools/vendor
cd tools/vendor
curl -L -o findsecbugs-cli.zip \
  https://github.com/find-sec-bugs/find-sec-bugs/releases/download/version-1.14.0/findsecbugs-cli-1.14.0.zip
unzip findsecbugs-cli.zip -d findsecbugs-cli
chmod +x findsecbugs-cli/findsecbugs.sh
# Fix CRLF if on macOS:
sed -i '' $'s/\r//' findsecbugs-cli/findsecbugs.sh
```

### Eclipse Steady startup timeout

Spring Boot can take 60–90 seconds. Check logs:
```bash
docker compose -f docker/steady/docker-compose.yml logs -f rest-backend
```

Wait for: `Started VulasApplication in X.XXX seconds`.

### `files_scanned: 0` in scan status

This is a known cosmetic issue when the LangGraph state loses coverage stats after the FP pipeline. Coverage stats are always written in the early DB write (at `node_write_findings`) — the value is in `metadata.files_scanned`. Restart the server with the latest `workflows/sast_workflow.py` to apply the fix.

### Stale jobs causing SLA warnings on startup

If you see repeated `SLA breach` warnings at startup, clean stale jobs from a previous session:

```sql
UPDATE pg_jobs
SET state = 'completed'
WHERE state = 'pending'
  AND created_at < NOW() - INTERVAL '1 hour';
```

---

## File Structure (key files)

```
RAgenticAI/
├── main.py                           ← Entry point (serve / scan / health)
├── requirements.txt                  ← Python dependencies
├── .env.example                      ← Environment variable template
├── pyproject.toml                    ← Python version requirement (≥3.9)
│
├── api/
│   └── agent_gateway.py              ← FastAPI routes + scan orchestration
│
├── workflows/
│   ├── sast_workflow.py              ← Semgrep SAST + FP pipeline (LangGraph)
│   ├── secret_scan_workflow.py       ← Secret/credential scanner
│   ├── sca_workflow.py               ← SCA (pip-audit / OSV)
│   ├── spotbugs_workflow.py          ← SpotBugs/FindSecBugs Java analysis
│   ├── reachability_workflow.py      ← CVE reachability (heuristic + Steady)
│   ├── code_review_workflow.py       ← LLM code review
│   └── fp_challenger_workflow.py     ← FP Challenger (post-hoc second pass)
│
├── tools/
│   ├── semgrep_tool.py               ← Semgrep Docker wrapper
│   ├── spotbugs_tool.py              ← SpotBugs/FindSecBugs auto-download + runner
│   ├── steady_tool.py                ← Eclipse Steady REST API client
│   ├── sca_tool.py                   ← pip-audit / npm audit / OSV API
│   ├── secret_scanner_tool.py        ← Regex + entropy secret scanner
│   └── vendor/                       ← Auto-downloaded JARs (gitignored)
│       └── findsecbugs-cli/
│
├── core/
│   ├── config.py                     ← Settings (env vars → dataclasses)
│   ├── audit_logger.py               ← Append-only audit log
│   ├── pg_job_queue.py               ← PostgreSQL job queue (SKIP LOCKED)
│   ├── watchdog.py                   ← SLA monitor
│   ├── fp_pipeline/
│   │   ├── layer1_rules.py           ← YAML rule-based FP pre-filter
│   │   └── layer3_llm.py             ← LLM + pgvector hybrid FP analysis
│   ├── output_contracts/
│   │   ├── sast_report.py            ← SASTFinding Pydantic contract
│   │   └── fp_decision.py            ← FPDecision Pydantic contract
│   └── state/
│       ├── workflow_state.py         ← PG-backed workflow state
│       └── vector_memory.py          ← pgvector memory (hybrid retrieval)
│
├── agents/
│   └── security/sast/
│       ├── rules/                    ← Semgrep OWASP detection rules (YAML)
│       └── fp_rules.yml              ← Layer 1 FP filter rules
│
├── prompts/
│   ├── sast_agent/v1.0/              ← SAST + FP analysis prompts
│   └── code_review_agent/v1.0/       ← Code review prompts
│
├── db/
│   ├── schema.sql                    ← Full PostgreSQL DDL
│   └── migrations.py                 ← Idempotent ALTER TABLE runner
│
├── docker/
│   └── steady/
│       ├── docker-compose.yml        ← Eclipse Steady stack
│       └── haproxy/conf/haproxy.cfg  ← HAProxy routing config
│
├── scripts/airgap/
│   ├── setup_ollama_models.sh        ← Bundle models for air-gap
│   ├── setup_semgrep_rules.sh        ← Bundle Semgrep rules
│   └── setup_grype_db.sh             ← Bundle vulnerability databases
│
└── ui/
    ├── package.json                  ← Node.js dependencies
    ├── vite.config.ts                ← Vite build config
    └── src/
        ├── components/               ← React components (ScanInput, ScanProgress, ScanResults, ...)
        ├── lib/api.ts                ← API client (submitScan, getScanStatus, getFindings, SSE)
        └── types.ts                  ← TypeScript types (Finding, ScanStatus, ScanCoverage, ...)
```

# SSDLC Platform — Technical Setup & Dependency Reference
> Branch: `phase2` | Python: 3.12 | Last Updated: 18 June 2026

---

## 1. Prerequisites

### System Requirements

| Component | Required | Actual | Notes |
|---|---|---|---|
| macOS | Apple Silicon (M3/M4) | ✅ | Metal GPU path for Ollama |
| Python | ≥ 3.11 | 3.12.13 (`/opt/homebrew/bin/python3.12`) | System Python 3.9 is too old — use brew |
| Node.js / npm | ≥ 18 | npm 11.6.2 | For React UI build and `npm audit` in SCA |
| PostgreSQL | 16+ | 18 (`/Library/PostgreSQL/18/`) | Standalone installer, not brew |
| Ollama | Any | 0.30.9 | Native Metal — no Docker layer |

---

## 2. Python Virtual Environment

```bash
# Create venv with Python 3.12 (NOT system Python 3.9)
/opt/homebrew/bin/python3.12 -m venv .venv

# Activate
source .venv/bin/activate

# Install all dependencies
pip install -r requirements.txt

# Install additional runtime dependencies (not yet in requirements.txt)
pip install pip-audit          # SCA: Python dependency vulnerability scanner
pip install semgrep            # SAST: native semgrep binary (Docker fallback removed)
pip install code-review-graph  # Code knowledge graph CLI
```

> **⚠️ click version conflict:** `semgrep` pins `click~=8.1.8`; `huggingface-hub` requires `click>=8.4.0`.
> Current resolution: `click==8.4.1`. Both tools work in practice. Pin is cosmetic — pip warns but doesn't break.

### Fix required in `requirements.txt`

The following packages are used at runtime but **not listed** in `requirements.txt`:

| Package | Version | Used by | Add to requirements.txt |
|---|---|---|---|
| `pip-audit` | 2.10.1 | `tools/sca_tool.py` — Python CVE scan | ✅ Yes |
| `semgrep` | 1.167.0 | `tools/semgrep_tool.py` — SAST scanner | ✅ Yes |
| `code-review-graph` | 2.3.6 | `workflows/code_review_workflow.py`, `api/agent_gateway.py` | ✅ Yes |

---

## 3. pgvector Extension

pgvector is installed via Homebrew but must be manually copied to the standalone PostgreSQL 18.

```bash
# Step 1 — Install pgvector via brew
brew install pgvector

# Step 2 — Copy extension files to PG18 (requires sudo)
sudo cp /opt/homebrew/Cellar/pgvector/0.8.3/lib/postgresql@18/vector.dylib \
    /Library/PostgreSQL/18/lib/postgresql/

sudo cp /opt/homebrew/Cellar/pgvector/0.8.3/share/postgresql@18/extension/vector* \
    /Library/PostgreSQL/18/share/postgresql/extension/

# Step 3 — Enable extension in the ssdlc database
PGPASSWORD=<password> /Library/PostgreSQL/18/bin/psql \
    -h localhost -p 5432 -U postgres -d ssdlc \
    -c "CREATE EXTENSION IF NOT EXISTS vector;"
```

> **Note:** The migrations in `db/migrations.py` skip pgvector-dependent tables gracefully if the extension is missing. The platform runs without vector search (Layer 3 FP degrades to LLM-only).

---

## 4. Database Setup

PostgreSQL 18 is installed as a standalone application (not brew).

```bash
# Binaries location
/Library/PostgreSQL/18/bin/psql
/Library/PostgreSQL/18/bin/pg_isready

# Verify it's running
/Library/PostgreSQL/18/bin/pg_isready -h localhost -p 5432

# Create the ssdlc database (first-time only)
PGPASSWORD=<password> /Library/PostgreSQL/18/bin/psql \
    -h localhost -p 5432 -U postgres \
    -c "CREATE DATABASE ssdlc;"
```

Schema migrations run automatically on every server startup (`db/migrations.py` — idempotent).

### Tables created on startup

| Table | Purpose |
|---|---|
| `workflow_runs` | Scan job lifecycle and metadata |
| `findings_reports` | SAST findings with all enrichment columns |
| `finding_embeddings` | pgvector embeddings for Layer 3 FP retrieval |
| `fp_decisions` | False positive verdicts (Layer 1/3) |
| `audit_log` | Append-only compliance ledger |
| `pg_jobs` | Inter-agent job queue (SKIP LOCKED) |
| `code_review_findings` | Code review agent output |
| `code_review_status` | Per-file progress tracking for live UI |
| `secret_findings` | Secret scanner output |
| `dependency_findings` | SCA (pip-audit + npm audit + OSV) output |
| `label_decisions` | Human labeling from the UI |
| `ui_sessions` | Auth sessions (Phase 1+) |

---

## 5. Environment Variables (`.env`)

`.env` is gitignored. Copy from `.env.example` and fill in:

| Variable | Default | Notes |
|---|---|---|
| `DB_HOST` | `localhost` | |
| `DB_PORT` | `5432` | |
| `DB_NAME` | `ssdlc` | |
| `DB_USER` | `postgres` | |
| `DB_PASSWORD` | _(set in .env)_ | Special chars (e.g. `@`) are auto URL-encoded — safe |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | |
| `OLLAMA_TIER1_MODEL` | `qwen2.5-coder:14b` | Pull before running |
| `OLLAMA_TIER2_MODEL` | `llama3.2:3b` | Pull before running |
| `SEMGREP_DETECTION_RULES_PATH` | `./agents/security/sast/rules` | Local rules directory |
| `SEMGREP_RULES_PATH` | `./agents/security/sast/fp_rules.yml` | Layer 1 FP filter rules |
| `SEMGREP_DOCKER_IMAGE` | `semgrep/semgrep:latest` | Only used if Docker is installed |
| `API_HOST` | `0.0.0.0` | |
| `API_PORT` | `8080` | React UI served on same port |
| `PROMPTS_DIR` | `./prompts` | |

> **⚠️ Password with special characters:** Passwords containing `@`, `/`, `+`, etc. must be URL-encoded in a raw DSN string. This is handled automatically in `core/config.py` via `urllib.parse.quote_plus`.

---

## 6. Ollama LLM Models

```bash
# Pull required models before first run
ollama pull qwen2.5-coder:14b   # ~9 GB — Tier 1 (SAST, code review, FP)
ollama pull llama3.2:3b         # ~2 GB — Tier 2 (routing, classification)

# Verify
ollama list
```

| Model | Size | Role | Status |
|---|---|---|---|
| `qwen2.5-coder:14b` | 9.0 GB | SAST analysis, code review, FP arbitration | ✅ Installed |
| `llama3.2:3b` | 2.0 GB | Classification, routing, extraction | ✅ Installed |

---

## 7. React UI Build

```bash
cd ui/

# Install dependencies (includes TypeScript — must be done before build)
npm install

# Production build (output to ui/dist/ — served by FastAPI)
npm run build
```

> **Note:** `tsc` is a devDependency. Running `npm run build` without `npm install` first will fail with `tsc: command not found`. The `dist/` folder is gitignored — build must be run on each fresh clone.

---

## 8. Starting the Server

```bash
# From project root, with venv active
.venv/bin/python main.py serve
# or:
source .venv/bin/activate && python main.py serve
```

Server starts at **http://localhost:8080**. FastAPI serves the React `ui/dist/` bundle on the same port.

### Health check

```bash
python main.py health
```

Checks: PostgreSQL connectivity, Ollama reachability, Docker availability.

### Kill + restart (development)

```bash
lsof -ti :8080 | xargs kill -9 2>/dev/null
.venv/bin/python main.py serve > /tmp/ssdlc.log 2>&1 &
tail -f /tmp/ssdlc.log
```

---

## 9. Runtime Dependency Status

### Python Packages

| Package | Version | Status | Required for |
|---|---|---|---|
| `fastapi` | 0.137.2 | ✅ | API server |
| `uvicorn` | 0.49.0 | ✅ | ASGI server |
| `pydantic` | 2.13.4 | ✅ | Output contracts |
| `asyncpg` | 0.31.0 | ✅ | PostgreSQL async driver |
| `psycopg2-binary` | 2.9.12 | ✅ | PostgreSQL sync driver (migrations) |
| `langchain` | 1.3.9 | ✅ | LLM framework |
| `langgraph` | 1.2.5 | ✅ | Agent workflow orchestration |
| `httpx` | 0.28.1 | ✅ | Ollama API calls, OSV API |
| `aiohttp` | 3.14.1 | ✅ | Async HTTP (SCA) |
| `transformers` | 5.12.1 | ✅ | UniXcoder embeddings (Layer 3) |
| `torch` | 2.12.1 | ✅ | UniXcoder (MPS backend on Apple Silicon) |
| `numpy` | 2.4.6 | ✅ | Embedding vectors |
| `aiofiles` | 25.1.0 | ✅ | Async static file serving |
| `jinja2` | — | ✅ | HTML labeling template |
| `python-dotenv` | 1.2.2 | ✅ | `.env` loader |
| `anthropic` | — | ✅ | Phase 1+ cloud fallback LLM |
| `openai` | — | ✅ | Phase 1+ cloud fallback LLM |
| `semgrep` | 1.167.0 | ✅ _added_ | SAST scanning (native, no Docker needed) |
| `pip-audit` | 2.10.1 | ✅ _added_ | SCA: Python CVE scanning |
| `code-review-graph` | 2.3.6 | ✅ _added_ | Code knowledge graph |
| `scipy` | — | ⬜ Not installed | Phase 1+ Layer 2 CodeBERT only |
| `scikit-learn` | — | ⬜ Not installed | Phase 1+ Layer 2 CodeBERT only |
| `pgvector` (Python client) | — | ⬜ Not needed | Raw asyncpg SQL used for vector queries |

### External CLI Tools

| Tool | Version | Status | Required for | Install |
|---|---|---|---|---|
| `ollama` | 0.30.9 | ✅ | LLM inference | `brew install ollama` |
| `npm` | 11.6.2 | ✅ | npm audit (SCA Node.js) | Included with Node.js |
| `semgrep` | 1.167.0 | ✅ _in venv_ | SAST scanning | `pip install semgrep` |
| `code-review-graph` CLI | 2.3.6 | ✅ _in venv_ | Knowledge graph build | `pip install code-review-graph` |
| `pip-audit` CLI | 2.10.1 | ✅ _in venv_ | Python SCA | `pip install pip-audit` |
| `docker` | — | ❌ Not installed | Semgrep sandbox (optional) | `brew install --cask docker` |

> **Docker is optional.** `tools/semgrep_tool.py` checks for Docker first; if absent, falls back to the native `semgrep` binary in the venv. For production/staging the design mandates Docker isolation — the native path is development-only.

### External Services / APIs

| Service | URL | Status | Required for |
|---|---|---|---|
| OSV API | `https://api.osv.dev/v1/querybatch` | ⚠️ Internet call | Maven SCA in `tools/sca_tool.py` |
| Ollama | `http://localhost:11434` | ✅ Local | All LLM inference |
| PostgreSQL | `localhost:5432` | ✅ Local | Everything |

> **Air-gap note:** The OSV API call in Maven SCA will fail in an air-gapped environment. Phase 1 plan is to run a local OSV mirror or cache the DB via Nexus.

---

## 10. Known Issues & Fixes Applied

| Issue | Root Cause | Fix Applied |
|---|---|---|
| Server crash on startup | Password containing `@` broke DSN URL parsing (`Paresh@31` → host parsed as `31@localhost`) | `urllib.parse.quote_plus()` applied to password in `core/config.py` |
| SSL connection error on localhost | asyncpg attempted SSL by default | Added `?sslmode=disable` to DSN in `core/config.py` |
| `code_review_graph build` not found | Hardcoded `python3.11` in subprocess calls but venv uses Python 3.12 | Replaced all `"python3.11"` with `sys.executable` in `api/agent_gateway.py` and `workflows/code_review_workflow.py` |
| `tsc: command not found` on UI build | `typescript` is a devDependency — not installed until `npm install` runs | Run `npm install` in `ui/` before `npm run build` |
| pgvector not available in PG18 | brew pgvector targets homebrew PG, not standalone PG18 | Manual `sudo cp` of `.dylib` and `.sql` files to `/Library/PostgreSQL/18/` |

---

## 11. First-Run Checklist

```
[ ] PostgreSQL 18 running  — /Library/PostgreSQL/18/bin/pg_isready -h localhost -p 5432
[ ] ssdlc database exists  — psql -U postgres -c "\l"
[ ] pgvector extension on  — psql -d ssdlc -c "SELECT extversion FROM pg_extension WHERE extname='vector';"
[ ] .env file present      — ls -la .env
[ ] Venv created           — ls .venv/bin/python
[ ] Deps installed         — .venv/bin/pip show semgrep pip-audit code-review-graph
[ ] UI built               — ls ui/dist/index.html
[ ] Ollama running         — ollama list
[ ] qwen2.5-coder:14b      — ollama list | grep qwen
[ ] llama3.2:3b            — ollama list | grep llama
[ ] Server starts          — python main.py health
```

---

## 12. Phase 1+ Dependencies (Not Yet Needed)

These are not installed and not imported anywhere in the current codebase. Install when the corresponding features are built.

| Package | Phase | Feature |
|---|---|---|
| `scikit-learn` | 1 | Layer 2 CodeBERT FP classifier |
| `scipy` | 1 | Classifier metrics (AUC, kappa) |
| `pgvector` (Python client) | 1 | Vector type registration in asyncpg (may be needed when enabling HNSW index ops) |
| `gitpython` | 1 | Git repo input support (`main.py --repo`) |
| `trufflehog` / `gitleaks` | 1 | Secret scanner backend (currently pure-Python regex) |
| `grype` | 2 | Container/image CVE scanning |
| `kubescape` | 2 | K8s security agent |
| `checkov` | 2 | IaC security agent |
| `zaproxy` | 2 | DAST agent |

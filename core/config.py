"""
core/config.py
==============
Centralised configuration loader for the SSDLC platform.

Reads from environment variables (loaded via python-dotenv from .env).
All components import `settings` from here — no scattered os.getenv() calls.

Phase 0: env-var based config.
Phase 1+: extend with HashiCorp Vault integration (vault_client.py).
"""

import os
from dataclasses import dataclass, field
from dotenv import load_dotenv

# Load .env file from project root (no-op if already loaded or file absent)
load_dotenv()


@dataclass
class DatabaseConfig:
    """PostgreSQL connection settings. pgvector runs in the same DB."""
    host: str = field(default_factory=lambda: os.getenv("DB_HOST", "localhost"))
    port: int = field(default_factory=lambda: int(os.getenv("DB_PORT", "5432")))
    name: str = field(default_factory=lambda: os.getenv("DB_NAME", "ssdlc"))
    user: str = field(default_factory=lambda: os.getenv("DB_USER", "postgres"))
    password: str = field(default_factory=lambda: os.getenv("DB_PASSWORD", ""))
    pool_min: int = 2
    pool_max: int = 10

    @property
    def dsn(self) -> str:
        """Asyncpg-compatible DSN string."""
        return (
            f"postgresql://{self.user}:{self.password}"
            f"@{self.host}:{self.port}/{self.name}"
        )


@dataclass
class OllamaConfig:
    """Ollama LLM server settings. Runs natively on Mac with Metal GPU."""
    base_url: str = field(default_factory=lambda: os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"))
    # Tier 1 — primary model for SAST analysis, code review, FP arbitration
    tier1_model: str = field(default_factory=lambda: os.getenv("OLLAMA_TIER1_MODEL", "qwen2.5-coder:14b-instruct-q5_K_M"))
    # Tier 2 — fast model for classification, routing, simple extraction
    tier2_model: str = field(default_factory=lambda: os.getenv("OLLAMA_TIER2_MODEL", "llama3.2:3b"))
    # Escalation threshold: re-run on Tier 1 if LLM confidence below this
    escalation_confidence_threshold: float = 0.6
    request_timeout: int = 240  # seconds — 14B model needs up to 4 min on cold GPU


@dataclass
class SemgrepConfig:
    """Semgrep SAST scanner settings. Runs in Docker sandbox for isolation."""
    # Detection rules path — Semgrep-format YAML rules for vulnerability detection.
    # Points to the rules/ DIRECTORY so Semgrep loads ALL rule files recursively.
    # Air-gap: bundled locally, no network calls.
    # Sub-directories:
    #   rules/owasp/    — 42 OWASP-mapped Java security rules
    #   rules/custom/   — custom rules: Java, Python, JS, secrets, performance
    detection_rules_path: str = field(default_factory=lambda: os.getenv(
        "SEMGREP_DETECTION_RULES_PATH", "./agents/security/sast/rules"
    ))
    # FP filter rules path — Python Layer 1 format, NOT passed to Semgrep.
    # Loaded by core/fp_pipeline/layer1_rules.py for post-scan FP filtering.
    rules_path: str = field(default_factory=lambda: os.getenv(
        "SEMGREP_RULES_PATH", "./agents/security/sast/fp_rules.yml"
    ))
    # Docker image used for sandboxed execution
    docker_image: str = field(default_factory=lambda: os.getenv("SEMGREP_DOCKER_IMAGE", "semgrep/semgrep:latest"))
    # Timeout per scan in seconds
    timeout: int = int(os.getenv("SEMGREP_TIMEOUT", "300"))
    # Max findings per run (circuit breaker for very large repos)
    max_findings: int = int(os.getenv("SEMGREP_MAX_FINDINGS", "1000"))


@dataclass
class WatchdogConfig:
    """SLA monitor settings. Watchdog runs every 5 minutes."""
    interval_seconds: int = int(os.getenv("WATCHDOG_INTERVAL", "300"))  # 5 min
    # How long a job can sit in 'pending' before alerting (seconds)
    sla_pending_seconds: int = int(os.getenv("WATCHDOG_SLA_PENDING", "1800"))   # 30 min
    # How long a job can sit in 'processing' before alerting
    sla_processing_seconds: int = int(os.getenv("WATCHDOG_SLA_PROCESSING", "3600"))  # 1 hr
    # Auto-replay failed jobs up to this many times
    auto_replay_max_attempts: int = 3


@dataclass
class AppConfig:
    """Top-level application config. Import this singleton."""
    db: DatabaseConfig = field(default_factory=DatabaseConfig)
    ollama: OllamaConfig = field(default_factory=OllamaConfig)
    semgrep: SemgrepConfig = field(default_factory=SemgrepConfig)
    watchdog: WatchdogConfig = field(default_factory=WatchdogConfig)

    # FastAPI server
    api_host: str = field(default_factory=lambda: os.getenv("API_HOST", "0.0.0.0"))
    api_port: int = field(default_factory=lambda: int(os.getenv("API_PORT", "8080")))

    # Prompt store: local YAML files in Phase 0, Gitea URL in Phase 1+
    prompts_dir: str = field(default_factory=lambda: os.getenv("PROMPTS_DIR", "./prompts"))

    # Embedding dimension (UniXcoder default output size — must match schema.sql)
    embedding_dim: int = 768

    # High-stakes CWEs — findings touching these always escalate to Tier 1
    high_stakes_cwes: list = field(default_factory=lambda: [
        "CWE-89",   # SQL Injection
        "CWE-79",   # XSS
        "CWE-22",   # Path Traversal
        "CWE-326",  # Weak Cryptography
        "CWE-798",  # Hard-coded Credentials
        "CWE-306",  # Missing Auth
        "CWE-502",  # Deserialization
    ])


# ---------------------------------------------------------------------------
# Module-level singleton — import this everywhere
# ---------------------------------------------------------------------------
settings = AppConfig()

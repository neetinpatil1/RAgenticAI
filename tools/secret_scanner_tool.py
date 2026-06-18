"""
tools/secret_scanner_tool.py
==============================
Pure-Python secret scanner — finds hardcoded secrets, tokens, and credentials
in source code using regex patterns and Shannon entropy analysis.

No external tools required — runs fully air-gapped.
Complements Semgrep secrets.yml with broader coverage (all file types, entropy).
"""

from __future__ import annotations

import math
import re
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class SecretPattern:
    name: str
    regex: str
    severity: str
    description: str
    _compiled: re.Pattern = field(init=False, repr=False)

    def __post_init__(self):
        self._compiled = re.compile(self.regex)

    def finditer(self, text: str):
        return self._compiled.finditer(text)


PATTERNS: list[SecretPattern] = [
    SecretPattern("aws-access-key-id",     r'AKIA[0-9A-Z]{16}',                                              "CRITICAL", "AWS Access Key ID"),
    SecretPattern("aws-secret-access-key", r'(?i)aws[^\n]{0,20}secret[^\n]{0,20}[=:]\s*[\'"]?([A-Za-z0-9+/]{40})[\'"]?', "CRITICAL", "AWS Secret Access Key"),
    SecretPattern("github-personal-token", r'ghp_[0-9a-zA-Z]{36}',                                           "CRITICAL", "GitHub Personal Access Token"),
    SecretPattern("github-oauth-token",    r'gho_[0-9a-zA-Z]{36}',                                           "CRITICAL", "GitHub OAuth Token"),
    SecretPattern("github-app-token",      r'(?:ghs_|ghu_)[0-9a-zA-Z]{36}',                                  "CRITICAL", "GitHub App/User Token"),
    SecretPattern("gitlab-token",          r'glpat-[0-9a-zA-Z\-_]{20}',                                      "CRITICAL", "GitLab Personal Access Token"),
    SecretPattern("stripe-live-key",       r'sk_live_[0-9a-zA-Z]{24,}',                                      "CRITICAL", "Stripe Live Secret Key"),
    SecretPattern("stripe-restricted-key", r'rk_live_[0-9a-zA-Z]{24,}',                                      "CRITICAL", "Stripe Restricted Key"),
    SecretPattern("private-key-pem",       r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY',             "CRITICAL", "PEM Private Key Block"),
    SecretPattern("slack-token",           r'xox[baprs]-[0-9a-zA-Z]{10,48}',                                 "HIGH",     "Slack API Token"),
    SecretPattern("slack-webhook",         r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+', "HIGH", "Slack Webhook URL"),
    SecretPattern("google-api-key",        r'AIza[0-9A-Za-z\-_]{35}',                                        "HIGH",     "Google API Key"),
    SecretPattern("jwt-token",             r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', "HIGH",    "JSON Web Token (JWT)"),
    SecretPattern("db-connection-string",  r'(?i)(?:mysql|postgresql|mongodb|redis|jdbc)://[^:\s]+:[^@\s]{4,}@', "HIGH", "Database connection string with credentials"),
    SecretPattern("sendgrid-key",          r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}',                     "HIGH",     "SendGrid API Key"),
    SecretPattern("npm-token",             r'npm_[A-Za-z0-9]{36}',                                           "HIGH",     "npm Access Token"),
    SecretPattern("hardcoded-password",    r'(?i)(?:password|passwd|pwd)\s*[=:]\s*[\'"]([^\'"\s]{8,})[\'"]', "HIGH",     "Hardcoded password"),
    SecretPattern("hardcoded-api-key",     r'(?i)api[_\-]?key\s*[=:]\s*[\'"]([A-Za-z0-9_\-]{16,})[\'"]',   "HIGH",     "Hardcoded API key"),
    SecretPattern("hardcoded-secret",      r'(?i)(?:client[_\-]?secret|app[_\-]?secret)\s*[=:]\s*[\'"]([A-Za-z0-9_\-]{16,})[\'"]', "HIGH", "Hardcoded client/app secret"),
    SecretPattern("generic-bearer-token",  r'(?i)bearer\s+([A-Za-z0-9_\-\.]{20,})',                         "MEDIUM",   "Bearer token in code"),
    SecretPattern("private-key-inline",    r'(?i)private[_\-]?key\s*[=:]\s*[\'"]([A-Za-z0-9+/=]{32,})[\'"]', "HIGH",   "Inline private key value"),
    SecretPattern("twilio-account-sid",    r'AC[0-9a-f]{32}',                                                "HIGH",     "Twilio Account SID"),
]

_SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__",
    "target", "build", "dist", ".idea", ".gradle",
}
_SKIP_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".mp3",
    ".pdf", ".zip", ".tar", ".gz", ".jar", ".war", ".class",
    ".pyc", ".lock", ".sum",
}
_ALLOWLIST_KEYWORDS = {
    "example", "sample", "test", "mock", "fixture",
    "dummy", "fake", ".example", ".sample",
}
_PLACEHOLDER_VALUES = {
    "your_secret_key", "your-api-key", "your_token", "changeme",
    "replace_me", "xxx", "yyy", "example", "placeholder", "dummy",
    "secret_key_here", "api_key_here", "password_here", "todo",
    "your-password", "your-token", "insert_key_here",
}
_MAX_FILE_BYTES = 1_048_576  # 1 MB


@dataclass
class SecretFinding:
    file_path: str
    line_start: int
    secret_type: str
    severity: str
    description: str
    match_preview: str      # partially redacted to avoid storing real secret
    entropy: Optional[float] = None
    context_line: Optional[str] = None


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _redact(value: str, keep: int = 6) -> str:
    if len(value) <= keep:
        return "*" * len(value)
    return value[:keep] + f"...[+{len(value) - keep} chars redacted]"


class SecretScannerTool:
    """
    Scans a directory tree for hardcoded secrets using regex patterns
    and Shannon entropy analysis.
    """

    def __init__(self, min_entropy: float = 3.2):
        self.min_entropy = min_entropy

    def scan(self, scan_path: str) -> tuple[list[SecretFinding], dict]:
        root = Path(scan_path).resolve()
        findings: list[SecretFinding] = []
        files_scanned = 0
        files_skipped = 0
        files_with_secrets: set[str] = set()

        for path in root.rglob("*"):
            if not path.is_file():
                continue

            rel_parts = path.relative_to(root).parts
            if any(part in _SKIP_DIRS for part in rel_parts):
                files_skipped += 1
                continue

            if path.suffix.lower() in _SKIP_EXTS:
                files_skipped += 1
                continue

            try:
                if path.stat().st_size > _MAX_FILE_BYTES:
                    files_skipped += 1
                    continue
            except OSError:
                files_skipped += 1
                continue

            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except (OSError, IOError):
                files_skipped += 1
                continue

            files_scanned += 1
            rel_path = str(path.relative_to(root))
            path_lower = rel_path.lower()
            is_example = any(kw in path_lower for kw in _ALLOWLIST_KEYWORDS)

            file_findings = self._scan_text(text, rel_path, is_example)
            if file_findings:
                findings.extend(file_findings)
                files_with_secrets.add(rel_path)

        logger.info(
            "Secret scan complete | files_scanned=%d skipped=%d secrets=%d",
            files_scanned, files_skipped, len(findings),
        )
        return findings, {
            "files_scanned":      files_scanned,
            "files_skipped":      files_skipped,
            "files_with_secrets": len(files_with_secrets),
        }

    def _scan_text(self, text: str, rel_path: str, is_example: bool) -> list[SecretFinding]:
        findings: list[SecretFinding] = []
        lines = text.splitlines()

        for line_idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            # Skip pure comment lines that look like documentation
            if stripped.startswith(("#", "//", "*", "<!--", "--")):
                if not any(kw in stripped.lower() for kw in ("=", ":", "key", "token", "secret")):
                    continue

            for pattern in PATTERNS:
                for match in pattern.finditer(line):
                    matched_text = match.group(0)
                    secret_value = (
                        match.group(1)
                        if match.lastindex and match.lastindex >= 1
                        else matched_text
                    )

                    if len(secret_value) < 6:
                        continue

                    if secret_value.lower() in _PLACEHOLDER_VALUES:
                        continue

                    entropy = _shannon_entropy(secret_value)
                    if pattern.severity == "MEDIUM" and entropy < self.min_entropy:
                        continue

                    # Example/test files: only report CRITICAL
                    if is_example and pattern.severity not in ("CRITICAL",):
                        continue

                    context = line.replace(secret_value, _redact(secret_value, 4))

                    findings.append(SecretFinding(
                        file_path=rel_path,
                        line_start=line_idx,
                        secret_type=pattern.name,
                        severity=pattern.severity,
                        description=pattern.description,
                        match_preview=_redact(matched_text, 6),
                        entropy=round(entropy, 2),
                        context_line=context[:300],
                    ))

        return findings

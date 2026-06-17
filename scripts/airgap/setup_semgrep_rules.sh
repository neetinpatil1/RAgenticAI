#!/usr/bin/env bash
# =============================================================================
# scripts/airgap/setup_semgrep_rules.sh
# Download official Semgrep Java/Spring OWASP rules for air-gap bundling.
#
# Design (SSDLC_Design_v3.2.docx §3, Gap #2):
#   Rules sourced from semgrep/semgrep-rules (Apache 2.0, open source).
#   Downloaded ONCE on a machine with internet, committed to git.
#   All future scans use local copies — no network calls during scanning.
#
# Usage:
#   cd /path/to/RAgenticAI
#   bash scripts/airgap/setup_semgrep_rules.sh
#
# Output: agents/security/sast/rules/owasp/*.yml
# Cadence: Re-run quarterly to pick up new rules
# =============================================================================

set -euo pipefail

RULES_DIR="agents/security/sast/rules/owasp"
RAW="https://raw.githubusercontent.com/semgrep/semgrep-rules/develop"

mkdir -p "$RULES_DIR"

# Helper: download one rule file, skip silently if URL 404s
fetch() {
  local url="$1"
  local out="$2"
  if curl -fsSL --max-time 15 "$url" -o "$out" 2>/dev/null; then
    # Reject empty files and HTML error pages
    if [ -s "$out" ] && head -1 "$out" | grep -q "^rules:\|^-\|- id:"; then
      echo "  OK  $(basename "$out")"
    else
      rm -f "$out"
      echo "  --  $(basename "$out") (not a valid rule file, skipped)"
    fi
  else
    echo "  --  $(basename "$out") (not found upstream, skipped)"
  fi
}

echo "=============================================="
echo " Semgrep OWASP Rules — Air-Gap Download"
echo " Output: $RULES_DIR"
echo "=============================================="
echo ""

# ---------------------------------------------------------------------------
# A01 + A03: Broken Access Control / Injection — SQL
# ---------------------------------------------------------------------------
echo "[A01/A03] SQL Injection..."
fetch "$RAW/java/lang/security/audit/formatted-sql-string.yaml"                    "$RULES_DIR/java-sqli-formatted.yml"
fetch "$RAW/java/lang/security/audit/tainted-sql-string.yaml"                      "$RULES_DIR/java-sqli-tainted.yml"
fetch "$RAW/java/spring/security/injection/tainted-sql-from-http-request.yaml"    "$RULES_DIR/spring-sqli-http.yml"

# ---------------------------------------------------------------------------
# A01: Broken Access Control — Path Traversal, Open Redirect, IDOR
# ---------------------------------------------------------------------------
echo "[A01] Broken Access Control..."
fetch "$RAW/java/lang/security/audit/path-traversal.yaml"                          "$RULES_DIR/java-path-traversal.yml"
fetch "$RAW/java/spring/security/spring-unvalidated-redirect.yaml"                 "$RULES_DIR/spring-open-redirect.yml"

# ---------------------------------------------------------------------------
# A02: Cryptographic Failures
# ---------------------------------------------------------------------------
echo "[A02] Cryptographic Failures..."
fetch "$RAW/java/lang/security/audit/crypto/weak-hash.yaml"                        "$RULES_DIR/java-weak-hash.yml"
fetch "$RAW/java/lang/security/audit/crypto/use-of-sha1.yaml"                      "$RULES_DIR/java-sha1.yml"
fetch "$RAW/java/lang/security/audit/crypto/weak-rsa.yaml"                         "$RULES_DIR/java-weak-rsa.yml"
fetch "$RAW/java/lang/security/audit/crypto/no-static-iv.yaml"                     "$RULES_DIR/java-static-iv.yml"
fetch "$RAW/java/lang/security/audit/crypto/weak-ssl.yaml"                         "$RULES_DIR/java-weak-ssl.yml"
fetch "$RAW/java/lang/security/audit/crypto/use-of-des.yaml"                       "$RULES_DIR/java-des.yml"

# ---------------------------------------------------------------------------
# A03: Injection — OS Command, LDAP, XSS, Log
# ---------------------------------------------------------------------------
echo "[A03] Injection (Command, LDAP, XSS, Log)..."
fetch "$RAW/java/lang/security/audit/command-injection-formatted-runtime-call.yaml" "$RULES_DIR/java-command-injection.yml"
fetch "$RAW/java/lang/security/audit/ldap-injection.yaml"                           "$RULES_DIR/java-ldap-injection.yml"
fetch "$RAW/java/lang/security/audit/xss/xss-javaee.yaml"                           "$RULES_DIR/java-xss-javaee.yml"
fetch "$RAW/java/lang/security/audit/xss/xss-potential.yaml"                        "$RULES_DIR/java-xss-potential.yml"

# ---------------------------------------------------------------------------
# A05: Security Misconfiguration
# ---------------------------------------------------------------------------
echo "[A05] Security Misconfiguration..."
fetch "$RAW/java/spring/security/spring-cookie-without-secure.yaml"                "$RULES_DIR/spring-cookie-secure.yml"
fetch "$RAW/java/spring/security/spring-cookie-without-httponly.yaml"              "$RULES_DIR/spring-cookie-httponly.yml"
fetch "$RAW/java/lang/security/audit/xml/xxe.yaml"                                 "$RULES_DIR/java-xxe.yml"

# ---------------------------------------------------------------------------
# A07: Identification and Authentication Failures
# ---------------------------------------------------------------------------
echo "[A07] Auth Failures..."
fetch "$RAW/java/lang/security/audit/hardcoded-credentials.yaml"                   "$RULES_DIR/java-hardcoded-creds.yml"
fetch "$RAW/java/lang/security/audit/hardcoded-secret-key.yaml"                    "$RULES_DIR/java-hardcoded-key.yml"
fetch "$RAW/java/spring/security/missing-jwt-signature-check.yaml"                 "$RULES_DIR/spring-jwt.yml"

# ---------------------------------------------------------------------------
# A08: Software and Data Integrity Failures
# ---------------------------------------------------------------------------
echo "[A08] Insecure Deserialization..."
fetch "$RAW/java/lang/security/audit/object-deserialization.yaml"                  "$RULES_DIR/java-deserialization.yml"

# ---------------------------------------------------------------------------
# A10: Server-Side Request Forgery (SSRF)
# ---------------------------------------------------------------------------
echo "[A10] SSRF..."
fetch "$RAW/java/spring/security/injection/tainted-ssrf-spring.yaml"               "$RULES_DIR/spring-ssrf.yml"
fetch "$RAW/java/lang/security/audit/url-rewriting.yaml"                            "$RULES_DIR/java-url-rewriting.yml"

# ---------------------------------------------------------------------------
# Remove any empty files left over
# ---------------------------------------------------------------------------
find "$RULES_DIR" -name "*.yml" -empty -delete 2>/dev/null || true

DOWNLOADED=$(ls "$RULES_DIR"/*.yml 2>/dev/null | wc -l | tr -d ' ')
echo ""
echo "=============================================="
echo " Done. $DOWNLOADED rule files in $RULES_DIR/"
echo ""
echo " Next steps:"
echo "  1. Commit to git:"
echo "       git add $RULES_DIR && git commit -m 'feat: bundle official OWASP Semgrep rules'"
echo ""
echo "  2. Update .env:"
echo "       SEMGREP_DETECTION_RULES_PATH=./agents/security/sast/rules"
echo ""
echo "  3. Restart server and re-scan your project"
echo "=============================================="

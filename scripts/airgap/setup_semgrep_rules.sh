#!/usr/bin/env bash
# =============================================================================
# scripts/airgap/setup_semgrep_rules.sh
# Download and stage Semgrep rules for air-gapped deployment.
#
# Design (SSDLC_Design_v3.2.docx §3, Gap #2):
#   Rules pulled from registry.semgrep.dev ONCE on a jump workstation.
#   Committed to agents/security/sast/ in Gitea (Phase 1+).
#   Semgrep invoked with --config=file:///opt/semgrep-rules/ (no network call).
#
# Run this on a jump workstation WITH internet access.
# Transfer the output directory to the air-gapped machine via approved media.
#
# Usage:
#   ./scripts/airgap/setup_semgrep_rules.sh [--output-dir /path/to/rules]
#
# Output: rules directory ready to mount into Semgrep Docker container
# Cadence: Quarterly (as per design doc)
# =============================================================================

set -euo pipefail

OUTPUT_DIR="${1:-./semgrep-rules-bundle}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="./semgrep-rules-setup-${TIMESTAMP}.log"

echo "=============================================="
echo " Semgrep Rules — Air-Gap Bundle Setup"
echo " Output: ${OUTPUT_DIR}"
echo " Log:    ${LOG_FILE}"
echo "=============================================="

# --- Check prerequisites ---
if ! command -v semgrep &>/dev/null; then
  echo "ERROR: semgrep not installed. Run: pip install semgrep"
  exit 1
fi
if ! command -v sha256sum &>/dev/null && ! command -v shasum &>/dev/null; then
  echo "ERROR: sha256sum / shasum not found"
  exit 1
fi

mkdir -p "${OUTPUT_DIR}/java"
mkdir -p "${OUTPUT_DIR}/javascript"
mkdir -p "${OUTPUT_DIR}/generic"

echo "[$(date)] Starting rule download..." | tee -a "${LOG_FILE}"

# ---------------------------------------------------------------------------
# Java / Spring Boot rules
# ---------------------------------------------------------------------------
echo "Downloading Java security rules..."
semgrep --config "p/java"         --dry-run --json /dev/null 2>/dev/null || true
semgrep --config "p/spring"       --dry-run --json /dev/null 2>/dev/null || true
semgrep --config "p/owasp-top-ten" --dry-run --json /dev/null 2>/dev/null || true

# Download rule YAML files directly
JAVA_RULESETS=(
  "https://semgrep.dev/c/p/java"
  "https://semgrep.dev/c/p/spring"
  "https://semgrep.dev/c/p/owasp-top-ten"
  "https://semgrep.dev/c/p/sql-injection"
  "https://semgrep.dev/c/p/secrets"
)
for url in "${JAVA_RULESETS[@]}"; do
  rulename=$(basename "${url}")
  echo "  Fetching ${rulename}..."
  curl -fsSL "${url}" -o "${OUTPUT_DIR}/java/${rulename}.yml" 2>>"${LOG_FILE}" || {
    echo "  WARNING: Failed to fetch ${url}" | tee -a "${LOG_FILE}"
  }
done

# ---------------------------------------------------------------------------
# JavaScript / Angular / TypeScript rules
# ---------------------------------------------------------------------------
echo "Downloading JavaScript/Angular rules..."
JS_RULESETS=(
  "https://semgrep.dev/c/p/javascript"
  "https://semgrep.dev/c/p/typescript"
  "https://semgrep.dev/c/p/angular"
  "https://semgrep.dev/c/p/react"
)
for url in "${JS_RULESETS[@]}"; do
  rulename=$(basename "${url}")
  echo "  Fetching ${rulename}..."
  curl -fsSL "${url}" -o "${OUTPUT_DIR}/javascript/${rulename}.yml" 2>>"${LOG_FILE}" || {
    echo "  WARNING: Failed to fetch ${url}" | tee -a "${LOG_FILE}"
  }
done

# ---------------------------------------------------------------------------
# Copy project-specific FP rules
# ---------------------------------------------------------------------------
echo "Copying project FP rules..."
cp ./agents/security/sast/fp_rules.yml "${OUTPUT_DIR}/generic/project-fp-rules.yml"

# ---------------------------------------------------------------------------
# Generate SHA-256 manifest for integrity verification on air-gapped machine
# ---------------------------------------------------------------------------
echo "Generating SHA-256 manifest..."
MANIFEST="${OUTPUT_DIR}/manifest.txt"
echo "# Semgrep Rules Bundle — SHA-256 Manifest" > "${MANIFEST}"
echo "# Generated: ${TIMESTAMP}" >> "${MANIFEST}"
echo "#" >> "${MANIFEST}"

find "${OUTPUT_DIR}" -name "*.yml" -type f | sort | while read -r f; do
  if command -v sha256sum &>/dev/null; then
    sha256sum "${f}" >> "${MANIFEST}"
  else
    shasum -a 256 "${f}" >> "${MANIFEST}"
  fi
done

echo ""
echo "=============================================="
echo " Bundle ready: ${OUTPUT_DIR}"
echo " Manifest:     ${MANIFEST}"
echo " Rule files:   $(find "${OUTPUT_DIR}" -name "*.yml" | wc -l | tr -d ' ')"
echo ""
echo " NEXT STEPS (air-gapped machine):"
echo "  1. Transfer ${OUTPUT_DIR} via approved media"
echo "  2. Verify: sha256sum -c ${MANIFEST}"
echo "  3. Set SEMGREP_RULES_PATH to the transferred directory"
echo "  4. Test: docker run --rm -v /path/to/code:/src -v ${OUTPUT_DIR}:/rules \\"
echo "           semgrep/semgrep semgrep --config file:///rules /src"
echo "=============================================="

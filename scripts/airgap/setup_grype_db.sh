#!/usr/bin/env bash
# =============================================================================
# scripts/airgap/setup_grype_db.sh
# Download Grype vulnerability DB for air-gapped deployment.
#
# Design (SSDLC_Design_v3.2.docx §3, Gap #1):
#   'Nightly sync' in v3 assumed internet access — resolved in v3.2:
#   Weekly offline DB refresh: download on jump workstation,
#   hash-verify, transfer via approved media, serve from Nexus OSS.
#
# Run this on a jump workstation WITH internet access.
# Transfer output to air-gapped machine via approved media.
#
# Usage:
#   ./scripts/airgap/setup_grype_db.sh [--output-dir /path/to/grype-db]
#
# Cadence: Weekly (vulnerability DB changes frequently)
# =============================================================================

set -euo pipefail

OUTPUT_DIR="${1:-./grype-db-bundle}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "=============================================="
echo " Grype Vulnerability DB — Air-Gap Bundle"
echo " Output: ${OUTPUT_DIR}"
echo "=============================================="

# --- Check prerequisites ---
if ! command -v grype &>/dev/null; then
  echo "ERROR: grype not installed."
  echo "  Install: curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin"
  exit 1
fi

mkdir -p "${OUTPUT_DIR}"

# ---------------------------------------------------------------------------
# Download latest Grype vulnerability database
# ---------------------------------------------------------------------------
echo "Downloading Grype vulnerability database..."
GRYPE_DB_DIR="${OUTPUT_DIR}/grype-db"
mkdir -p "${GRYPE_DB_DIR}"

# Update Grype DB to latest
GRYPE_DB_CACHE_DIR="${GRYPE_DB_DIR}" grype db update

# Copy the downloaded DB files to output dir
DB_CACHE="${HOME}/.cache/grype/db"
if [ -d "${DB_CACHE}" ]; then
  cp -r "${DB_CACHE}/." "${GRYPE_DB_DIR}/"
  echo "  Grype DB copied from ${DB_CACHE}"
else
  echo "  WARNING: Could not find Grype DB cache at ${DB_CACHE}"
  echo "  Run 'grype db update' first and check GRYPE_DB_CACHE_DIR"
fi

# ---------------------------------------------------------------------------
# Download Trivy DB as well (Gap #1 also covers Trivy)
# ---------------------------------------------------------------------------
if command -v trivy &>/dev/null; then
  echo "Downloading Trivy vulnerability database..."
  TRIVY_CACHE="${OUTPUT_DIR}/trivy-db"
  mkdir -p "${TRIVY_CACHE}"
  TRIVY_CACHE_DIR="${TRIVY_CACHE}" trivy image --download-db-only 2>/dev/null || {
    echo "  WARNING: Trivy DB download failed — continuing with Grype only"
  }
else
  echo "  Trivy not installed — skipping (install from https://github.com/aquasecurity/trivy)"
fi

# ---------------------------------------------------------------------------
# Generate SHA-256 manifest
# ---------------------------------------------------------------------------
echo "Generating SHA-256 manifest..."
MANIFEST="${OUTPUT_DIR}/manifest.txt"
echo "# Grype/Trivy DB Bundle — SHA-256 Manifest" > "${MANIFEST}"
echo "# Generated: ${TIMESTAMP}" >> "${MANIFEST}"
echo "#" >> "${MANIFEST}"

find "${OUTPUT_DIR}" -type f ! -name "manifest.txt" | sort | while read -r f; do
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
echo ""
echo " NEXT STEPS (air-gapped machine):"
echo "  1. Transfer ${OUTPUT_DIR} via approved media"
echo "  2. Verify: sha256sum -c ${MANIFEST}"
echo "  3. Set env vars:"
echo "     export GRYPE_DB_UPDATE_URL=file://${GRYPE_DB_DIR}"
echo "     export GRYPE_DB_CACHE_DIR=${GRYPE_DB_DIR}"
echo "     export TRIVY_CACHE_DIR=${TRIVY_CACHE}"
echo "     export TRIVY_DB_REPOSITORY=<internal-registry-if-using-Nexus>"
echo "  4. Test: grype <image-or-path>"
echo "=============================================="

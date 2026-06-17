#!/usr/bin/env bash
# =============================================================================
# scripts/airgap/setup_ollama_models.sh
# Download Ollama LLM models for air-gapped deployment.
#
# Design (SSDLC_Design_v3.2.docx §3, Gap #6):
#   ollama pull on jump workstation → copy ~/.ollama/models/ to air-gapped
#   Mac via approved transfer. Set OLLAMA_MODELS=/opt/ollama-models.
#
# Run on a jump workstation WITH internet access.
# Transfer ~/.ollama/models/ to air-gapped machine via approved media.
#
# Usage:
#   ./scripts/airgap/setup_ollama_models.sh [--output-dir /path/to/ollama-bundle]
#
# Cadence: Quarterly or per model refresh cycle (SSDLC_Design_v3.2.docx §10)
# =============================================================================

set -euo pipefail

OUTPUT_DIR="${1:-./ollama-models-bundle}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "=============================================="
echo " Ollama Models — Air-Gap Bundle"
echo " Output: ${OUTPUT_DIR}"
echo "=============================================="

# --- Check prerequisites ---
if ! command -v ollama &>/dev/null; then
  echo "ERROR: ollama not installed."
  echo "  Install: https://ollama.ai/download"
  exit 1
fi

mkdir -p "${OUTPUT_DIR}"

# ---------------------------------------------------------------------------
# Models to pull (from SSDLC_Design_v3.2.docx §2.2)
# ---------------------------------------------------------------------------
MODELS=(
  "qwen2.5-coder:14b"   # Tier 1 — primary SAST/code review/FP analysis (~10GB)
  "llama3.2:3b"         # Tier 2 — fast classification/routing (~2.5GB)
)

for model in "${MODELS[@]}"; do
  echo ""
  echo "Pulling model: ${model}"
  ollama pull "${model}"
  echo "  ✓ ${model} pulled"
done

# ---------------------------------------------------------------------------
# Copy Ollama model files to output directory
# ---------------------------------------------------------------------------
OLLAMA_MODELS_DIR="${HOME}/.ollama/models"
if [ ! -d "${OLLAMA_MODELS_DIR}" ]; then
  echo "ERROR: Ollama models directory not found at ${OLLAMA_MODELS_DIR}"
  exit 1
fi

echo ""
echo "Copying model files to ${OUTPUT_DIR}..."
cp -r "${OLLAMA_MODELS_DIR}/." "${OUTPUT_DIR}/"

# ---------------------------------------------------------------------------
# Generate model manifest with SHA-256 hashes (air-gap integrity verification)
# ---------------------------------------------------------------------------
echo "Generating model manifest..."
MANIFEST="${OUTPUT_DIR}/model_manifest.json"

python3 - <<'PYEOF'
import json, hashlib, os, sys
from pathlib import Path
from datetime import datetime, timezone

output_dir = sys.argv[1] if len(sys.argv) > 1 else "."
manifest = {
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "models": []
}

# Find all .bin and model blob files
for f in sorted(Path(output_dir).rglob("*")):
    if f.is_file() and f.suffix in (".bin", "") and f.stat().st_size > 10_000_000:
        sha256 = hashlib.sha256(f.read_bytes()).hexdigest()
        size_gb = f.stat().st_size / (1024**3)
        manifest["models"].append({
            "path": str(f.relative_to(output_dir)),
            "size_gb": round(size_gb, 2),
            "sha256": sha256,
            "security_reviewed": False,   # set to True after security review
            "approved_by": None,          # fill in before production deployment
        })
        print(f"  {f.name} ({size_gb:.1f}GB) — SHA256: {sha256[:16]}...")

with open(Path(output_dir) / "model_manifest.json", "w") as mf:
    json.dump(manifest, mf, indent=2)
print(f"\nManifest written to model_manifest.json")
PYEOF
"${OUTPUT_DIR}"

echo ""
echo "=============================================="
echo " Bundle ready: ${OUTPUT_DIR}"
echo " Manifest:     ${OUTPUT_DIR}/model_manifest.json"
echo ""
echo " NEXT STEPS (air-gapped machine):"
echo "  1. Transfer ${OUTPUT_DIR} via approved media"
echo "  2. Verify SHA-256 hashes from model_manifest.json"
echo "  3. Place files at /opt/ollama-models/ (or your preferred path)"
echo "  4. Set: export OLLAMA_MODELS=/opt/ollama-models"
echo "  5. Restart Ollama: ollama serve"
echo "  6. Verify: ollama list"
echo ""
echo "  IMPORTANT: Update model_manifest.json:"
echo "    - Set security_reviewed: true after security team reviews"
echo "    - Set approved_by: <name> before production deployment"
echo "    - Commit manifest to Gitea security-rules repo"
echo "=============================================="

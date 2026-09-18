#!/usr/bin/env bash
# ==============================================================================
# Cevell OS: Portable Cryptographic Provenance Auditor
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="$(which python3 || echo "")"

if [ -z "$PYTHON_BIN" ]; then
    echo "[❌ ERROR] python3 is required to run the provenance audit."
    exit 1
fi

exec "$PYTHON_BIN" "$SCRIPT_DIR/verify_provenance.py" "$@"

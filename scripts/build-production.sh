#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "================================================================="
echo "   CEVELL OS PRODUCTION IMAGE BUILDER (AWS AMD SEV-SNP)"
echo "================================================================="
echo "[*] Source Directory: ${SOURCE_DIR}"
echo "[*] Building Cevell OS UEFI Bootable Image..."

cd "${SOURCE_DIR}"
export TMPDIR="${TMPDIR:-/var/tmp}"

# ==============================================================================
# MANDATORY DEBUG FLAG VERIFICATION
# ==============================================================================
# The build script refuses to execute without an explicit declaration of DEBUG.
# - DEBUG=off (Production): Strictly kills & locks down all virtual serial devices
#   (/dev/ttyS0, /dev/console, /dev/tty1). Silent kernel boot (console=null).
#   No terminal or console exists for any process or attacker to run commands.
# - DEBUG=on  (Development): Enables virtual serial console for hypervisor logging.
# ==============================================================================
RAW_DEBUG="${DEBUG:-}"
if [ -z "${RAW_DEBUG}" ]; then
    echo "================================================================="
    echo "[❌ FATAL BUILD CONFIGURATION ERROR: MISSING MANDATORY DEBUG FLAG]"
    echo "================================================================="
    echo "The build script will NOT run without an explicit DEBUG declaration."
    echo ""
    echo "Please specify DEBUG=off or DEBUG=on before running the build:"
    echo ""
    echo "  DEBUG=off ./scripts/build-production.sh   (PRODUCTION: Zero console, fully locked down)"
    echo "  DEBUG=on  ./scripts/build-production.sh   (DEVELOPMENT: Serial console enabled for debugging)"
    echo "================================================================="
    exit 1
fi

DEBUG_MODE="$(echo "${RAW_DEBUG}" | tr '[:upper:]' '[:lower:]')"
if [ "${DEBUG_MODE}" != "on" ] && [ "${DEBUG_MODE}" != "off" ]; then
    echo "[❌ FATAL BUILD CONFIGURATION ERROR] DEBUG must be 'on' or 'off'. Received: '${RAW_DEBUG}'"
    exit 1
fi

echo "[*] Mandatory Debug Mode Confirmed: DEBUG=${DEBUG_MODE}"

NIX_BUILD="$(which nix-build 2>/dev/null || echo "")"
if [ -z "${NIX_BUILD}" ]; then
    for p in "${HOME}/.nix-profile/bin/nix-build" "/nix/var/nix/profiles/default/bin/nix-build"; do
        if [ -x "$p" ]; then
            NIX_BUILD="$p"
            break
        fi
    done
fi

if [ -z "${NIX_BUILD}" ]; then
    echo "[❌ ERROR] nix-build could not be found. Please ensure Nix is installed and in PATH."
    exit 1
fi

# Verify upstream bootloader and kernel assets are present; if missing, auto-install
if [ ! -f "${SOURCE_DIR}/boot-efi/vmlinuz-aws" ] || [ ! -d "${SOURCE_DIR}/boot-efi/nvidia-modules" ]; then
    echo "[*] Upstream bootloader or driver assets missing in boot-efi/. Running requirements installer..."
    "${SOURCE_DIR}/scripts/install-requirements.sh"
fi

# 1. Build Go binary artifacts
echo "[1/3] Compiling unified cevell-node engine (debug=${DEBUG_MODE})..."
"${NIX_BUILD}" --argstr debug "${DEBUG_MODE}" -A cevell-node --out-link result-node

# 2. Build stage 1 initrd
echo "[2/3] Building verified dm-verity initrd..."
"${NIX_BUILD}" --argstr debug "${DEBUG_MODE}" -A initrd --out-link result-initrd

# 3. Build two-pass bootable UEFI image
echo "[3/3] Generating two-pass deterministic UEFI disk image with dm-verity (debug=${DEBUG_MODE})..."
"${NIX_BUILD}" --argstr debug "${DEBUG_MODE}" -A bootable-image --out-link result-image

echo "================================================================="
echo "[✓] Production Image Build Complete!"
echo "    Disk Image: $(readlink -f result-image)/cevell-os.raw"
if [ -f "$(readlink -f result-image)/cevell-os.roothash" ]; then
    echo "    dm-verity Root Hash: $(cat "$(readlink -f result-image)/cevell-os.roothash")"
fi
echo "================================================================="

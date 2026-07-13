#!/usr/bin/env bash
# SecurityOps Assistant — one-shot installer for Kali Linux.
#
# Installs system dependencies, creates a Python virtual environment in
# .venv/, and installs the application's Python requirements. Safe to re-run.
#
# Usage:
#   ./scripts/install.sh          # install everything, then print run instructions
#   ./scripts/install.sh --run    # install, then launch the app immediately

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

info()  { printf '\033[1;34m[install]\033[0m %s\n' "$1"; }
warn()  { printf '\033[1;33m[install]\033[0m %s\n' "$1"; }
error() { printf '\033[1;31m[install]\033[0m %s\n' "$1" >&2; }

if [[ "$(uname -s)" != "Linux" ]]; then
    warn "This script targets Kali Linux. Continuing anyway, but apt steps will fail."
fi

# --------------------------------------------------------------------------- #
# 1. Pick a Python interpreter (3.12+ preferred, 3.11 accepted with a warning)
# --------------------------------------------------------------------------- #
PYTHON_BIN=""
for candidate in python3.12 python3.13 python3; do
    if command -v "$candidate" >/dev/null 2>&1; then
        PYTHON_BIN="$candidate"
        break
    fi
done

if [[ -z "$PYTHON_BIN" ]]; then
    error "No python3 interpreter found. Install Python 3.12+ and re-run."
    exit 1
fi

PY_VERSION="$("$PYTHON_BIN" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
info "Using $PYTHON_BIN (Python $PY_VERSION)"

if ! "$PYTHON_BIN" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)'; then
    warn "Python $PY_VERSION detected; this app targets 3.12+. It may still work on 3.11,"
    warn "but modern type-hint syntax used in the code requires 3.10+ at minimum."
fi

# --------------------------------------------------------------------------- #
# 2. System packages (Qt platform libs + PDF export deps + venv/pip)
# --------------------------------------------------------------------------- #
if command -v apt-get >/dev/null 2>&1; then
    info "Installing system packages via apt (sudo required)…"
    sudo apt-get update -qq
    sudo apt-get install -y \
        python3-venv python3-pip \
        libgl1 libegl1 libxkbcommon0 libxcb-cursor0 libnss3 libxdamage1 \
        libpango-1.0-0 libpangocairo-1.0-0 libcairo2 \
        || warn "Some system packages failed to install; continuing anyway."
else
    warn "apt-get not found; skipping system package installation."
fi

# --------------------------------------------------------------------------- #
# 3. Virtual environment + Python dependencies
# --------------------------------------------------------------------------- #
if [[ ! -d ".venv" ]]; then
    info "Creating virtual environment in .venv/"
    "$PYTHON_BIN" -m venv .venv
else
    info "Reusing existing .venv/"
fi

# shellcheck disable=SC1091
source .venv/bin/activate

info "Upgrading pip"
pip install --upgrade pip --quiet

info "Installing Python requirements"
pip install -r requirements.txt

info "Installation complete."
echo
echo "To run SecurityOps Assistant:"
echo "  source .venv/bin/activate"
echo "  python -m securityops"
echo

if [[ "${1:-}" == "--run" ]]; then
    info "Launching SecurityOps Assistant…"
    exec python -m securityops
fi

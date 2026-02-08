#!/usr/bin/env bash
#
# QJ Security Dashboard — Start Script
# ======================================
# Creates Python venv if needed, installs deps, launches the server.
#
# Usage:
#   ./start.sh              # Start on port 5000
#   ./start.sh --port 8080  # Custom port
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"
REQ_FILE="$SCRIPT_DIR/requirements.txt"

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║   🛡️  QJ Security Dashboard                  ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# 1. Check Python
if ! command -v python3 &>/dev/null; then
    echo "❌ Python 3 is required but not found."
    echo "   Install with: brew install python3"
    exit 1
fi

PYTHON_VERSION=$(python3 --version 2>&1)
echo "✓ Found $PYTHON_VERSION"

# 2. Create venv if not exists
if [ ! -d "$VENV_DIR" ]; then
    echo "→ Creating virtual environment in .venv ..."
    python3 -m venv "$VENV_DIR"
    echo "✓ Virtual environment created"
else
    echo "✓ Virtual environment exists"
fi

# 3. Activate venv
source "$VENV_DIR/bin/activate"

# 4. Install / update requirements
echo "→ Installing dependencies ..."
pip install -q --upgrade pip
pip install -q -r "$REQ_FILE"
echo "✓ Dependencies installed"

# 5. Launch server
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Starting server..."
echo "  Open: http://localhost:5050"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

python "$SCRIPT_DIR/server.py" "$@"

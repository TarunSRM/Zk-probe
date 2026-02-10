#!/bin/bash
#
# Run Phase 2 Detection Engine
# This script runs the Phase 2 detector, reading snapshots from stdin

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Configuration
CONFIG_PATH="${PHASE2_CONFIG:-$PROJECT_ROOT/phase2/config/invariants.yaml}"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=== Phase 2 Detector ===${NC}" >&2
echo "Project root: $PROJECT_ROOT" >&2
echo "Config: $CONFIG_PATH" >&2
echo "" >&2

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo -e "${YELLOW}Error: python3 not found${NC}" >&2
    exit 1
fi

# Check if package is installed or use PYTHONPATH
if ! python3 -c "import zkNIDS_phase2" 2>/dev/null; then
    echo "Package not installed, using PYTHONPATH..." >&2
    export PYTHONPATH="$PROJECT_ROOT/phase2:$PYTHONPATH"
fi

# Run Phase 2 detector
cd "$PROJECT_ROOT/phase2"
if [ -f "$CONFIG_PATH" ]; then
    exec python3 -m zkNIDS_phase2 --config "$CONFIG_PATH"
else
    echo -e "${YELLOW}Warning: Config file not found, using defaults${NC}" >&2
    exec python3 -m zkNIDS_phase2
fi
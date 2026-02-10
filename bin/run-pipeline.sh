#!/bin/bash
#
# Run Full Phase 1 → Phase 2 Pipeline
# This script pipes Phase 1 snapshots directly into Phase 2 detector

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}=== zkNIDS Full Pipeline ===${NC}"
echo -e "${BLUE}Phase 1 → Phase 2${NC}"
echo ""

# Check for root (Phase 1 needs it)
if [ "$EUID" -ne 0 ]; then
    echo "This pipeline requires root privileges for Phase 1"
    echo "Please run with sudo:"
    echo "  sudo $0"
    exit 1
fi

# Optional: Save snapshots to file while processing
if [ -n "$SAVE_SNAPSHOTS" ]; then
    echo "Saving snapshots to: $SAVE_SNAPSHOTS"
    exec "$SCRIPT_DIR/run-phase1.sh" | tee "$SAVE_SNAPSHOTS" | "$SCRIPT_DIR/run-phase2.sh"
else
    exec "$SCRIPT_DIR/run-phase1.sh" | "$SCRIPT_DIR/run-phase2.sh"
fi
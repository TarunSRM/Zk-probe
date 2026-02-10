#!/bin/bash
#
# Run Phase 1 Invariant Collector
# This script resolves paths and runs the Phase 1 loader

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Auto-detect network interface if not specified
if [ -z "$PHASE1_INTERFACE" ]; then
    # Try to find the first active non-loopback interface
    INTERFACE=$(ip -o link show | awk -F': ' '$2 !~ /^lo$/ && $2 !~ /^docker/ && $2 !~ /^br-/ {print $2; exit}')
    
    if [ -z "$INTERFACE" ]; then
        echo "Error: No network interface found. Please specify one:" >&2
        echo "  export PHASE1_INTERFACE=<your_interface>" >&2
        echo "" >&2
        echo "Available interfaces:" >&2
        ip link show >&2
        exit 1
    fi
    
    echo "Auto-detected interface: $INTERFACE" >&2
else
    INTERFACE="$PHASE1_INTERFACE"
fi

BPF_DIR="$PROJECT_ROOT/phase1/build/bpf"
INTERVAL="${PHASE1_INTERVAL:-1}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Phase 1 Loader ===${NC}" >&2
echo "Project root: $PROJECT_ROOT" >&2
echo "Interface: $INTERFACE" >&2
echo "BPF directory: $BPF_DIR" >&2
echo "Snapshot interval: ${INTERVAL}s" >&2
echo "" >&2

# Check if phase1_loader exists
LOADER_PATH="$PROJECT_ROOT/phase1/userspace/collector/phase1_loader"
if [ ! -f "$LOADER_PATH" ]; then
    echo -e "${RED}Error: phase1_loader not found at $LOADER_PATH${NC}" >&2
    echo "Please build Phase 1 first:" >&2
    echo "  cd $PROJECT_ROOT/phase1" >&2
    echo "  make" >&2
    exit 1
fi

# Check if BPF objects exist
if [ ! -d "$BPF_DIR" ] || [ -z "$(ls -A $BPF_DIR 2>/dev/null)" ]; then
    echo -e "${RED}Error: BPF objects not found in $BPF_DIR${NC}" >&2
    echo "Please build Phase 1 first:" >&2
    echo "  cd $PROJECT_ROOT/phase1" >&2
    echo "  make" >&2
    exit 1
fi

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}Warning: Phase 1 requires root privileges to attach eBPF programs${NC}" >&2
    echo "Please run with sudo:" >&2
    echo "  sudo $0" >&2
    exit 1
fi

# Run Phase 1 loader
cd "$PROJECT_ROOT/phase1/userspace/collector"
exec ./phase1_loader --interface "$INTERFACE" --bpf-dir "$BPF_DIR" --interval "$INTERVAL"
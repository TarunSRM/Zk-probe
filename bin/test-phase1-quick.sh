#!/bin/bash
#
# Quick Phase 1 Verification
# Tests if XDP is capturing ANY traffic at all
#

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}Quick Phase 1 Test${NC}"
echo ""

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Must run as root${NC}"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT/phase1/userspace/collector"

echo "Starting Phase 1 for 10 seconds..."
echo ""

# Auto-detect interface
INTERFACE=$(ip -o link show | awk -F': ' '$2 !~ /^lo$/ && $2 !~ /^docker/ && $2 !~ /^br-/ {print $2; exit}')

if [ -z "$INTERFACE" ]; then
    echo -e "${RED}Could not auto-detect interface${NC}"
    echo "Available interfaces:"
    ip link show
    exit 1
fi

echo "Using interface: $INTERFACE"
echo ""

# Start Phase 1
timeout 10 ./phase1_loader $INTERFACE 1 > /tmp/quick_test.txt 2>&1 &
PHASE1_PID=$!

# Generate traffic
sleep 2
echo "Generating traffic (pinging 8.8.8.8)..."
ping -c 5 8.8.8.8 > /dev/null 2>&1 &

# Wait
sleep 8

# Check output
echo ""
echo "Results:"
echo ""

if [ -f /tmp/quick_test.txt ]; then
    SNAPSHOTS=$(grep -c "^T=" /tmp/quick_test.txt || echo "0")
    echo "Snapshots generated: $SNAPSHOTS"
    
    if [ "$SNAPSHOTS" -gt 0 ]; then
        echo ""
        echo "First snapshot:"
        head -1 /tmp/quick_test.txt
        echo ""
        echo "Last snapshot:"
        tail -1 /tmp/quick_test.txt
        echo ""
        
        # Parse last snapshot
        LAST=$(tail -1 /tmp/quick_test.txt)
        PACKETS=$(echo "$LAST" | grep -oP 'packets=\K\d+' || echo "0")
        EXECVE=$(echo "$LAST" | grep -oP 'execve=\K\d+' || echo "0")
        
        echo "Final counts:"
        echo "  Packets: $PACKETS"
        echo "  Execve:  $EXECVE"
        echo ""
        
        if [ "$PACKETS" -gt 0 ]; then
            echo -e "${GREEN}✓ SUCCESS: XDP is capturing packets!${NC}"
            echo ""
            echo "Your Phase 1 is working correctly!"
            echo "The issue is likely with:"
            echo "  1. Network attack not reaching the interface"
            echo "  2. hping3 parameters"
            echo "  3. Threshold settings in Phase 2"
        else
            echo -e "${YELLOW}⚠ XDP loaded but no packets captured${NC}"
            echo ""
            echo "This could mean:"
            echo "  1. No traffic on ens33"
            echo "  2. XDP program not attached correctly"
            echo "  3. Interface has no activity"
        fi
    else
        echo -e "${RED}✗ No snapshots generated${NC}"
        echo ""
        echo "Phase 1 output:"
        cat /tmp/quick_test.txt
    fi
else
    echo -e "${RED}✗ No output file created${NC}"
fi

echo ""
echo "Full output saved to: /tmp/quick_test.txt"
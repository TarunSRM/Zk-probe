#!/bin/bash
#
# Comprehensive Phase 1 Network Capture Diagnostic
#

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}═══ Phase 1 Network Capture Diagnostic ═══${NC}"
echo ""

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Must run as root${NC}"
    exit 1
fi

# Get IP
IP=$(ip -4 addr show ens33 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
echo "Your IP: $IP"
echo ""

# Start Phase 1 with verbose output
cd /home/ubuntu/projects/zkNIDS/phase1/userspace/collector

echo -e "${CYAN}Starting Phase 1 (10 seconds)...${NC}"
./phase1_loader -i ens33 -s 1 > /tmp/phase1_diagnostic.txt 2>&1 &
PID=$!

sleep 2

# Generate baseline traffic
echo "Generating baseline (5 seconds)..."
for i in {1..5}; do
    ping -c 1 -W 1 8.8.8.8 > /dev/null 2>&1
    sleep 1
done

echo ""
echo -e "${YELLOW}Now from another machine, run:${NC}"
echo "  sudo hping3 -1 -c 100 $IP"
echo ""
read -p "Press Enter after sending 100 packets..."

# Wait a bit more
sleep 3

# Stop
kill $PID 2>/dev/null
sleep 1

echo ""
echo -e "${CYAN}═══ Analysis ═══${NC}"
echo ""

# Show snapshots
SNAPSHOTS=$(grep -c "^T=" /tmp/phase1_diagnostic.txt || echo "0")
echo "Snapshots generated: $SNAPSHOTS"
echo ""

if [ "$SNAPSHOTS" -gt 0 ]; then
    echo "First 3 snapshots:"
    grep "^T=" /tmp/phase1_diagnostic.txt | head -3
    echo ""
    
    echo "Last 3 snapshots:"
    grep "^T=" /tmp/phase1_diagnostic.txt | tail -3
    echo ""
    
    # Parse last snapshot
    LAST=$(grep "^T=" /tmp/phase1_diagnostic.txt | tail -1)
    
    PACKETS=$(echo "$LAST" | grep -oP 'packets=\K\d+')
    FLOWS=$(echo "$LAST" | grep -oP 'flows=\K\d+')
    SYN=$(echo "$LAST" | grep -oP 'syn=\K\d+')
    BYTES=$(echo "$LAST" | grep -oP 'bytes=\K\d+')
    
    echo "Final counters:"
    echo "  Packets: $PACKETS"
    echo "  Flows:   $FLOWS"
    echo "  SYN:     $SYN"
    echo "  Bytes:   $BYTES"
    echo ""
    
    if [ "$PACKETS" -gt 50 ]; then
        echo -e "${GREEN}✓ Phase 1 IS capturing packets!${NC}"
        echo ""
        echo "The problem is likely in Phase 2 detection thresholds."
    elif [ "$PACKETS" -gt 0 ]; then
        echo -e "${YELLOW}⚠ Phase 1 capturing some packets, but not many${NC}"
        echo ""
        echo "This could mean:"
        echo "  - hping3 packets being dropped"
        echo "  - Network issues"
        echo "  - Firewall"
    else
        echo -e "${RED}✗ Phase 1 NOT capturing external packets${NC}"
        echo ""
        echo "This could mean:"
        echo "  - XDP not working correctly"
        echo "  - Packets not reaching interface"
        echo "  - Interface issue"
    fi
else
    echo -e "${RED}✗ No snapshots generated${NC}"
    echo ""
    echo "Phase 1 output:"
    cat /tmp/phase1_diagnostic.txt
fi

echo ""
echo "Full output: /tmp/phase1_diagnostic.txt"

#!/bin/bash
#
# Quick Counter Change Test
# Verifies Phase 1 counters reset between snapshots
#

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}Quick Counter Test${NC}"
echo ""

cd /home/ubuntu/projects/zkNIDS/phase1/userspace/collector

echo "Running Phase 1 for 10 seconds with traffic..."
echo ""

# Start Phase 1
./phase1_loader -i ens33 -s 1 > /tmp/counter_test.txt 2>&1 &
PID=$!

sleep 2

# Generate continuous traffic
echo "Generating traffic..."
for i in {1..8}; do
    ping -c 3 8.8.8.8 > /dev/null 2>&1 &
    sleep 1
done

sleep 2

# Stop
kill $PID 2>/dev/null
sleep 1

echo ""
echo -e "${CYAN}Analysis:${NC}"
echo ""

# Get snapshots
SNAPSHOTS=$(grep "^T=" /tmp/counter_test.txt)
SNAP_COUNT=$(echo "$SNAPSHOTS" | wc -l)

echo "Snapshots generated: $SNAP_COUNT"
echo ""

if [ "$SNAP_COUNT" -lt 3 ]; then
    echo -e "${RED}Not enough snapshots to analyze${NC}"
    cat /tmp/counter_test.txt
    exit 1
fi

# Show first 3 and last 3
echo "First 3 snapshots:"
echo "$SNAPSHOTS" | head -3
echo ""

echo "Last 3 snapshots:"
echo "$SNAPSHOTS" | tail -3
echo ""

# Extract packet counts
echo "Packet count analysis:"
COUNTS=$(echo "$SNAPSHOTS" | grep -oP 'packets=\K\d+')

echo "$COUNTS" | head -10 | while read count; do
    echo "  packets=$count"
done

echo ""

# Check if counts are changing
FIRST=$(echo "$COUNTS" | head -1)
LAST=$(echo "$COUNTS" | tail -1)
UNIQUE=$(echo "$COUNTS" | sort -u | wc -l)

echo "Summary:"
echo "  First snapshot: $FIRST packets"
echo "  Last snapshot:  $LAST packets"
echo "  Unique values:  $UNIQUE"
echo ""

if [ "$UNIQUE" -eq 1 ]; then
    echo -e "${RED}✗ COUNTERS NOT CHANGING!${NC}"
    echo ""
    echo "This means:"
    echo "  1. Map clearing is NOT working"
    echo "  2. Phase 1 was not rebuilt with fixes"
    echo ""
    echo "FIX:"
    echo "  cd /home/ubuntu/projects/zkNIDS/phase1"
    echo "  make clean"
    echo "  make"
elif [ "$FIRST" = "$LAST" ]; then
    echo -e "${YELLOW}⚠ Start and end values same (might be low traffic)${NC}"
else
    echo -e "${GREEN}✓ COUNTERS ARE CHANGING!${NC}"
    echo ""
    echo "Map clearing is working correctly."
    echo "If no alerts, issue is likely:"
    echo "  - Thresholds too high"
    echo "  - Attacks not aggressive enough"
    echo "  - Baseline too high"
fi

echo ""
echo "Full output: /tmp/counter_test.txt"

#!/bin/bash
#
# Check Interface and Test Phase 1
#

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}=== Interface Check ===${NC}"
echo ""

echo "All interfaces:"
ip link show
echo ""

echo "Non-loopback interfaces:"
ip -o link show | grep -v "lo:" | awk -F': ' '{print $2}'
echo ""

echo "Interfaces with IP addresses:"
ip -4 addr show | grep -oP '^\d+: \K[^:]+' | grep -v lo
echo ""

# Try common interface names
for iface in ens33 eth0 ens3 enp0s3 enp0s8; do
    if ip link show $iface &>/dev/null; then
        IP=$(ip -4 addr show $iface 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
        echo -e "${GREEN}✓ Found: $iface${NC}"
        if [ -n "$IP" ]; then
            echo "  IP: $IP"
        fi
        FOUND_IFACE=$iface
    fi
done

if [ -z "$FOUND_IFACE" ]; then
    echo -e "${RED}No common interface found${NC}"
    exit 1
fi

echo ""
echo -e "${CYAN}=== Testing Phase 1 with $FOUND_IFACE ===${NC}"
echo ""

cd /home/ubuntu/projects/zkNIDS/phase1/userspace/collector

echo "Running: ./phase1_loader -i $FOUND_IFACE -s 1"
echo ""

timeout 5 ./phase1_loader -i $FOUND_IFACE -s 1 > /tmp/phase1_test_real.txt 2>&1 &
PID=$!

sleep 2
ping -c 3 8.8.8.8 > /dev/null 2>&1
sleep 3

wait $PID 2>/dev/null

echo "Output:"
cat /tmp/phase1_test_real.txt
echo ""

SNAPSHOTS=$(grep -c "^T=" /tmp/phase1_test_real.txt || echo "0")
echo "Snapshots generated: $SNAPSHOTS"

if [ "$SNAPSHOTS" -gt 0 ]; then
    echo -e "${GREEN}✓ Phase 1 is working!${NC}"
    echo ""
    echo "Last snapshot:"
    tail -1 /tmp/phase1_test_real.txt
else
    echo -e "${RED}✗ No snapshots generated${NC}"
    echo ""
    echo "Checking for errors..."
    grep -i "error\|failed\|not found" /tmp/phase1_test_real.txt || echo "No obvious errors"
fi

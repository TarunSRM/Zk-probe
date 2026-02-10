#!/bin/bash
#
# zkNIDS Network Diagnostic - Complete Test
# Tests if XDP is actually seeing network traffic
#

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     zkNIDS Complete Network Diagnostic Test                   ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Must run as root${NC}"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo -e "${CYAN}=== Step 1: System Information ===${NC}"
echo ""

# Get interface info
INTERFACE="ens33"
echo "Interface: $INTERFACE"
echo ""

# Get IP
LOCAL_IP=$(ip -4 addr show $INTERFACE | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
echo "Local IP: $LOCAL_IP"
echo ""

# Get gateway
GATEWAY=$(ip route | grep default | awk '{print $3}')
echo "Gateway: $GATEWAY"
echo ""

echo -e "${CYAN}=== Step 2: Check if XDP is loaded ===${NC}"
echo ""

# Check bpftool
if command -v bpftool &> /dev/null; then
    echo "XDP programs loaded:"
    bpftool net list | grep -A 5 xdp || echo "  No XDP programs found"
else
    echo -e "${YELLOW}bpftool not installed (install: apt install linux-tools-generic)${NC}"
fi
echo ""

echo -e "${CYAN}=== Step 3: Test Phase 1 with Real Traffic ===${NC}"
echo ""

# Start Phase 1
echo "Starting Phase 1..."
cd "$PROJECT_ROOT/phase1/userspace/collector"
./phase1_loader $INTERFACE 1 > /tmp/phase1_test.log 2>&1 &
PHASE1_PID=$!
echo "Phase 1 PID: $PHASE1_PID"
sleep 3

# Generate some traffic
echo ""
echo "Generating test traffic (ping to gateway)..."
ping -c 5 $GATEWAY > /dev/null 2>&1 &

sleep 6

# Stop Phase 1
echo ""
echo "Stopping Phase 1..."
kill $PHASE1_PID 2>/dev/null
sleep 1

# Check output
echo ""
echo -e "${CYAN}=== Phase 1 Output ===${NC}"
echo ""

if [ -f /tmp/phase1_test.log ]; then
    SNAPSHOT_COUNT=$(grep -c "^T=" /tmp/phase1_test.log || echo "0")
    echo "Snapshots generated: $SNAPSHOT_COUNT"
    echo ""
    
    if [ "$SNAPSHOT_COUNT" -gt 0 ]; then
        echo "Sample snapshots:"
        head -3 /tmp/phase1_test.log
        echo ""
        
        # Check if packets were captured
        LAST_SNAPSHOT=$(tail -1 /tmp/phase1_test.log)
        PACKETS=$(echo "$LAST_SNAPSHOT" | grep -oP 'packets=\K\d+')
        
        echo "Last snapshot packet count: $PACKETS"
        
        if [ "$PACKETS" -gt 0 ]; then
            echo -e "${GREEN}✓ XDP IS CAPTURING PACKETS!${NC}"
        else
            echo -e "${RED}✗ XDP NOT capturing packets${NC}"
        fi
    else
        echo -e "${RED}✗ No snapshots generated${NC}"
        echo "Raw output:"
        cat /tmp/phase1_test.log
    fi
else
    echo -e "${RED}✗ No output file${NC}"
fi

echo ""
echo -e "${CYAN}=== Step 4: Test with External Traffic ===${NC}"
echo ""

echo "For this test, you need another machine to attack this one."
echo ""
echo -e "${YELLOW}From another machine, run:${NC}"
echo "  ping -c 10 $LOCAL_IP"
echo ""
read -p "Press Enter after sending pings from another machine..."

# Start Phase 1 again
echo ""
echo "Starting Phase 1 to capture external traffic..."
cd "$PROJECT_ROOT/phase1/userspace/collector"
./phase1_loader $INTERFACE 1 > /tmp/phase1_external.log 2>&1 &
PHASE1_PID=$!
sleep 15

kill $PHASE1_PID 2>/dev/null

echo ""
echo "Checking external traffic capture..."
if [ -f /tmp/phase1_external.log ]; then
    SNAPSHOT_COUNT=$(grep -c "^T=" /tmp/phase1_external.log || echo "0")
    echo "Snapshots: $SNAPSHOT_COUNT"
    
    if [ "$SNAPSHOT_COUNT" -gt 0 ]; then
        LAST_SNAPSHOT=$(tail -1 /tmp/phase1_external.log)
        PACKETS=$(echo "$LAST_SNAPSHOT" | grep -oP 'packets=\K\d+')
        echo "Packets captured: $PACKETS"
        
        if [ "$PACKETS" -gt 5 ]; then
            echo -e "${GREEN}✓ External traffic captured!${NC}"
        else
            echo -e "${YELLOW}⚠ Very few packets captured${NC}"
        fi
    fi
fi

echo ""
echo -e "${CYAN}=== Step 5: Full Pipeline Test ===${NC}"
echo ""

echo "Now testing full pipeline with Phase 2..."
echo ""
echo -e "${YELLOW}From another machine, run these attacks:${NC}"
echo "  1. Packet flood: sudo hping3 -1 --flood -c 5000 $LOCAL_IP"
echo "  2. SYN flood:    sudo hping3 -S -p 80 --flood -c 3000 $LOCAL_IP"
echo ""
read -p "Press Enter when ready to start pipeline..."

# Start full pipeline
cd "$PROJECT_ROOT"
./bin/run-pipeline.sh > /tmp/full_pipeline.log 2>&1 &
PIPELINE_PID=$!

echo "Pipeline started (PID: $PIPELINE_PID)"
echo ""
echo "Waiting 15 seconds for baseline..."
sleep 15

echo ""
echo -e "${GREEN}Ready for attacks! Launch hping3 from other machine now!${NC}"
echo ""
read -p "Press Enter after attacks complete..."

sleep 5

# Stop pipeline
kill $PIPELINE_PID 2>/dev/null
sleep 2
pkill -f phase1_loader 2>/dev/null
pkill -f zkNIDS_phase2 2>/dev/null

echo ""
echo -e "${CYAN}=== Results ===${NC}"
echo ""

if [ -f /tmp/full_pipeline.log ]; then
    ALERT_COUNT=$(grep -c '"alert_id"' /tmp/full_pipeline.log || echo "0")
    
    echo "Total alerts: $ALERT_COUNT"
    
    if [ "$ALERT_COUNT" -gt 0 ]; then
        echo ""
        echo -e "${GREEN}✓ ALERTS GENERATED!${NC}"
        echo ""
        echo "Alert types:"
        grep -o '"id":"[^"]*"' /tmp/full_pipeline.log | sort | uniq -c
        echo ""
        echo "Sample alert:"
        grep '"alert_id"' /tmp/full_pipeline.log | head -1 | jq . 2>/dev/null || grep '"alert_id"' /tmp/full_pipeline.log | head -1
    else
        echo -e "${RED}✗ No alerts generated${NC}"
        echo ""
        echo "Checking if snapshots were processed..."
        SNAPSHOTS=$(grep -oP 'Snapshots processed: \K\d+' /tmp/full_pipeline.log | tail -1)
        echo "Snapshots processed: $SNAPSHOTS"
        
        echo ""
        echo "Last few lines of output:"
        tail -20 /tmp/full_pipeline.log
    fi
else
    echo -e "${RED}✗ No pipeline output${NC}"
fi

echo ""
echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  Diagnostic Complete                                           ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

echo "Output files saved:"
echo "  /tmp/phase1_test.log - Initial Phase 1 test"
echo "  /tmp/phase1_external.log - External traffic test"
echo "  /tmp/full_pipeline.log - Full pipeline with attacks"

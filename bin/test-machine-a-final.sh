#!/bin/bash
#
# Machine A - Improved Test with Proper Output Capture
#

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

clear

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     zkNIDS Network Attack Test (Improved Output Capture)      ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Must run as root${NC}"
    exit 1
fi

# Get IP
IP=$(ip -4 addr show ens33 | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)

if [ -z "$IP" ]; then
    echo -e "${RED}Could not detect IP on ens33${NC}"
    exit 1
fi

echo -e "${GREEN}Your IP: $IP${NC}"
echo ""

cd /home/ubuntu/projects/zkNIDS

# Setup output files
TIMESTAMP=$(date +%s)
ALERTS_FILE="/tmp/alerts_${TIMESTAMP}.jsonl"
SNAPSHOTS_FILE="/tmp/snapshots_${TIMESTAMP}.txt"
SYSTEM_LOG="/tmp/system_${TIMESTAMP}.log"

echo -e "${CYAN}Output files:${NC}"
echo "  Alerts:    $ALERTS_FILE"
echo "  Snapshots: $SNAPSHOTS_FILE"
echo "  System:    $SYSTEM_LOG"
echo ""

# Start Phase 1 separately to capture snapshots
echo -e "${CYAN}Starting Phase 1...${NC}"
./bin/run-phase1.sh 2> >(tee "$SYSTEM_LOG" >&2) > "$SNAPSHOTS_FILE" &
PHASE1_PID=$!
sleep 3

# Start Phase 2 reading from snapshots file
echo -e "${CYAN}Starting Phase 2...${NC}"
tail -f "$SNAPSHOTS_FILE" | ./bin/run-phase2.sh > "$ALERTS_FILE" 2>&1 &
PHASE2_PID=$!
sleep 2

echo -e "${GREEN}Pipeline started${NC}"
echo "  Phase 1 PID: $PHASE1_PID"
echo "  Phase 2 PID: $PHASE2_PID"
echo ""

# Baseline
echo -e "${CYAN}Establishing baseline (15 seconds)...${NC}"
for i in {1..15}; do
    printf "  %2d/15\r" $i
    ping -c 1 -W 1 8.8.8.8 > /dev/null 2>&1
    sleep 1
done
echo ""
echo -e "${GREEN}✓ Baseline established${NC}"
echo ""

# Show baseline snapshots
echo "Baseline snapshots:"
tail -3 "$SNAPSHOTS_FILE"
echo ""

# Ready for attack
echo -e "${YELLOW}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║                READY FOR ATTACKS!                         ║${NC}"
echo -e "${YELLOW}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}On Machine B, run:${NC}"
echo ""
echo "  ./attack-from-machine-b.sh $IP"
echo ""
echo "OR manually:"
echo "  TARGET_IP=\"$IP\""
echo "  for i in {1..10}; do hping3 -1 -i u100 -c 5000 \$TARGET_IP &> /dev/null & done"
echo "  wait && sleep 5"
echo "  for i in {1..10}; do hping3 -S -p 80 -i u100 -c 3000 \$TARGET_IP &> /dev/null & done"
echo "  wait"
echo ""
echo -e "${YELLOW}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

read -p "Press Enter after attacks complete..."

# Wait for processing
echo ""
echo -e "${CYAN}Waiting 10 seconds for final alerts...${NC}"
sleep 10

# Stop pipeline
echo -e "${CYAN}Stopping pipeline...${NC}"
kill $PHASE1_PID $PHASE2_PID 2>/dev/null
sleep 2
pkill -f phase1_loader 2>/dev/null
pkill -f zkNIDS_phase2 2>/dev/null
pkill -f "tail -f" 2>/dev/null

# Analysis
echo ""
echo -e "${CYAN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                    RESULTS ANALYSIS                       ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Count snapshots
SNAP_COUNT=$(grep -c "^T=" "$SNAPSHOTS_FILE" 2>/dev/null || echo "0")
echo "Snapshots captured: $SNAP_COUNT"

if [ "$SNAP_COUNT" -gt 0 ]; then
    echo ""
    echo "Last 5 snapshots:"
    tail -5 "$SNAPSHOTS_FILE"
    echo ""
    
    # Analyze counter changes
    FIRST_PKT=$(head -1 "$SNAPSHOTS_FILE" | grep -oP 'packets=\K\d+' || echo "0")
    LAST_PKT=$(tail -1 "$SNAPSHOTS_FILE" | grep -oP 'packets=\K\d+' || echo "0")
    MAX_PKT=$(grep -oP 'packets=\K\d+' "$SNAPSHOTS_FILE" | sort -n | tail -1)
    
    echo "Packet counter analysis:"
    echo "  First: $FIRST_PKT"
    echo "  Max:   $MAX_PKT"
    echo "  Last:  $LAST_PKT"
    
    if [ "$MAX_PKT" -gt 1000 ]; then
        echo -e "  ${GREEN}✓ Significant traffic captured!${NC}"
    elif [ "$MAX_PKT" -gt 100 ]; then
        echo -e "  ${YELLOW}⚠ Moderate traffic captured${NC}"
    else
        echo -e "  ${RED}✗ Very low traffic${NC}"
    fi
    
    # Check SYN packets
    MAX_SYN=$(grep -oP 'syn=\K\d+' "$SNAPSHOTS_FILE" | sort -n | tail -1)
    echo ""
    echo "SYN packet analysis:"
    echo "  Max SYN: $MAX_SYN"
    
    if [ "$MAX_SYN" -gt 100 ]; then
        echo -e "  ${GREEN}✓ SYN packets detected!${NC}"
    elif [ "$MAX_SYN" -gt 0 ]; then
        echo -e "  ${YELLOW}⚠ Some SYN packets${NC}"
    else
        echo -e "  ${RED}✗ No SYN packets${NC}"
    fi
fi

echo ""
echo "─────────────────────────────────────────────────────────"

# Count alerts
ALERT_COUNT=$(grep -c '"alert_id"' "$ALERTS_FILE" 2>/dev/null || echo "0")
echo ""
echo "Alerts generated: $ALERT_COUNT"

if [ "$ALERT_COUNT" -gt 0 ]; then
    echo ""
    echo -e "${GREEN}✓ SUCCESS - Attacks detected!${NC}"
    echo ""
    
    PACKET_SPIKE=$(grep -c 'packet_rate_spike' "$ALERTS_FILE" || echo "0")
    SYN_FLOOD=$(grep -c 'syn_flood_detection' "$ALERTS_FILE" || echo "0")
    
    echo "Alert breakdown:"
    echo "  • packet_rate_spike:    $PACKET_SPIKE"
    echo "  • syn_flood_detection:  $SYN_FLOOD"
    echo ""
    
    echo "Sample alerts:"
    grep '"alert_id"' "$ALERTS_FILE" | head -3 | jq -r '.invariant.id + ": " + (.observation.observed_value|tostring)' 2>/dev/null || \
    grep '"alert_id"' "$ALERTS_FILE" | head -3
else
    echo ""
    echo -e "${YELLOW}⚠ No alerts generated${NC}"
    echo ""
    echo "Possible reasons:"
    if [ "$MAX_PKT" -lt 100 ]; then
        echo "  - Attacks didn't reach the system"
    else
        echo "  - Thresholds too high (check config)"
        echo "  - Baseline too high"
    fi
fi

echo ""
echo "─────────────────────────────────────────────────────────"
echo "Output files:"
echo "  Alerts:    $ALERTS_FILE"
echo "  Snapshots: $SNAPSHOTS_FILE"
echo "  System:    $SYSTEM_LOG"
echo ""

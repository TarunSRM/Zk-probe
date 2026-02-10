#!/bin/bash
#
# Machine A (Target) - UPDATED Network Attack Test
# Version 2.0 - After Bug Fixes
#

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

clear

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Machine A - Network Attack Test (v2.0 - After Bug Fixes)     ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Must run as root${NC}"
    exit 1
fi

# Check if Phase 1 was rebuilt
echo -e "${CYAN}Checking if Phase 1 was rebuilt with fixes...${NC}"
PHASE1_MTIME=$(stat -c %Y /home/ubuntu/projects/zkNIDS/phase1/userspace/collector/phase1_loader 2>/dev/null || echo "0")
NOW=$(date +%s)
AGE=$((NOW - PHASE1_MTIME))

if [ "$AGE" -gt 3600 ]; then
    echo -e "${YELLOW}⚠ Phase 1 may not have recent bug fixes!${NC}"
    echo ""
    echo "Please rebuild Phase 1 first:"
    echo "  cd /home/ubuntu/projects/zkNIDS/phase1"
    echo "  make clean && make"
    echo ""
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
else
    echo -e "${GREEN}✓ Phase 1 recently built${NC}"
fi
echo ""

# Get IP
IP=$(ip -4 addr show ens33 | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)

if [ -z "$IP" ]; then
    echo -e "${RED}Could not detect IP on ens33${NC}"
    exit 1
fi

echo -e "${GREEN}Your IP: $IP${NC}"
echo ""

# Start pipeline
cd /home/ubuntu/projects/zkNIDS

echo -e "${CYAN}Starting zkNIDS pipeline...${NC}"
RESULT_FILE="/tmp/network_attack_v2_$(date +%s).jsonl"
./bin/run-pipeline.sh > "$RESULT_FILE" 2>&1 &
PID=$!
echo "$PID" > /tmp/pipeline.pid

echo -e "${GREEN}Pipeline started (PID: $PID)${NC}"
echo -e "${YELLOW}Results will be saved to: $RESULT_FILE${NC}"
echo ""

# Wait for Phase 1 to initialize
sleep 3

# Baseline
echo -e "${CYAN}Establishing baseline (15 seconds)...${NC}"
echo "Generating light traffic to establish normal packet rate..."
for i in {1..15}; do
    printf "  %2d/15 - Sending baseline ping...\r" $i
    ping -c 1 -W 1 8.8.8.8 > /dev/null 2>&1
    sleep 1
done
echo ""
echo -e "${GREEN}✓ Baseline established (expect ~2-5 packets/sec)${NC}"
echo ""

# Ready for attack
echo -e "${YELLOW}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║                READY FOR ATTACKS!                         ║${NC}"
echo -e "${YELLOW}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}Target IP: ${GREEN}$IP${NC}"
echo ""
echo -e "${CYAN}On Machine B, run the AGGRESSIVE attack script:${NC}"
echo ""
echo -e "  ${GREEN}./attack-from-machine-b.sh $IP${NC}"
echo ""
echo "This will launch:"
echo "  • ICMP flood:  50,000 packets (parallel)"
echo "  • SYN flood:   30,000 SYN packets (parallel)"
echo "  • Combined:    Both simultaneously"
echo ""
echo -e "${YELLOW}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

read -p "Press Enter after Machine B completes all 3 attacks..."

# Wait for final alerts
echo ""
echo -e "${CYAN}Waiting 10 seconds for final alerts to process...${NC}"
sleep 10

# Stop pipeline
echo -e "${CYAN}Stopping pipeline...${NC}"
kill $PID 2>/dev/null
sleep 2
pkill -f phase1_loader 2>/dev/null
pkill -f zkNIDS_phase2 2>/dev/null

# Analyze results
echo ""
echo -e "${CYAN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                    RESULTS ANALYSIS                       ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

if [ ! -f "$RESULT_FILE" ]; then
    echo -e "${RED}✗ Result file not found!${NC}"
    exit 1
fi

# Count alerts
TOTAL=$(grep -c '"alert_id"' "$RESULT_FILE" 2>/dev/null || echo "0")
PACKET_SPIKE=$(grep -c '"id":"packet_rate_spike"' "$RESULT_FILE" 2>/dev/null || echo "0")
SYN_FLOOD=$(grep -c '"id":"syn_flood_detection"' "$RESULT_FILE" 2>/dev/null || echo "0")
EXECVE=$(grep -c '"id":"execve_rate_high"' "$RESULT_FILE" 2>/dev/null || echo "0")

echo "Alert Summary:"
echo "─────────────────────────────────────"
echo "Total alerts:           $TOTAL"
echo ""
echo "Alert breakdown:"
echo "  • packet_rate_spike:    $PACKET_SPIKE"
echo "  • syn_flood_detection:  $SYN_FLOOD"
echo "  • execve_rate_high:     $EXECVE"
echo ""

# Success criteria
if [ "$TOTAL" -gt 0 ]; then
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║              ✓ SUCCESS - ATTACKS DETECTED!                ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    if [ "$PACKET_SPIKE" -gt 0 ]; then
        echo -e "${GREEN}✓ Packet rate spike detection: WORKING${NC}"
    fi
    
    if [ "$SYN_FLOOD" -gt 0 ]; then
        echo -e "${GREEN}✓ SYN flood detection: WORKING${NC}"
    fi
    
    echo ""
    echo "Sample alerts:"
    echo "─────────────────────────────────────"
    grep '"alert_id"' "$RESULT_FILE" | head -5 | jq -r '.invariant.id + ": " + (.observation.observed_value|tostring) + " (threshold: " + (.observation.threshold|tostring) + ")"' 2>/dev/null || \
    grep '"alert_id"' "$RESULT_FILE" | head -5
else
    echo -e "${YELLOW}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║            ⚠ NO ALERTS GENERATED                          ║${NC}"
    echo -e "${YELLOW}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Diagnostic info
    SNAPSHOTS=$(grep -oP 'Snapshots processed: \K\d+' "$RESULT_FILE" | tail -1)
    echo "Snapshots processed: $SNAPSHOTS"
    echo ""
    
    if [ "$SNAPSHOTS" -gt 0 ]; then
        echo "Checking snapshot data..."
        echo ""
        
        # Look for snapshots in output
        if grep -q "^T=" "$RESULT_FILE"; then
            echo "Sample snapshots (first 3):"
            grep "^T=" "$RESULT_FILE" | head -3
            echo ""
            echo "Sample snapshots (last 3):"
            grep "^T=" "$RESULT_FILE" | tail -3
            echo ""
            
            # Check if counters are changing (verifies map clearing)
            FIRST_PACKETS=$(grep "^T=" "$RESULT_FILE" | head -1 | grep -oP 'packets=\K\d+' || echo "0")
            LAST_PACKETS=$(grep "^T=" "$RESULT_FILE" | tail -1 | grep -oP 'packets=\K\d+' || echo "0")
            
            echo "Counter Analysis:"
            echo "  First snapshot packets: $FIRST_PACKETS"
            echo "  Last snapshot packets:  $LAST_PACKETS"
            
            if [ "$FIRST_PACKETS" = "$LAST_PACKETS" ] && [ "$FIRST_PACKETS" != "0" ]; then
                echo -e "  ${RED}⚠ COUNTERS NOT CHANGING!${NC}"
                echo "  This means map clearing is NOT working."
                echo "  Phase 1 needs to be rebuilt with the fix."
            elif [ "$LAST_PACKETS" = "0" ]; then
                echo -e "  ${YELLOW}⚠ No packets captured!${NC}"
                echo "  Attacks may not have reached this machine."
            else
                echo -e "  ${GREEN}✓ Counters changing correctly${NC}"
                echo "  Issue is likely threshold configuration."
            fi
        else
            echo "No snapshot data found in output."
            echo "Check system logs for errors."
        fi
    else
        echo -e "${RED}Phase 1/Phase 2 pipeline issue - no snapshots processed${NC}"
    fi
fi

echo ""
echo "─────────────────────────────────────"
echo "Full results saved to:"
echo "  $RESULT_FILE"
echo ""
echo "To view alerts:"
echo "  grep alert_id $RESULT_FILE | jq ."
echo ""
echo "To view snapshots:"
echo "  grep '^T=' $RESULT_FILE | tail -20"
echo ""

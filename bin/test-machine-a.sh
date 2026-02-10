#!/bin/bash
#
# Machine A (Target) - Automated Test Script
#

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

clear

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     Machine A (zkNIDS Target) - Network Attack Test           ║${NC}"
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
echo -e "${YELLOW}Tell Machine B to attack: $IP${NC}"
echo ""

# Start pipeline
cd /home/ubuntu/projects/zkNIDS

echo -e "${CYAN}Starting zkNIDS pipeline...${NC}"
./bin/run-pipeline.sh > /tmp/network_attack_$(date +%s).jsonl 2>&1 &
PID=$!
echo "$PID" > /tmp/pipeline.pid

echo -e "${GREEN}Pipeline started (PID: $PID)${NC}"
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

# Ready for attack
echo -e "${YELLOW}═══════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}Ready for attacks!${NC}"
echo ""
echo -e "${CYAN}On Machine B, download and run the attack script:${NC}"
echo ""
echo "  # Download attack-from-machine-b.sh to Machine B"
echo "  chmod +x attack-from-machine-b.sh"
echo "  sudo ./attack-from-machine-b.sh $IP"
echo ""
echo -e "${YELLOW}OR run manually with parallel floods:${NC}"
echo ""
echo "  TARGET_IP=\"$IP\""
echo "  # ICMP flood (10 parallel processes)"
echo "  for i in {1..10}; do hping3 -1 -i u100 -c 5000 \$TARGET_IP &> /dev/null & done"
echo "  wait"
echo "  sleep 5"
echo "  # SYN flood (10 parallel processes)"
echo "  for i in {1..10}; do hping3 -S -p 80 -i u100 -c 3000 \$TARGET_IP &> /dev/null & done"
echo "  wait"
echo ""
echo -e "${YELLOW}═══════════════════════════════════════════════════════${NC}"
echo ""

read -p "Press Enter after Machine B completes both attacks..."

# Wait for alerts
echo ""
echo -e "${CYAN}Waiting 10 seconds for alerts to process...${NC}"
sleep 10

# Stop pipeline
echo -e "${CYAN}Stopping pipeline...${NC}"
kill $PID 2>/dev/null
sleep 2
pkill -f phase1_loader 2>/dev/null
pkill -f zkNIDS_phase2 2>/dev/null

# Analyze results
RESULT_FILE=$(ls -t /tmp/network_attack_*.jsonl | head -1)

echo ""
echo -e "${CYAN}═══ Results ═══${NC}"
echo ""

if [ -f "$RESULT_FILE" ]; then
    TOTAL=$(grep -c '"alert_id"' "$RESULT_FILE" || echo "0")
    PACKET_SPIKE=$(grep -c '"id":"packet_rate_spike"' "$RESULT_FILE" || echo "0")
    SYN_FLOOD=$(grep -c '"id":"syn_flood_detection"' "$RESULT_FILE" || echo "0")
    EXECVE=$(grep -c '"id":"execve_rate_high"' "$RESULT_FILE" || echo "0")
    
    echo "Total alerts: $TOTAL"
    echo ""
    echo "Alert breakdown:"
    echo "  • packet_rate_spike:    $PACKET_SPIKE"
    echo "  • syn_flood_detection:  $SYN_FLOOD"
    echo "  • execve_rate_high:     $EXECVE"
    echo ""
    
    if [ "$TOTAL" -gt 0 ]; then
        echo -e "${GREEN}✓ SUCCESS! Network attacks detected!${NC}"
        echo ""
        echo "Sample alerts:"
        grep '"alert_id"' "$RESULT_FILE" | head -3 | jq -r '.invariant.id + ": " + (.observation.observed_value|tostring)' 2>/dev/null || \
        grep '"alert_id"' "$RESULT_FILE" | head -3
    else
        echo -e "${YELLOW}⚠ No alerts generated${NC}"
        echo ""
        
        # Check snapshots
        SNAPSHOTS=$(grep -oP 'Snapshots processed: \K\d+' "$RESULT_FILE" | tail -1)
        echo "Snapshots processed: $SNAPSHOTS"
        
        if [ "$SNAPSHOTS" -gt 0 ]; then
            echo ""
            echo "Phase 1/Phase 2 are working, but no violations detected."
            echo ""
            echo "Checking if packets were captured..."
            echo ""
            
            # Try to find snapshots in stderr
            if grep -q "^T=" "$RESULT_FILE"; then
                echo "Last snapshots captured:"
                grep "^T=" "$RESULT_FILE" | tail -5
                echo ""
                
                # Parse last snapshot
                LAST=$(grep "^T=" "$RESULT_FILE" | tail -1)
                PACKETS=$(echo "$LAST" | grep -oP 'packets=\K\d+' || echo "0")
                SYN=$(echo "$LAST" | grep -oP 'syn=\K\d+' || echo "0")
                
                echo "Last snapshot stats:"
                echo "  Packets: $PACKETS"
                echo "  SYN:     $SYN"
                echo ""
                
                if [ "$PACKETS" -lt 100 ]; then
                    echo -e "${YELLOW}Very few packets captured!${NC}"
                    echo "Possible issues:"
                    echo "  - hping3 attacks didn't reach this machine"
                    echo "  - Firewall blocking"
                    echo "  - Wrong target IP"
                fi
            fi
        fi
    fi
    
    echo ""
    echo "Full results: $RESULT_FILE"
else
    echo -e "${RED}No result file found!${NC}"
fi

echo ""
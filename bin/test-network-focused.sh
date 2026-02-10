#!/bin/bash
#
# Fixed Network Attack Test - Attacks actual interface (not localhost)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

LOG_DIR="$PROJECT_ROOT/test_results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
ALERT_LOG="$LOG_DIR/alerts_network_fixed_${TIMESTAMP}.jsonl"
SYSTEM_LOG="$LOG_DIR/system_network_fixed_${TIMESTAMP}.log"

mkdir -p "$LOG_DIR"

print_banner() {
    clear
    echo -e "${BLUE}"
    cat << "EOF"
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║     zkNIDS Network Attack Test (FIXED)                        ║
║                                                                ║
║  Attacks actual interface (not localhost)                     ║
║  Target Alerts: packet_rate_spike + syn_flood_detection       ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}\n"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}✗ Must run as root${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Running as root${NC}"
}

get_target_ip() {
    # Get the IP of the interface zkNIDS is monitoring
    echo -e "${CYAN}Detecting target IP address...${NC}"
    
    # Try to get IP from common interfaces
    TARGET_IP=$(ip -4 addr show ens33 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
    
    if [ -z "$TARGET_IP" ]; then
        TARGET_IP=$(ip -4 addr show eth0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
    fi
    
    if [ -z "$TARGET_IP" ]; then
        # Fallback: get first non-loopback IP
        TARGET_IP=$(ip -4 addr | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v "127.0.0.1" | head -1)
    fi
    
    if [ -z "$TARGET_IP" ]; then
        echo -e "${RED}✗ Could not detect IP address${NC}"
        echo "Please specify manually:"
        read -p "Enter target IP: " TARGET_IP
    fi
    
    echo -e "${GREEN}✓ Target IP: $TARGET_IP${NC}"
    echo ""
}

check_hping3() {
    if command -v hping3 &> /dev/null; then
        echo -e "${GREEN}✓ hping3 installed${NC}"
        return 0
    else
        echo -e "${RED}✗ hping3 not installed${NC}"
        echo "Install with: sudo apt install hping3"
        exit 1
    fi
}

start_pipeline() {
    echo -e "\n${CYAN}Starting zkNIDS pipeline...${NC}"
    
    "$SCRIPT_DIR/run-pipeline.sh" > >(tee "$ALERT_LOG") 2> >(tee "$SYSTEM_LOG" >&2) &
    PIPELINE_PID=$!
    
    echo -e "${GREEN}✓ Pipeline started (PID: $PIPELINE_PID)${NC}"
    echo -e "${YELLOW}  📁 Alerts: $ALERT_LOG${NC}"
    echo -e "${YELLOW}  📁 Logs:   $SYSTEM_LOG${NC}"
    
    sleep 5
}

stop_pipeline() {
    echo -e "\n${CYAN}Stopping pipeline...${NC}"
    
    if [ -n "$PIPELINE_PID" ]; then
        kill $PIPELINE_PID 2>/dev/null || true
        sleep 2
        kill -9 $PIPELINE_PID 2>/dev/null || true
    fi
    
    pkill -f "phase1_loader" 2>/dev/null || true
    pkill -f "zkNIDS_phase2" 2>/dev/null || true
    
    echo -e "${GREEN}✓ Pipeline stopped${NC}"
}

establish_baseline() {
    echo -e "\n${CYAN}━━━ Establishing Baseline (10 seconds) ━━━${NC}\n"
    echo "Creating light traffic to $TARGET_IP..."
    
    # Light traffic for 10 seconds
    for i in {1..10}; do
        # Send a few pings
        ping -c 2 -W 1 $TARGET_IP > /dev/null 2>&1 &
        
        sleep 1
        echo "  Baseline second $i/10..."
    done
    
    wait
    
    echo -e "${GREEN}✓ Baseline established${NC}"
    echo "  Expected baseline: ~3-6 packets/sec"
    sleep 2
}

test_packet_flood() {
    echo -e "\n${CYAN}━━━ Test 1: Packet Rate Spike ━━━${NC}\n"
    
    echo -e "${GREEN}Using hping3 ICMP flood...${NC}"
    echo ""
    echo "Configuration:"
    echo "  • Target: $TARGET_IP (actual interface)"
    echo "  • Packet type: ICMP (ping)"
    echo "  • Mode: FLOOD (maximum speed)"
    echo "  • Duration: 5 seconds"
    echo "  • Expected: 5,000-10,000 packets/sec"
    echo ""
    
    read -p "Press Enter to launch packet flood..."
    
    echo -e "${YELLOW}Launching ICMP flood to $TARGET_IP...${NC}"
    
    # Flood for 5 seconds
    timeout 5 hping3 -1 --flood $TARGET_IP > /dev/null 2>&1 || true
    
    echo -e "${GREEN}✓ Packet flood completed${NC}"
    echo -e "${GREEN}✓ EXPECTED ALERT: packet_rate_spike${NC}"
    
    sleep 3
}

test_syn_flood() {
    echo -e "\n${CYAN}━━━ Test 2: SYN Flood Attack ━━━${NC}\n"
    
    echo -e "${GREEN}Using hping3 SYN flood...${NC}"
    echo ""
    echo "Configuration:"
    echo "  • Target: $TARGET_IP:80"
    echo "  • Packet type: TCP SYN"
    echo "  • Mode: FLOOD (maximum speed)"
    echo "  • Duration: 5 seconds"
    echo "  • Expected SYN ratio: >90%"
    echo ""
    
    read -p "Press Enter to launch SYN flood..."
    
    echo -e "${YELLOW}Launching SYN flood to $TARGET_IP:80...${NC}"
    
    # SYN flood for 5 seconds
    timeout 5 hping3 -S -p 80 --flood $TARGET_IP > /dev/null 2>&1 || true
    
    echo -e "${GREEN}✓ SYN flood completed${NC}"
    echo -e "${GREEN}✓ EXPECTED ALERT: syn_flood_detection${NC}"
    
    sleep 3
}

test_combined() {
    echo -e "\n${CYAN}━━━ Test 3: Combined Attack ━━━${NC}\n"
    echo "Launching ICMP flood AND SYN flood simultaneously to $TARGET_IP..."
    echo ""
    
    # Launch both in background
    (timeout 3 hping3 -1 --flood $TARGET_IP > /dev/null 2>&1 || true) &
    FLOOD1_PID=$!
    
    (timeout 3 hping3 -S -p 80 --flood $TARGET_IP > /dev/null 2>&1 || true) &
    FLOOD2_PID=$!
    
    echo "  → ICMP flood running (PID: $FLOOD1_PID)"
    echo "  → SYN flood running (PID: $FLOOD2_PID)"
    
    # Wait for both
    wait $FLOOD1_PID 2>/dev/null || true
    wait $FLOOD2_PID 2>/dev/null || true
    
    echo -e "${GREEN}✓ Combined attack completed${NC}"
    echo -e "${GREEN}✓ EXPECTED: Both packet_rate_spike AND syn_flood_detection${NC}"
    
    sleep 3
}

analyze_results() {
    echo -e "\n${CYAN}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  Analyzing Network Attack Results                     ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════╝${NC}\n"
    
    if [ ! -f "$ALERT_LOG" ]; then
        echo -e "${RED}✗ No alert log found${NC}"
        return 1
    fi
    
    # Count alerts
    TOTAL_ALERTS=$(grep -c "alert_id" "$ALERT_LOG" 2>/dev/null || echo "0")
    PACKET_SPIKE=$(grep -c "packet_rate_spike" "$ALERT_LOG" 2>/dev/null || echo "0")
    SYN_FLOOD=$(grep -c "syn_flood_detection" "$ALERT_LOG" 2>/dev/null || echo "0")
    EXECVE_ALERTS=$(grep -c "execve_rate_high" "$ALERT_LOG" 2>/dev/null || echo "0")
    
    echo -e "${GREEN}═══ Network Test Results ═══${NC}\n"
    echo "Total Alerts: $TOTAL_ALERTS"
    echo ""
    echo "Alert Breakdown:"
    echo "  • packet_rate_spike:    $PACKET_SPIKE 🎯"
    echo "  • syn_flood_detection:  $SYN_FLOOD 🎯"
    echo "  • execve_rate_high:     $EXECVE_ALERTS"
    echo ""
    
    # Show target alerts
    if [ "$PACKET_SPIKE" -gt 0 ]; then
        echo -e "${GREEN}✓ packet_rate_spike DETECTED!${NC}"
        grep "packet_rate_spike" "$ALERT_LOG" 2>/dev/null | head -1 | jq -r '"  Rate: " + (.observation.observed_value|tostring) + " packets/sec"' 2>/dev/null || echo "  (Check log for details)"
    else
        echo -e "${RED}✗ packet_rate_spike NOT detected${NC}"
    fi
    echo ""
    
    if [ "$SYN_FLOOD" -gt 0 ]; then
        echo -e "${GREEN}✓ syn_flood_detection DETECTED!${NC}"
        grep "syn_flood_detection" "$ALERT_LOG" 2>/dev/null | head -1 | jq -r '"  SYN Ratio: " + ((.observation.observed_value * 100)|tostring) + "%"' 2>/dev/null || echo "  (Check log for details)"
    else
        echo -e "${RED}✗ syn_flood_detection NOT detected${NC}"
    fi
    echo ""
    
    echo -e "${YELLOW}📁 Full Results:${NC}"
    echo "  Alerts: $ALERT_LOG"
    echo "  System: $SYSTEM_LOG"
    echo ""
    
    # Success criteria
    if [ "$PACKET_SPIKE" -gt 0 ] && [ "$SYN_FLOOD" -gt 0 ]; then
        echo -e "${GREEN}╔════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║     ✓ COMPLETE SUCCESS - ALL ALERTS DETECTED      ║${NC}"
        echo -e "${GREEN}╚════════════════════════════════════════════════════╝${NC}"
        return 0
    elif [ "$PACKET_SPIKE" -gt 0 ] || [ "$SYN_FLOOD" -gt 0 ]; then
        echo -e "${YELLOW}╔════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}║     ✓ PARTIAL SUCCESS - SOME ALERTS DETECTED      ║${NC}"
        echo -e "${YELLOW}╚════════════════════════════════════════════════════╝${NC}"
        return 0
    else
        echo -e "${RED}╔════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║     ✗ NO TARGET ALERTS - Check if packets reached ║${NC}"
        echo -e "${RED}╚════════════════════════════════════════════════════╝${NC}"
        
        echo ""
        echo "Debug suggestions:"
        echo "  1. Check if packets were captured: tcpdump -i ens33 -c 10"
        echo "  2. View system log: cat $SYSTEM_LOG"
        echo "  3. Verify XDP is attached: sudo bpftool net list"
        
        return 1
    fi
}

# Main execution
main() {
    print_banner
    check_root
    check_hping3
    get_target_ip
    
    # Trap Ctrl+C
    trap 'stop_pipeline; echo "Test interrupted"; exit 1' INT TERM
    
    echo ""
    echo -e "${CYAN}This test will attack: $TARGET_IP${NC}"
    echo -e "${YELLOW}(This is YOUR machine's IP on the monitored interface)${NC}"
    echo ""
    
    read -p "Press Enter to begin network attack tests..."
    
    # Start pipeline
    start_pipeline
    
    # Run tests
    establish_baseline
    test_packet_flood
    test_syn_flood
    test_combined
    
    # Wait for final alerts
    echo -e "\n${YELLOW}Waiting 10 seconds for final alerts to process...${NC}"
    sleep 10
    
    # Stop pipeline
    stop_pipeline
    
    # Analyze
    analyze_results
    RESULT=$?
    
    exit $RESULT
}

main "$@"

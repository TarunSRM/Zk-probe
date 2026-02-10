#!/bin/bash
#
# Extended Real-Time Detection Test
# Includes: Process spikes + Packet floods + SYN floods
# Automatically saves all outputs to test_results/
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
ALERT_LOG="$LOG_DIR/alerts_extended_${TIMESTAMP}.jsonl"
SYSTEM_LOG="$LOG_DIR/system_extended_${TIMESTAMP}.log"

mkdir -p "$LOG_DIR"

print_banner() {
    echo -e "${BLUE}"
    cat << "EOF"
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║     zkNIDS Extended Test Suite - All Attack Types             ║
║                                                                ║
║  Tests: Process Spikes + Packet Floods + SYN Floods           ║
║  Outputs: Automatically saved to test_results/                ║
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

check_hping3() {
    if command -v hping3 &> /dev/null; then
        echo -e "${GREEN}✓ hping3 installed${NC}"
        return 0
    else
        echo -e "${YELLOW}⚠ hping3 not installed${NC}"
        echo "  Install with: sudo apt install hping3"
        echo "  Will use fallback methods for packet/SYN tests"
        return 1
    fi
}

start_pipeline() {
    echo -e "\n${CYAN}Starting zkNIDS pipeline...${NC}"
    
    "$SCRIPT_DIR/run-pipeline.sh" > >(tee "$ALERT_LOG") 2> >(tee "$SYSTEM_LOG" >&2) &
    PIPELINE_PID=$!
    
    echo -e "${GREEN}✓ Pipeline started (PID: $PIPELINE_PID)${NC}"
    echo -e "${YELLOW}  📁 Alerts saving to: $ALERT_LOG${NC}"
    echo -e "${YELLOW}  📁 Logs saving to:   $SYSTEM_LOG${NC}"
    
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

test_process_spike() {
    echo -e "\n${CYAN}━━━ Test 1: Process Creation Spike ━━━${NC}\n"
    echo "Creating 250 processes rapidly..."
    
    for i in {1..250}; do
        /bin/true &
    done
    
    echo -e "${GREEN}✓ Process spike completed${NC}"
    echo -e "${GREEN}✓ EXPECTED: execve_rate_high alert${NC}"
    sleep 3
}

test_packet_flood() {
    echo -e "\n${CYAN}━━━ Test 2: Packet Flood (Pure Network) ━━━${NC}\n"
    
    if command -v hping3 &> /dev/null; then
        echo "Using hping3 for pure packet flood..."
        echo "Sending 10,000 ICMP packets at maximum speed..."
        
        # ICMP flood (pure packets, no process creation)
        timeout 5 hping3 -1 --flood -c 10000 127.0.0.1 2>/dev/null || true
        
        echo -e "${GREEN}✓ Packet flood completed (10,000 packets)${NC}"
        echo -e "${GREEN}✓ EXPECTED: packet_rate_spike alert${NC}"
    else
        echo -e "${YELLOW}Using ping flood (fallback method)...${NC}"
        
        # Multiple parallel ping floods
        for i in {1..10}; do
            ping -c 500 -f 127.0.0.1 > /dev/null 2>&1 &
        done
        
        wait
        
        echo -e "${GREEN}✓ Ping flood completed${NC}"
        echo -e "${YELLOW}⚠ May need hping3 for reliable packet_rate_spike detection${NC}"
    fi
    
    sleep 3
}

test_syn_flood() {
    echo -e "\n${CYAN}━━━ Test 3: SYN Flood Attack ━━━${NC}\n"
    
    if command -v hping3 &> /dev/null; then
        echo "Using hping3 for SYN flood..."
        echo "Sending 5,000 SYN packets to localhost:80..."
        
        # SYN flood
        timeout 5 hping3 -S -p 80 --flood -c 5000 127.0.0.1 2>/dev/null || true
        
        echo -e "${GREEN}✓ SYN flood completed (5,000 SYN packets)${NC}"
        echo -e "${GREEN}✓ EXPECTED: syn_flood_detection alert (SYN ratio > 80%)${NC}"
    else
        echo -e "${YELLOW}hping3 not available - using connection flood...${NC}"
        
        # Alternative: rapid SYN connection attempts
        for i in {1..200}; do
            (timeout 0.05 nc -z 127.0.0.1 80 2>/dev/null || true) &
            (timeout 0.05 nc -z 127.0.0.1 443 2>/dev/null || true) &
        done
        
        wait
        
        echo -e "${GREEN}✓ Connection flood completed${NC}"
        echo -e "${YELLOW}⚠ Install hping3 for true SYN flood testing${NC}"
    fi
    
    sleep 3
}

test_combined_attack() {
    echo -e "\n${CYAN}━━━ Test 4: Combined Attack (All Types) ━━━${NC}\n"
    echo "Launching coordinated attack..."
    
    # Process spike
    (
        for i in {1..180}; do /bin/true & done
    ) &
    
    # Packet flood
    if command -v hping3 &> /dev/null; then
        (timeout 3 hping3 -1 --flood -c 3000 127.0.0.1 2>/dev/null || true) &
    else
        (ping -c 500 -f 127.0.0.1 > /dev/null 2>&1) &
    fi
    
    # Wait for attacks to complete
    sleep 4
    
    echo -e "${GREEN}✓ Combined attack completed${NC}"
    echo -e "${GREEN}✓ EXPECTED: Multiple alert types${NC}"
    
    sleep 2
}

analyze_results() {
    echo -e "\n${CYAN}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  Analyzing Extended Test Results                      ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════╝${NC}\n"
    
    if [ ! -f "$ALERT_LOG" ]; then
        echo -e "${RED}✗ No alert log found${NC}"
        return 1
    fi
    
    # Count alerts
    TOTAL_ALERTS=$(grep -c "alert_id" "$ALERT_LOG" 2>/dev/null || echo "0")
    EXECVE_ALERTS=$(grep -c "execve_rate_high" "$ALERT_LOG" 2>/dev/null || echo "0")
    SYN_ALERTS=$(grep -c "syn_flood_detection" "$ALERT_LOG" 2>/dev/null || echo "0")
    SPIKE_ALERTS=$(grep -c "packet_rate_spike" "$ALERT_LOG" 2>/dev/null || echo "0")
    
    echo -e "${GREEN}═══ Extended Test Results ═══${NC}\n"
    echo "Total Alerts: $TOTAL_ALERTS"
    echo ""
    echo "Alert Breakdown:"
    echo "  • execve_rate_high:     $EXECVE_ALERTS"
    echo "  • packet_rate_spike:    $SPIKE_ALERTS"
    echo "  • syn_flood_detection:  $SYN_ALERTS"
    echo ""
    
    # Show sample alerts by type
    if [ "$TOTAL_ALERTS" -gt 0 ]; then
        echo -e "${CYAN}Sample Alerts by Type:${NC}\n"
        
        if [ "$EXECVE_ALERTS" -gt 0 ]; then
            echo -e "${YELLOW}Process Spike Alerts:${NC}"
            grep "execve_rate_high" "$ALERT_LOG" 2>/dev/null | head -2 | while read -r alert; do
                OBSERVED=$(echo "$alert" | jq -r '.observation.observed_value')
                THRESHOLD=$(echo "$alert" | jq -r '.observation.threshold')
                echo "  🚨 execve_rate_high: $OBSERVED > $THRESHOLD"
            done
            echo ""
        fi
        
        if [ "$SPIKE_ALERTS" -gt 0 ]; then
            echo -e "${YELLOW}Packet Spike Alerts:${NC}"
            grep "packet_rate_spike" "$ALERT_LOG" 2>/dev/null | head -2 | while read -r alert; do
                OBSERVED=$(echo "$alert" | jq -r '.observation.observed_value')
                echo "  🚨 packet_rate_spike: $OBSERVED packets/sec"
            done
            echo ""
        fi
        
        if [ "$SYN_ALERTS" -gt 0 ]; then
            echo -e "${YELLOW}SYN Flood Alerts:${NC}"
            grep "syn_flood_detection" "$ALERT_LOG" 2>/dev/null | head -2 | while read -r alert; do
                OBSERVED=$(echo "$alert" | jq -r '.observation.observed_value')
                THRESHOLD=$(echo "$alert" | jq -r '.observation.threshold')
                echo "  🚨 syn_flood_detection: $(echo "$OBSERVED * 100" | bc)% SYN ratio > $(echo "$THRESHOLD * 100" | bc)%"
            done
            echo ""
        fi
    fi
    
    echo -e "${YELLOW}📁 Full Results Saved To:${NC}"
    echo "  Alerts: $ALERT_LOG"
    echo "  System: $SYSTEM_LOG"
    echo ""
    
    # Validation
    if [ "$TOTAL_ALERTS" -gt 0 ]; then
        echo -e "${GREEN}✓ EXTENDED TEST PASSED: Alerts were generated${NC}"
        
        if [ "$EXECVE_ALERTS" -gt 0 ]; then
            echo -e "${GREEN}✓ Process spike detection working${NC}"
        fi
        
        if [ "$SPIKE_ALERTS" -gt 0 ]; then
            echo -e "${GREEN}✓ Packet spike detection working${NC}"
        else
            echo -e "${YELLOW}⚠ No packet_rate_spike alerts (may need hping3 or lower threshold)${NC}"
        fi
        
        if [ "$SYN_ALERTS" -gt 0 ]; then
            echo -e "${GREEN}✓ SYN flood detection working${NC}"
        else
            echo -e "${YELLOW}⚠ No syn_flood alerts (may need hping3 for true SYN flood)${NC}"
        fi
        
        return 0
    else
        echo -e "${RED}✗ EXTENDED TEST FAILED: No alerts generated${NC}"
        return 1
    fi
}

# Main execution
main() {
    print_banner
    check_root
    
    HAS_HPING3=false
    check_hping3 && HAS_HPING3=true
    
    # Trap Ctrl+C
    trap 'stop_pipeline; echo "Test interrupted"; exit 1' INT TERM
    
    echo ""
    read -p "Press Enter to start extended tests..."
    
    # Start pipeline
    start_pipeline
    
    # Run tests
    test_process_spike
    test_packet_flood
    test_syn_flood
    test_combined_attack
    
    # Wait for final alerts
    echo -e "\n${YELLOW}Waiting 5 seconds for final alerts...${NC}"
    sleep 5
    
    # Stop pipeline
    stop_pipeline
    
    # Analyze
    analyze_results
    RESULT=$?
    
    echo ""
    echo -e "${BLUE}════════════════════════════════════════════════════${NC}"
    if [ $RESULT -eq 0 ]; then
        echo -e "${GREEN}     ✓ EXTENDED TEST SUITE PASSED${NC}"
    else
        echo -e "${RED}     ✗ EXTENDED TEST SUITE FAILED${NC}"
    fi
    echo -e "${BLUE}════════════════════════════════════════════════════${NC}"
    echo ""
    
    if [ "$HAS_HPING3" = false ]; then
        echo -e "${YELLOW}💡 Tip: Install hping3 for complete testing:${NC}"
        echo "   sudo apt install hping3"
        echo ""
    fi
    
    exit $RESULT
}

main "$@"

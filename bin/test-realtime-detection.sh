#!/bin/bash
#
# Real-Time Detection Test Orchestrator
# Runs zkNIDS pipeline and generates traffic in parallel
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
ALERT_LOG="$LOG_DIR/alerts_${TIMESTAMP}.jsonl"
SYSTEM_LOG="$LOG_DIR/system_${TIMESTAMP}.log"

mkdir -p "$LOG_DIR"

print_banner() {
    clear
    echo -e "${BLUE}"
    cat << "EOF"
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║        zkNIDS Real-Time Detection Test Suite v1.0             ║
║                                                                ║
║  Tests the complete Phase 1 → Phase 2 pipeline with           ║
║  simulated attacks and real-time traffic generation           ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

check_prerequisites() {
    echo -e "${CYAN}Checking prerequisites...${NC}"
    
    # Check root
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}✗ Must run as root (required for Phase 1 eBPF)${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Running as root${NC}"
    
    # Check Phase 1 built
    if [ ! -f "$PROJECT_ROOT/phase1/userspace/collector/phase1_loader" ]; then
        echo -e "${RED}✗ Phase 1 not built${NC}"
        echo "  Run: cd $PROJECT_ROOT/phase1 && make"
        exit 1
    fi
    echo -e "${GREEN}✓ Phase 1 built${NC}"
    
    # Check Phase 2 installed
    if ! python3 -c "import zkNIDS_phase2" 2>/dev/null; then
        echo -e "${RED}✗ Phase 2 not installed${NC}"
        echo "  Run: cd $PROJECT_ROOT/phase2 && pip install -e ."
        exit 1
    fi
    echo -e "${GREEN}✓ Phase 2 installed${NC}"
    
    echo ""
}

start_pipeline() {
    echo -e "${CYAN}Starting zkNIDS pipeline...${NC}"
    
    # Start pipeline in background, capture both stdout (alerts) and stderr (system logs)
    "$SCRIPT_DIR/run-pipeline.sh" > >(tee "$ALERT_LOG") 2> >(tee "$SYSTEM_LOG" >&2) &
    PIPELINE_PID=$!
    
    echo -e "${GREEN}✓ Pipeline started (PID: $PIPELINE_PID)${NC}"
    echo -e "${YELLOW}  Alerts: $ALERT_LOG${NC}"
    echo -e "${YELLOW}  Logs: $SYSTEM_LOG${NC}"
    
    # Give it time to initialize
    sleep 3
}

stop_pipeline() {
    echo -e "\n${CYAN}Stopping pipeline...${NC}"
    
    if [ -n "$PIPELINE_PID" ]; then
        kill $PIPELINE_PID 2>/dev/null || true
        sleep 2
        kill -9 $PIPELINE_PID 2>/dev/null || true
    fi
    
    # Cleanup any orphaned processes
    pkill -f "phase1_loader" 2>/dev/null || true
    pkill -f "zkNIDS_phase2" 2>/dev/null || true
    
    echo -e "${GREEN}✓ Pipeline stopped${NC}"
}

run_traffic_tests() {
    echo -e "\n${CYAN}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  Starting Traffic Generation Tests                    ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════╝${NC}\n"
    
    sleep 2
    
    # Run traffic generator
    if [ -f "$SCRIPT_DIR/test-realtime-traffic.sh" ]; then
        bash "$SCRIPT_DIR/test-realtime-traffic.sh"
    else
        echo -e "${YELLOW}⚠ Traffic generator script not found${NC}"
        echo "  Generating basic test traffic..."
        
        # Basic tests
        echo "Test 1: Process spike..."
        for i in {1..150}; do /bin/true & done
        sleep 2
        
        echo "Test 2: Sustained load..."
        for round in {1..3}; do
            for i in {1..120}; do /bin/true & done
            sleep 1
        done
    fi
}

analyze_results() {
    echo -e "\n${CYAN}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  Analyzing Results                                     ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════╝${NC}\n"
    
    if [ ! -f "$ALERT_LOG" ]; then
        echo -e "${RED}✗ No alert log found${NC}"
        return
    fi
    
    # Count alerts
    TOTAL_ALERTS=$(grep -c "alert_id" "$ALERT_LOG" 2>/dev/null || echo "0")
    EXECVE_ALERTS=$(grep -c "execve_rate_high" "$ALERT_LOG" 2>/dev/null || echo "0")
    SYN_ALERTS=$(grep -c "syn_flood_detection" "$ALERT_LOG" 2>/dev/null || echo "0")
    SPIKE_ALERTS=$(grep -c "packet_rate_spike" "$ALERT_LOG" 2>/dev/null || echo "0")
    
    # Extract unique alert types
    echo -e "${GREEN}═══ Test Results ═══${NC}\n"
    echo "Total Alerts: $TOTAL_ALERTS"
    echo ""
    echo "Alert Breakdown:"
    echo "  • execve_rate_high:     $EXECVE_ALERTS"
    echo "  • syn_flood_detection:  $SYN_ALERTS"
    echo "  • packet_rate_spike:    $SPIKE_ALERTS"
    echo ""
    
    # Show sample alerts
    if [ "$TOTAL_ALERTS" -gt 0 ]; then
        echo -e "${CYAN}Sample Alerts:${NC}"
        grep "alert_id" "$ALERT_LOG" 2>/dev/null | head -3 | while read -r alert; do
            INVARIANT=$(echo "$alert" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
            OBSERVED=$(echo "$alert" | grep -o '"observed_value":[^,]*' | cut -d':' -f2)
            THRESHOLD=$(echo "$alert" | grep -o '"threshold":[^,]*' | cut -d':' -f2)
            echo "  🚨 $INVARIANT: $OBSERVED > $THRESHOLD"
        done
    fi
    
    echo ""
    echo -e "${YELLOW}Full results saved to:${NC}"
    echo "  Alerts: $ALERT_LOG"
    echo "  System: $SYSTEM_LOG"
    echo ""
    
    # Validation
    if [ "$TOTAL_ALERTS" -gt 0 ]; then
        echo -e "${GREEN}✓ TEST PASSED: Alerts were generated${NC}"
        
        if [ "$EXECVE_ALERTS" -gt 0 ]; then
            echo -e "${GREEN}✓ Process spike detection working${NC}"
        fi
        
        return 0
    else
        echo -e "${RED}✗ TEST FAILED: No alerts generated${NC}"
        echo "  This could mean:"
        echo "  - Traffic generation was insufficient"
        echo "  - Detection thresholds are too high"
        echo "  - Pipeline is not working correctly"
        return 1
    fi
}

show_live_monitoring() {
    echo -e "\n${CYAN}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  Live Monitoring Instructions                          ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════╝${NC}\n"
    
    echo "To monitor alerts in real-time, open another terminal and run:"
    echo ""
    echo -e "${YELLOW}  tail -f $ALERT_LOG | jq .${NC}"
    echo ""
    echo "Or for a simpler view:"
    echo ""
    echo -e "${YELLOW}  tail -f $ALERT_LOG | grep -o '\"id\":\"[^\"]*\"' ${NC}"
    echo ""
    echo "Press Enter to continue..."
    read
}

# Main execution
main() {
    print_banner
    check_prerequisites
    
    # Trap Ctrl+C
    trap 'stop_pipeline; echo "Test interrupted"; exit 1' INT TERM
    
    # Show monitoring instructions
    show_live_monitoring
    
    # Start the pipeline
    start_pipeline
    
    # Wait for Phase 1 to start collecting
    echo -e "${YELLOW}Waiting 5 seconds for Phase 1 to initialize...${NC}"
    sleep 5
    
    # Run traffic tests
    run_traffic_tests
    
    # Let alerts settle
    echo -e "\n${YELLOW}Waiting 5 seconds for final alerts...${NC}"
    sleep 5
    
    # Stop pipeline
    stop_pipeline
    
    # Analyze results
    analyze_results
    
    RESULT=$?
    
    echo ""
    echo -e "${BLUE}════════════════════════════════════════════════════${NC}"
    if [ $RESULT -eq 0 ]; then
        echo -e "${GREEN}        ✓ REAL-TIME DETECTION TEST PASSED${NC}"
    else
        echo -e "${RED}        ✗ REAL-TIME DETECTION TEST FAILED${NC}"
    fi
    echo -e "${BLUE}════════════════════════════════════════════════════${NC}"
    echo ""
    
    exit $RESULT
}

main "$@"

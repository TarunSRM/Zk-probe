#!/bin/bash
#
# Real-Time Traffic Generator for zkNIDS Testing
# Generates various types of network and process activity to test detection
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
DURATION=${TEST_DURATION:-60}  # Default 60 seconds
INTERFACE=${INTERFACE:-}

print_banner() {
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║          zkNIDS Real-Time Traffic Test Suite              ║${NC}"
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo ""
}

print_section() {
    echo -e "\n${CYAN}━━━ $1 ━━━${NC}\n"
}

print_test() {
    echo -e "${YELLOW}▶ $1${NC}"
}

print_result() {
    if [ "$1" = "success" ]; then
        echo -e "${GREEN}✓ $2${NC}"
    else
        echo -e "${RED}✗ $2${NC}"
    fi
}

# Check dependencies
check_dependencies() {
    local missing=0
    
    echo "Checking dependencies..."
    
    if ! command -v nc &> /dev/null; then
        echo -e "${YELLOW}  ⚠ netcat (nc) not found - network tests will be limited${NC}"
    fi
    
    if ! command -v ping &> /dev/null; then
        echo -e "${RED}  ✗ ping not found${NC}"
        missing=1
    fi
    
    if [ $missing -eq 1 ]; then
        echo -e "${RED}Please install missing dependencies${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✓ Dependencies OK${NC}"
}

# Test 1: Normal baseline traffic
test_normal_traffic() {
    print_section "Test 1: Normal Baseline Traffic"
    print_test "Generating normal process and network activity (30s)..."
    
    # Light process creation (5-10 per second)
    for i in {1..300}; do
        /bin/true &
        sleep 0.1
    done
    
    # Light network traffic (pings)
    ping -c 10 -i 0.2 127.0.0.1 > /dev/null 2>&1 &
    
    print_result success "Normal traffic generated (should NOT trigger alerts)"
    sleep 2
}

# Test 2: Process creation spike (execve attack)
test_execve_spike() {
    print_section "Test 2: Process Creation Spike Attack"
    print_test "Simulating rapid process creation (fork bomb)..."
    
    echo -e "${YELLOW}  → Creating 200 processes in 1 second (200/sec >> 100/sec threshold)${NC}"
    
    # Rapid process creation - should trigger execve_rate_high alert
    for i in {1..200}; do
        /bin/true &
    done
    
    print_result success "Process spike generated"
    echo -e "${GREEN}  ✓ EXPECTED ALERT: execve_rate_high (200 > 100/sec)${NC}"
    
    # Let the system process
    sleep 3
    
    # Cleanup background processes
    jobs -p | xargs -r kill 2>/dev/null || true
}

# Test 3: Sustained process creation
test_sustained_load() {
    print_section "Test 3: Sustained High Process Creation"
    print_test "Maintaining high process rate for 5 seconds..."
    
    # Sustained load at threshold
    for round in {1..5}; do
        echo "  Round $round/5: Creating 120 processes..."
        for i in {1..120}; do
            /bin/true &
        done
        sleep 1
    done
    
    print_result success "Sustained load completed"
    echo -e "${GREEN}  ✓ EXPECTED: Multiple execve_rate_high alerts${NC}"
    
    sleep 2
}

# Test 4: Network traffic spike
test_network_spike() {
    print_section "Test 4: Network Traffic Spike"
    print_test "Generating rapid network connections..."
    
    # Create many connections to localhost
    echo -e "${YELLOW}  → Opening 50 rapid connections${NC}"
    
    for i in {1..50}; do
        # Try to connect to common ports (connection attempts generate packets)
        (timeout 0.1 nc -z 127.0.0.1 80 2>/dev/null || true) &
        (timeout 0.1 nc -z 127.0.0.1 443 2>/dev/null || true) &
    done
    
    # Rapid pings
    ping -c 100 -f 127.0.0.1 > /dev/null 2>&1 &
    
    print_result success "Network spike generated"
    echo -e "${GREEN}  ✓ EXPECTED: Possible packet_rate_spike alert${NC}"
    
    sleep 3
    
    # Cleanup
    killall ping 2>/dev/null || true
}

# Test 5: Combined attack
test_combined_attack() {
    print_section "Test 5: Combined Attack (Process + Network)"
    print_test "Simulating coordinated attack..."
    
    echo -e "${YELLOW}  → Launching process spike + network flood${NC}"
    
    # Process spike
    (
        for i in {1..150}; do
            /bin/true &
        done
    ) &
    
    # Network flood
    (
        ping -c 200 -f 127.0.0.1 > /dev/null 2>&1
    ) &
    
    sleep 2
    
    print_result success "Combined attack completed"
    echo -e "${GREEN}  ✓ EXPECTED: Multiple alerts (execve_rate_high + packet_rate_spike)${NC}"
    
    sleep 2
}

# Test 6: Gradual ramp-up
test_gradual_rampup() {
    print_section "Test 6: Gradual Load Increase"
    print_test "Slowly increasing load to test baseline adaptation..."
    
    for rate in 20 40 60 80 100 120 140; do
        echo "  Creating $rate processes..."
        for i in $(seq 1 $rate); do
            /bin/true &
        done
        sleep 1
    done
    
    print_result success "Gradual ramp-up completed"
    echo -e "${GREEN}  ✓ EXPECTED: Alerts when crossing threshold (>100/sec)${NC}"
    
    sleep 2
}

# Test 7: Spike detection test
test_spike_detection() {
    print_section "Test 7: Spike Detection (5x Baseline)"
    print_test "Testing spike detection with baseline then sudden increase..."
    
    # Establish baseline (10/sec for 10 seconds)
    echo "  Establishing baseline (10 processes/sec)..."
    for i in {1..10}; do
        for j in {1..10}; do
            /bin/true &
        done
        sleep 1
    done
    
    sleep 2
    
    # Sudden spike (5x baseline = 50/sec)
    echo "  Creating spike (50 processes/sec = 5x baseline)..."
    for i in {1..50}; do
        /bin/true &
    done
    
    print_result success "Spike test completed"
    echo -e "${GREEN}  ✓ EXPECTED: packet_rate_spike alert (if enabled)${NC}"
    
    sleep 2
}

# Main test execution
main() {
    print_banner
    
    # Check root
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}This test must be run as root (for Phase 1 eBPF)${NC}"
        echo "Usage: sudo $0"
        exit 1
    fi
    
    check_dependencies
    
    echo ""
    echo -e "${CYAN}Starting real-time traffic tests...${NC}"
    echo -e "${CYAN}Duration: ${DURATION}s${NC}"
    echo -e "${CYAN}Monitor zkNIDS pipeline output for alerts${NC}"
    echo ""
    echo -e "${YELLOW}Press Ctrl+C to stop early${NC}"
    sleep 3
    
    # Run tests in sequence
    test_normal_traffic
    test_execve_spike
    test_sustained_load
    test_network_spike
    test_combined_attack
    test_gradual_rampup
    test_spike_detection
    
    # Final summary
    print_section "Test Summary"
    echo "All traffic generation tests completed!"
    echo ""
    echo -e "${GREEN}Expected Alerts:${NC}"
    echo "  • execve_rate_high: ~8-12 alerts"
    echo "  • packet_rate_spike: 1-3 alerts (if enabled)"
    echo "  • syn_flood_detection: 0 alerts (no SYN flood in these tests)"
    echo ""
    echo -e "${CYAN}Check your zkNIDS pipeline output for actual alerts.${NC}"
    echo ""
}

# Trap Ctrl+C
trap 'echo -e "\n${YELLOW}Test interrupted by user${NC}"; exit 0' INT

main "$@"

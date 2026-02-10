#!/bin/bash
#
# zkNIDS Network Testing Diagnostic
# Checks what tools are available for network attack simulation
#

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  zkNIDS Network Testing Diagnostic                    ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check hping3
echo -e "${YELLOW}Checking for hping3...${NC}"
if command -v hping3 &> /dev/null; then
    VERSION=$(hping3 --version 2>&1 | head -1)
    echo -e "${GREEN}✓ hping3 installed: $VERSION${NC}"
    HPING3_AVAILABLE=true
else
    echo -e "${RED}✗ hping3 NOT installed${NC}"
    echo "  Install with: sudo apt install hping3"
    HPING3_AVAILABLE=false
fi
echo ""

# Check scapy (alternative for Python-based packet generation)
echo -e "${YELLOW}Checking for scapy...${NC}"
if python3 -c "import scapy.all" 2>/dev/null; then
    VERSION=$(python3 -c "import scapy; print(scapy.__version__)")
    echo -e "${GREEN}✓ scapy installed: $VERSION${NC}"
    SCAPY_AVAILABLE=true
else
    echo -e "${YELLOW}⚠ scapy NOT installed${NC}"
    echo "  Install with: sudo pip3 install scapy"
    SCAPY_AVAILABLE=false
fi
echo ""

# Check netcat
echo -e "${YELLOW}Checking for netcat...${NC}"
if command -v nc &> /dev/null; then
    echo -e "${GREEN}✓ netcat installed${NC}"
    NC_AVAILABLE=true
else
    echo -e "${RED}✗ netcat NOT installed${NC}"
    NC_AVAILABLE=false
fi
echo ""

# Check current invariant configuration
echo -e "${YELLOW}Checking current detection thresholds...${NC}"
if [ -f "phase2/config/invariants.yaml" ]; then
    EXECVE_THRESHOLD=$(grep -A 5 "id: execve_rate_high" phase2/config/invariants.yaml | grep "threshold:" | awk '{print $2}')
    PACKET_SPIKE_ENABLED=$(grep -A 5 "id: packet_rate_spike" phase2/config/invariants.yaml | grep "enabled:" | awk '{print $2}')
    PACKET_SPIKE_MULT=$(grep -A 5 "id: packet_rate_spike" phase2/config/invariants.yaml | grep "baseline_multiplier:" | awk '{print $2}')
    SYN_FLOOD_ENABLED=$(grep -A 5 "id: syn_flood_detection" phase2/config/invariants.yaml | grep "enabled:" | awk '{print $2}')
    SYN_FLOOD_THRESHOLD=$(grep -A 5 "id: syn_flood_detection" phase2/config/invariants.yaml | grep "threshold:" | awk '{print $2}')
    
    echo "Current Configuration:"
    echo "  • execve_rate_high: threshold=$EXECVE_THRESHOLD"
    echo "  • packet_rate_spike: enabled=$PACKET_SPIKE_ENABLED, multiplier=$PACKET_SPIKE_MULT"
    echo "  • syn_flood_detection: enabled=$SYN_FLOOD_ENABLED, threshold=$SYN_FLOOD_THRESHOLD (80% ratio)"
else
    echo -e "${RED}✗ Configuration file not found${NC}"
fi
echo ""

# Recommendations
echo -e "${CYAN}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  Recommendations                                       ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════╝${NC}"
echo ""

if [ "$HPING3_AVAILABLE" = false ]; then
    echo -e "${YELLOW}⚠ RECOMMENDED: Install hping3 for best network testing${NC}"
    echo "  Command: sudo apt install hping3"
    echo "  Why: Most effective for packet floods and SYN floods"
    echo ""
fi

if [ "$SCAPY_AVAILABLE" = false ]; then
    echo -e "${YELLOW}ℹ OPTIONAL: Install scapy for Python-based packet generation${NC}"
    echo "  Command: sudo pip3 install scapy"
    echo "  Why: Alternative if hping3 unavailable"
    echo ""
fi

# Test suggestions
echo -e "${CYAN}Suggested Tests:${NC}"
echo ""

if [ "$HPING3_AVAILABLE" = true ]; then
    echo -e "${GREEN}With hping3 (RECOMMENDED):${NC}"
    echo "  1. Packet flood: sudo hping3 -1 --flood -c 10000 127.0.0.1"
    echo "  2. SYN flood:    sudo hping3 -S -p 80 --flood -c 5000 127.0.0.1"
    echo ""
else
    echo -e "${YELLOW}Without hping3 (Limited):${NC}"
    echo "  1. Ping flood:   ping -c 5000 -f 127.0.0.1"
    echo "  2. Connections:  for i in {1..500}; do (nc -z 127.0.0.1 80 &); done"
    echo ""
    echo -e "${RED}  ⚠ These may not trigger alerts reliably${NC}"
    echo ""
fi

# Summary
echo -e "${CYAN}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  System Capability Summary                            ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════╝${NC}"
echo ""

CAPABILITIES=0
if [ "$HPING3_AVAILABLE" = true ]; then ((CAPABILITIES++)); fi
if [ "$SCAPY_AVAILABLE" = true ]; then ((CAPABILITIES++)); fi
if [ "$NC_AVAILABLE" = true ]; then ((CAPABILITIES++)); fi

echo "Network Testing Capabilities: $CAPABILITIES/3"
echo ""

if [ "$HPING3_AVAILABLE" = true ]; then
    echo -e "${GREEN}✓ READY for full network attack testing${NC}"
else
    echo -e "${YELLOW}⚠ LIMITED network testing (install hping3 for full tests)${NC}"
fi

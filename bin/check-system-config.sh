#!/bin/bash
#
# System Configuration Check
#

echo "═══ System Configuration Check ═══"
echo ""

echo "1. Firewall Status:"
echo "-------------------"
if command -v ufw &> /dev/null; then
    echo "UFW status:"
    sudo ufw status
else
    echo "UFW not installed"
fi

echo ""
if command -v iptables &> /dev/null; then
    echo "iptables rules:"
    sudo iptables -L -n | head -20
fi

echo ""
echo "2. Network Interface Status:"
echo "----------------------------"
ip -s link show ens33

echo ""
echo "3. XDP Programs Attached:"
echo "-------------------------"
if command -v bpftool &> /dev/null; then
    sudo bpftool net list
else
    echo "bpftool not available"
    echo "Install: sudo apt install linux-tools-generic"
fi

echo ""
echo "4. Kernel Version:"
echo "------------------"
uname -r

echo ""
echo "5. System Load:"
echo "---------------"
uptime

echo ""
echo "6. Network Statistics:"
echo "----------------------"
netstat -s | grep -i "icmp\|tcp" | head -10

echo ""
echo "7. Test Packet Receipt (tcpdump):"
echo "-----------------------------------"
echo "Testing if packets are being received..."
echo "Run from another machine: ping -c 3 $(hostname -I | awk '{print $1}')"
echo ""
read -p "Press Enter after running ping from other machine..."

echo "Capturing 10 packets on ens33..."
timeout 5 sudo tcpdump -i ens33 -c 10 -n 2>&1 | grep -v "listening"

echo ""
echo "If you see packets above, ens33 IS receiving traffic."
echo "If not, there's a network-level issue."

#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# zkNIDS Agent Host — Install Script v2.2
# ═══════════════════════════════════════════════════════════════════════════════
#
# Installs Phase 1 (eBPF), Phase 2 (detector), Agent (heartbeat/forwarder),
# and pipeline scripts on a sensor host.
#
# Usage:
#   sudo bash install.sh --api-key <key> --aggregator http://10.0.0.50:8080
#   sudo bash install.sh --api-key <key> --interface ens4
#
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

INSTALL_DIR="/opt/zknids"
CONFIG_DIR="/etc/zknids"
DATA_DIR="/var/lib/zknids"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Defaults
AGGREGATOR_URL="http://10.0.0.50:8080"
API_KEY=""
INTERFACE=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --api-key)      API_KEY="$2"; shift 2 ;;
        --aggregator)   AGGREGATOR_URL="$2"; shift 2 ;;
        --interface)    INTERFACE="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: sudo bash install.sh [OPTIONS]"
            echo "  --api-key KEY        Agent API key (from aggregator install)"
            echo "  --aggregator URL     Aggregator URL (default: http://10.0.0.50:8080)"
            echo "  --interface IFACE    Network capture interface (auto-detect if omitted)"
            exit 0 ;;
        *) echo "Unknown: $1"; exit 1 ;;
    esac
done

# Root check
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: Run with sudo"
    exit 1
fi

echo "═══════════════════════════════════════════════════════════"
echo "  zkNIDS Agent Host — Installer v2.2"
echo "═══════════════════════════════════════════════════════════"
echo "  Package dir: $SCRIPT_DIR"
echo "  Install dir: $INSTALL_DIR"
echo "  Aggregator:  $AGGREGATOR_URL"
echo

# ══════════════════════════════════════════════════════════════════════════════
# STEP 1: System Dependencies
# ══════════════════════════════════════════════════════════════════════════════
echo "[1/5] Installing system dependencies..."

apt-get update -qq
apt-get install -y -qq \
    build-essential clang llvm \
    libbpf-dev linux-tools-common linux-tools-generic \
    libssl-dev pkg-config \
    python3 python3-pip python3-yaml \
    curl jq >/dev/null 2>&1

# Install bpftool for kernel version
KVER=$(uname -r)
apt-get install -y -qq "linux-tools-${KVER}" 2>/dev/null || \
    echo "  ⚠ Could not install linux-tools-${KVER}. bpftool may not work."

# Python deps
pip3 install requests pyyaml --break-system-packages -q 2>/dev/null || \
    pip3 install requests pyyaml -q

echo "  ✓ Dependencies installed"

# ══════════════════════════════════════════════════════════════════════════════
# STEP 2: Phase 1 — eBPF/XDP Packet Capture
# ══════════════════════════════════════════════════════════════════════════════
echo
echo "[2/5] Building Phase 1 (eBPF)..."

mkdir -p "$INSTALL_DIR"

if [[ -d "$SCRIPT_DIR/phase1" ]]; then
    cp -r "$SCRIPT_DIR/phase1" "$INSTALL_DIR/"

    cd "$INSTALL_DIR/phase1"

    # Generate vmlinux.h for this kernel
    if [[ ! -f "include/vmlinux.h" ]]; then
        mkdir -p include
        if command -v bpftool &>/dev/null; then
            bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h 2>/dev/null
            echo "  ✓ vmlinux.h generated ($(wc -l < include/vmlinux.h) lines)"
        else
            echo "  ⚠ bpftool not found — vmlinux.h not generated"
        fi
    fi

    # Build
    if make -j"$(nproc)" 2>/dev/null; then
        echo "  ✓ Phase 1 built (eBPF + loader)"
    else
        echo "  ⚠ Phase 1 build failed — check dependencies"
    fi
else
    echo "  ERROR: phase1/ directory not found in package"
    exit 1
fi

# ══════════════════════════════════════════════════════════════════════════════
# STEP 3: Phase 2 — Detection Engine
# ══════════════════════════════════════════════════════════════════════════════
echo
echo "[3/5] Installing Phase 2 (detector)..."

if [[ -d "$SCRIPT_DIR/phase2" ]]; then
    cp -r "$SCRIPT_DIR/phase2" "$INSTALL_DIR/"

    cd "$INSTALL_DIR/phase2"

    if [[ -f setup.py ]]; then
        pip3 install -e . --break-system-packages -q 2>/dev/null \
            || pip3 install -e . -q
        echo "  ✓ Phase 2 installed as Python package"
    elif [[ -f requirements.txt ]]; then
        pip3 install -r requirements.txt --break-system-packages -q 2>/dev/null \
            || pip3 install -r requirements.txt -q
        echo "  ✓ Phase 2 dependencies installed"
    fi

    if python3 -c "import zkNIDS_phase2" 2>/dev/null; then
        echo "  ✓ Phase 2 module importable"
    else
        echo "  ⚠ Phase 2 not importable — will use PYTHONPATH fallback"
    fi
else
    echo "  ERROR: phase2/ directory not found in package"
    exit 1
fi

# ══════════════════════════════════════════════════════════════════════════════
# STEP 4: Agent + Pipeline Scripts
# ══════════════════════════════════════════════════════════════════════════════
echo
echo "[4/5] Installing Agent v2.2..."

# Copy agent script
cp "$SCRIPT_DIR/zknids_agent.py" "$INSTALL_DIR/"
chmod 755 "$INSTALL_DIR/zknids_agent.py"
echo "  ✓ $INSTALL_DIR/zknids_agent.py"

# Copy pipeline scripts from package or create them inline
mkdir -p "$INSTALL_DIR/bin"
if [[ -f "$SCRIPT_DIR/bin/run-pipeline.sh" ]]; then
    cp "$SCRIPT_DIR/bin/run-pipeline.sh" "$INSTALL_DIR/bin/"
    chmod +x "$INSTALL_DIR/bin/run-pipeline.sh"
    echo "  ✓ Pipeline script from package"
else
    # Create run-pipeline.sh inline
    cat > "$INSTALL_DIR/bin/run-pipeline.sh" <<'PIPELINE'
#!/bin/bash
set -uo pipefail

INSTALL_DIR="/opt/zknids"
CONFIG_FILE="/etc/zknids/agent.conf"
ALERT_DIR="/var/lib/zknids/alerts"

# Resolve interface: env var > agent.conf > auto-detect
if [[ -z "${PHASE1_INTERFACE:-}" ]]; then
    if [[ -f "$CONFIG_FILE" ]]; then
        CONF_IFACE=$(python3 -c "
import json
try:
    c = json.load(open('$CONFIG_FILE'))
    v = c.get('interface', '')
    if v: print(v)
except: pass
" 2>/dev/null)
        [[ -n "$CONF_IFACE" ]] && PHASE1_INTERFACE="$CONF_IFACE"
    fi
fi
if [[ -z "${PHASE1_INTERFACE:-}" ]]; then
    PHASE1_INTERFACE=$(ip -o link show | awk -F': ' '
        $2 !~ /^lo$/ && $2 !~ /^docker/ && $2 !~ /^br-/ && $2 !~ /^veth/ {
            gsub(/@.*/, "", $2); a[++n]=$2
        } END { if(n>=2) print a[2]; else if(n>=1) print a[1] }')
fi
echo "Pipeline: interface=$PHASE1_INTERFACE"

CONFIG_PATH="${PHASE2_CONFIG:-$INSTALL_DIR/phase2/config/invariants.yaml}"
mkdir -p "$ALERT_DIR"

PHASE1_BIN=""
for p in "$INSTALL_DIR/phase1/userspace/collector/phase1_loader" \
         "$INSTALL_DIR/phase1/phase1_loader"; do
    [[ -x "$p" ]] && PHASE1_BIN="$p" && break
done
[[ -z "$PHASE1_BIN" ]] && echo "ERROR: Phase 1 not found" >&2 && exit 1

P2_ARGS=""
[[ -f "$CONFIG_PATH" ]] && P2_ARGS="--config $CONFIG_PATH"

# cd to phase1 binary dir so relative .bpf.o paths resolve
cd "$(dirname "$PHASE1_BIN")"

"$PHASE1_BIN" -i "$PHASE1_INTERFACE" 2>&1 | \
    python3 -m zkNIDS_phase2 $P2_ARGS 2>&1 | \
    while IFS= read -r line; do
        echo "$line" >&2
        if echo "$line" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
            echo "$line" > "$ALERT_DIR/alert_$(date +%s%N).json"
        fi
    done
PIPELINE
    chmod +x "$INSTALL_DIR/bin/run-pipeline.sh"
    echo "  ✓ Pipeline script created inline"
fi

# ── Auto-detect interface if not provided ──
if [[ -z "$INTERFACE" ]]; then
    # Prefer second interface (monitoring NIC)
    INTERFACE=$(ip -o link show | awk -F': ' '
        $2 !~ /^lo$/ && $2 !~ /^docker/ && $2 !~ /^br-/ && $2 !~ /^veth/ && $2 !~ /^virbr/ {
            gsub(/@.*/, "", $2); a[++n] = $2
        }
        END { if (n >= 2) print a[2]; else if (n >= 1) print a[1] }
    ')
    if [[ -z "$INTERFACE" ]]; then
        INTERFACE="eth0"
        echo "  ⚠ Could not detect interface. Defaulting to eth0."
    else
        echo "  ✓ Auto-detected interface: $INTERFACE"
    fi
fi

# ── Prompt for API key if not provided ──
if [[ -z "$API_KEY" ]]; then
    echo
    echo "  ┌─────────────────────────────────────────────────┐"
    echo "  │ API key needed. Get it from aggregator:         │"
    echo "  │   cat /var/lib/zknids/api_keys_plaintext.txt   │"
    echo "  └─────────────────────────────────────────────────┘"
    echo
    read -rp "  Enter Agent API key (or press Enter to skip): " API_KEY
    if [[ -z "$API_KEY" ]]; then
        echo "  ⚠ No API key. Edit $CONFIG_DIR/agent.conf later."
    fi
fi

# ── Write config ──
mkdir -p "$CONFIG_DIR"
cat > "$CONFIG_DIR/agent.conf" <<CONF
{
    "aggregator_url": "${AGGREGATOR_URL}",
    "api_key": "${API_KEY}",
    "host_id": "",
    "interface": "${INTERFACE}",
    "heartbeat_interval": 10,
    "alert_watch_dir": "${DATA_DIR}/alerts",
    "alert_archive_dir": "${DATA_DIR}/alerts/sent",
    "retry_max": 5,
    "retry_base_delay": 1,
    "log_file": "/var/log/zknids-agent.log"
}
CONF
chmod 600 "$CONFIG_DIR/agent.conf"
echo "  ✓ $CONFIG_DIR/agent.conf (interface=$INTERFACE)"

# ── Data directories ──
mkdir -p "$DATA_DIR/alerts/sent"

# ══════════════════════════════════════════════════════════════════════════════
# STEP 5: Systemd Services
# ══════════════════════════════════════════════════════════════════════════════
echo
echo "[5/5] Installing systemd services..."

# ── Service 1: zkNIDS Agent (heartbeat + alert forwarder) ──
cat > /etc/systemd/system/zknids-agent.service <<EOF
[Unit]
Description=zkNIDS Agent — Heartbeat + Alert Forwarder v2.2
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/zknids_agent.py --config ${CONFIG_DIR}/agent.conf
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=zknids-agent

[Install]
WantedBy=multi-user.target
EOF
echo "  ✓ zknids-agent.service"

# ── Service 2: zkNIDS Pipeline (phase1 → phase2 pipe) ──
# NOTE: No PHASE1_INTERFACE env var — pipeline reads from agent.conf
cat > /etc/systemd/system/zknids-pipeline.service <<EOF
[Unit]
Description=zkNIDS Pipeline — Phase 1 (eBPF) → Phase 2 (Detector)
After=network.target
Requires=zknids-agent.service

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/bin/run-pipeline.sh
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=zknids-pipeline

[Install]
WantedBy=multi-user.target
EOF
echo "  ✓ zknids-pipeline.service"

systemctl daemon-reload

# ══════════════════════════════════════════════════════════════════════════════
# DONE
# ══════════════════════════════════════════════════════════════════════════════
echo
echo "═══════════════════════════════════════════════════════════"
echo "  ✓ zkNIDS Agent Host — Installation Complete (v2.2)"
echo "═══════════════════════════════════════════════════════════"
echo
echo "  Install dir:   $INSTALL_DIR"
echo "  Config:        $CONFIG_DIR/agent.conf"
echo "  Interface:     $INTERFACE"
echo "  Alert dir:     $DATA_DIR/alerts"
echo
echo "  Start services:"
echo "    sudo systemctl start zknids-agent"
echo "    sudo systemctl start zknids-pipeline"
echo
echo "  Enable on boot:"
echo "    sudo systemctl enable zknids-agent zknids-pipeline"
echo
echo "  Check status:"
echo "    journalctl -u zknids-agent -f"
echo "    journalctl -u zknids-pipeline -f"
echo "═══════════════════════════════════════════════════════════"
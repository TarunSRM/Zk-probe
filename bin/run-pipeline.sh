#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# zkNIDS Pipeline Runner — Phase 1 (eBPF) → Phase 2 (Detector)
# ═══════════════════════════════════════════════════════════════════════════════
#
# Pipes Phase 1 output into Phase 2 and saves alerts as JSON files for the
# agent to pick up and forward to the aggregator.
#
# Interface resolution (in order):
#   1. $PHASE1_INTERFACE environment variable (from systemd service)
#   2. "interface" field in /etc/zknids/agent.conf
#   3. Auto-detect: prefers second NIC (ens4/eth1)
#
# ═══════════════════════════════════════════════════════════════════════════════

set -uo pipefail

INSTALL_DIR="/opt/zknids"
CONFIG_DIR="/etc/zknids"
CONFIG_FILE="$CONFIG_DIR/agent.conf"
ALERT_DIR="/var/lib/zknids/alerts"
PROJECT_ROOT="$INSTALL_DIR"

# ── Resolve interface ──
# Priority: env var > agent.conf > auto-detect
if [[ -z "${PHASE1_INTERFACE:-}" ]]; then
    # Try reading from agent.conf
    if [[ -f "$CONFIG_FILE" ]]; then
        CONF_IFACE=$(python3 -c "
import json, sys
try:
    c = json.load(open('$CONFIG_FILE'))
    v = c.get('interface', '')
    if v: print(v)
except: pass
" 2>/dev/null)
        if [[ -n "$CONF_IFACE" ]]; then
            PHASE1_INTERFACE="$CONF_IFACE"
        fi
    fi
fi

# Auto-detect if still empty: prefer second interface (monitoring NIC)
if [[ -z "${PHASE1_INTERFACE:-}" ]]; then
    PHASE1_INTERFACE=$(ip -o link show | awk -F': ' '
        $2 !~ /^lo$/ && $2 !~ /^docker/ && $2 !~ /^br-/ && $2 !~ /^veth/ && $2 !~ /^virbr/ {
            gsub(/@.*/, "", $2); ifaces[++n] = $2
        }
        END { if (n >= 2) print ifaces[2]; else if (n >= 1) print ifaces[1] }
    ')
    if [[ -z "$PHASE1_INTERFACE" ]]; then
        echo "ERROR: Cannot detect interface. Set PHASE1_INTERFACE or configure agent.conf" >&2
        exit 1
    fi
fi

echo "Pipeline starting: interface=$PHASE1_INTERFACE"

# ── Resolve Phase 2 config ──
CONFIG_PATH="${PHASE2_CONFIG:-$INSTALL_DIR/phase2/config/invariants.yaml}"

# ── Ensure alert directory exists ──
mkdir -p "$ALERT_DIR"

# ── Find Phase 1 binary ──
PHASE1_BIN=""
for p in "$INSTALL_DIR/phase1/userspace/collector/phase1_loader" \
         "$INSTALL_DIR/phase1/phase1_loader" \
         "/usr/local/bin/zknids-phase1"; do
    if [[ -x "$p" ]]; then
        PHASE1_BIN="$p"
        break
    fi
done
if [[ -z "$PHASE1_BIN" ]]; then
    echo "ERROR: Phase 1 binary not found" >&2
    exit 1
fi

echo "Phase 1: $PHASE1_BIN"
echo "Phase 2 config: $CONFIG_PATH"
echo "Alert dir: $ALERT_DIR"

# ── Run pipeline: Phase 1 → Phase 2 → alert JSON files ──
# Phase 1 outputs JSON snapshots to stdout (1/sec)
# Phase 2 reads from stdin, outputs alert JSON to stdout when invariants fire
# We parse Phase 2 stdout and save valid JSON lines as alert files

# Phase 1 binary uses relative paths to find .bpf.o files (../../build/bpf/...)
# Must cd to the binary's directory so paths resolve correctly
PHASE1_DIR="$(dirname "$PHASE1_BIN")"
cd "$PHASE1_DIR"
echo "Working dir: $(pwd)"

if [[ -f "$CONFIG_PATH" ]]; then
    P2_ARGS="--config $CONFIG_PATH"
else
    P2_ARGS=""
fi

"$PHASE1_BIN" -i "$PHASE1_INTERFACE" 2>&1 | \
    python3 -m zkNIDS_phase2 $P2_ARGS 2>&1 | \
    while IFS= read -r line; do
        # Log everything to stderr (visible in journalctl)
        echo "$line" >&2
        
        # Check if line is valid JSON — if so, it's an alert
        if echo "$line" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
            ALERT_FILE="$ALERT_DIR/alert_$(date +%s%N).json"
            echo "$line" > "$ALERT_FILE"
            echo "ALERT saved: $ALERT_FILE" >&2
        fi
    done
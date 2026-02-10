#!/usr/bin/env bash
###############################################################################
# zkNIDS - Machine A (Defender) - Final Real-Time Attack Test
# 
# Run this on Machine A (192.168.36.131) BEFORE starting attacks from Machine B
#
# Usage: sudo ./machine_a_final_test.sh
###############################################################################

set -euo pipefail

# ─── Configuration ───────────────────────────────────────────────────────────
ZKNIDS_DIR="/home/ubuntu/projects/zkNIDS"
INTERFACE="ens33"
TEST_DIR="/tmp/zkNIDS_final_test_$(date +%Y%m%d_%H%M%S)"
ALERT_FILE="${TEST_DIR}/alerts.jsonl"
PHASE1_LOG="${TEST_DIR}/phase1.log"
PHASE2_LOG="${TEST_DIR}/phase2.log"
PIPELINE_LOG="${TEST_DIR}/pipeline.log"
DURATION=180  # Total test window in seconds (covers full attack sequence)
GRACE_PERIOD=20  # Seconds to wait before counting alerts (baseline stabilization)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ─── Pre-flight Checks ──────────────────────────────────────────────────────
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║         zkNIDS - Final Real-Time Attack Test (Machine A)    ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR] This script must be run as root (sudo)${NC}"
    exit 1
fi

# Check interface
if ! ip link show "$INTERFACE" &>/dev/null; then
    echo -e "${RED}[ERROR] Interface '$INTERFACE' not found${NC}"
    echo "Available interfaces:"
    ip -o link show | awk -F': ' '{print "  - "$2}'
    exit 1
fi

# Check zkNIDS directory
if [[ ! -d "$ZKNIDS_DIR" ]]; then
    echo -e "${RED}[ERROR] zkNIDS directory not found at $ZKNIDS_DIR${NC}"
    exit 1
fi

# Check compiled BPF objects
if [[ ! -f "$ZKNIDS_DIR/phase1/build/bpf/xdp/xdp_counter.bpf.o" ]]; then
    echo -e "${YELLOW}[WARN] BPF objects not found. Rebuilding Phase 1...${NC}"
    cd "$ZKNIDS_DIR/phase1"
    make clean && make
    echo -e "${GREEN}[OK] Phase 1 rebuilt successfully${NC}"
fi

# Check Phase 2 dependencies
if ! python3 -c "import yaml" 2>/dev/null; then
    echo -e "${RED}[ERROR] Python yaml module not found. Install: pip3 install pyyaml${NC}"
    exit 1
fi

# ─── Verify Bug Fixes ───────────────────────────────────────────────────────
echo -e "${CYAN}[CHECK] Verifying critical bug fixes...${NC}"

# Bug Fix #1: TCP bounds check ordering
if grep -q "void \*tcp_start" "$ZKNIDS_DIR/phase1/ebpf/xdp/xdp_counter.bpf.c"; then
    echo -e "  ${GREEN}✓ Bug Fix #1: TCP bounds check ordering${NC}"
else
    echo -e "  ${RED}✗ Bug Fix #1: TCP bounds check NOT applied!${NC}"
    exit 1
fi

# Bug Fix #2: execve_map type
if grep -q "__type(value, __u64)" "$ZKNIDS_DIR/phase1/ebpf/tracepoints/execve_counter.bpf.c"; then
    echo -e "  ${GREEN}✓ Bug Fix #2: execve_map type fix${NC}"
else
    echo -e "  ${RED}✗ Bug Fix #2: execve_map type NOT fixed!${NC}"
    exit 1
fi

# Bug Fix #3: Map clearing
if grep -q "Clear maps" "$ZKNIDS_DIR/phase1/userspace/collector/phase1_loader.c"; then
    echo -e "  ${GREEN}✓ Bug Fix #3: Map clearing per interval${NC}"
else
    echo -e "  ${RED}✗ Bug Fix #3: Map clearing NOT applied!${NC}"
    exit 1
fi

# ─── Verify Thresholds ──────────────────────────────────────────────────────
echo -e "${CYAN}[CHECK] Verifying detection thresholds...${NC}"

INVARIANTS_FILE="$ZKNIDS_DIR/phase2/config/invariants.yaml"

THRESHOLD_INFO=$(python3 -c "
import yaml, sys
with open('$INVARIANTS_FILE') as f:
    cfg = yaml.safe_load(f)
baseline = syn_thresh = 'NOT FOUND'
for inv in cfg.get('invariants', []):
    if inv.get('id') == 'packet_rate_spike':
        baseline = inv.get('baseline_multiplier', 'NOT SET')
    if inv.get('id') == 'syn_flood_detection':
        syn_thresh = inv.get('threshold', 'NOT SET')
print(f'{baseline}|{syn_thresh}')
" 2>/dev/null || echo "ERROR|ERROR")

BASELINE=$(echo "$THRESHOLD_INFO" | cut -d'|' -f1)
SYN_THRESH=$(echo "$THRESHOLD_INFO" | cut -d'|' -f2)

echo -e "  Packet spike baseline_multiplier: ${BOLD}${BASELINE}${NC} (should be 1.5)"
echo -e "  SYN flood threshold:              ${BOLD}${SYN_THRESH}${NC} (should be 0.2)"

# ─── Kill Previous Instances ────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}[CLEANUP] Stopping any existing zkNIDS processes...${NC}"
pkill -f phase1_loader 2>/dev/null || true
pkill -f zkNIDS_phase2 2>/dev/null || true
sleep 2

# ─── Create Test Directory ──────────────────────────────────────────────────
mkdir -p "$TEST_DIR"
echo -e "${GREEN}[OK] Test output directory: $TEST_DIR${NC}"

# ─── Start Pipeline ─────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}[START] Launching zkNIDS pipeline...${NC}"
echo -e "${BOLD}════════════════════════════════════════════════════════════════${NC}"

cd "$ZKNIDS_DIR"

# Set environment variables for the pipeline scripts
export PHASE1_INTERFACE="$INTERFACE"
export PHASE1_INTERVAL=1
export PHASE2_CONFIG="$INVARIANTS_FILE"

# Verify pipeline scripts exist
if [[ ! -x "$ZKNIDS_DIR/bin/run-pipeline.sh" ]]; then
    echo -e "${RED}[ERROR] run-pipeline.sh not found or not executable at $ZKNIDS_DIR/bin/run-pipeline.sh${NC}"
    exit 1
fi

# Start full pipeline (Phase 1 → Phase 2) using existing scripts
echo -e "${CYAN}[Pipeline] Starting Phase 1 → Phase 2 via run-pipeline.sh...${NC}"
export SAVE_SNAPSHOTS="$PHASE1_LOG"
"$ZKNIDS_DIR/bin/run-pipeline.sh" > "$ALERT_FILE" 2>"$PIPELINE_LOG" &
PIPELINE_PID=$!
sleep 3

if ! kill -0 $PIPELINE_PID 2>/dev/null; then
    echo -e "${RED}[ERROR] Pipeline failed to start!${NC}"
    echo -e "${RED}  Check logs:${NC}"
    echo -e "${RED}    Pipeline: $PIPELINE_LOG${NC}"
    echo -e "${RED}    Phase 1:  $PHASE1_LOG${NC}"
    cat "$PIPELINE_LOG" 2>/dev/null
    exit 1
fi
echo -e "${GREEN}  ✓ Pipeline running (PID: $PIPELINE_PID)${NC}"
echo -e "${GREEN}    Phase 1 snapshots: $PHASE1_LOG${NC}"
echo -e "${GREEN}    Phase 2 alerts:    $ALERT_FILE${NC}"

# ─── Live Monitoring ────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  zkNIDS is LIVE and monitoring!${NC}"
echo -e "${BOLD}════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}  Machine A IP:    $(ip -4 addr show $INTERFACE | grep inet | awk '{print $2}' | head -1)${NC}"
echo -e "${YELLOW}  Interface:       $INTERFACE${NC}"
echo -e "${YELLOW}  Alert file:      $ALERT_FILE${NC}"
echo -e "${YELLOW}  Test duration:   ${DURATION}s${NC}"
echo ""
echo -e "${CYAN}  ➤ Start attacks from Machine B now!${NC}"
echo -e "${CYAN}  ➤ Monitoring alerts in real-time...${NC}"
echo ""
echo -e "${BOLD}──────────────────── LIVE ALERTS ────────────────────${NC}"
echo -e "${YELLOW}  (First ${GRACE_PERIOD}s is grace period — alerts during warmup are noted but excluded from count)${NC}"

# Monitor alerts in real-time
SECONDS=0
ALERT_COUNT=0
GRACE_ALERTS=0
GRACE_DONE=false

while [[ $SECONDS -lt $DURATION ]]; do
    # Count new alerts (only lines containing valid JSON with alert_id)
    if [[ -f "$ALERT_FILE" ]]; then
        NEW_COUNT=$(grep -c '"alert_id"' "$ALERT_FILE" 2>/dev/null | tail -1 || true)
        NEW_COUNT=${NEW_COUNT:-0}
        # Ensure NEW_COUNT is a valid integer
        if ! [[ "$NEW_COUNT" =~ ^[0-9]+$ ]]; then
            NEW_COUNT=0
        fi

        TOTAL_SO_FAR=$((NEW_COUNT))

        # Grace period handling
        if [[ $SECONDS -lt $GRACE_PERIOD ]]; then
            # During grace period — track but label as warmup noise
            if [[ $TOTAL_SO_FAR -gt $GRACE_ALERTS ]]; then
                DIFF=$((TOTAL_SO_FAR - GRACE_ALERTS))
                GRACE_ALERTS=$TOTAL_SO_FAR
                echo -e "${YELLOW}[WARMUP] +${DIFF} alert(s) during grace period (excluded from final count)${NC}"
                tail -$DIFF "$ALERT_FILE" | while IFS= read -r line; do
                    ALERT_TYPE=$(echo "$line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('invariant',{}).get('id','unknown'))" 2>/dev/null || echo "parse_error")
                    echo -e "  ${YELLOW}│ [warmup] ${ALERT_TYPE}${NC}"
                done
            fi
        else
            # After grace period — real alert counting
            if [[ "$GRACE_DONE" == "false" ]]; then
                GRACE_DONE=true
                # Reset: real alerts = total alerts minus grace alerts
                ALERT_COUNT=$GRACE_ALERTS
                echo -e "${GREEN}  ✓ Grace period complete. Monitoring for real alerts...${NC}"
            fi

            if [[ $TOTAL_SO_FAR -gt $ALERT_COUNT ]]; then
                DIFF=$((TOTAL_SO_FAR - ALERT_COUNT))
                ALERT_COUNT=$TOTAL_SO_FAR
                REAL_ALERTS=$((ALERT_COUNT - GRACE_ALERTS))

                # Display new alerts
                echo -e "${RED}[ALERT] +${DIFF} new alert(s) detected! (Real: ${REAL_ALERTS})${NC}"
                tail -$DIFF "$ALERT_FILE" | while IFS= read -r line; do
                    ALERT_TYPE=$(echo "$line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('invariant',{}).get('id','unknown'))" 2>/dev/null || echo "parse_error")
                    SEVERITY=$(echo "$line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('metadata',{}).get('severity','unknown'))" 2>/dev/null || echo "unknown")
                    OBSERVED=$(echo "$line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('observation',{}).get('observed_value','?'))" 2>/dev/null || echo "?")
                    echo -e "  ${RED}│ Type: ${BOLD}${ALERT_TYPE}${NC}"
                    echo -e "  ${RED}│ Severity: ${SEVERITY}  |  Observed: ${OBSERVED}${NC}"
                    echo -e "  ${RED}└──────────────────────────────────────${NC}"
                done
            fi
        fi
    fi
    
    # Status heartbeat every 10 seconds
    if (( SECONDS % 10 == 0 )); then
        REAL_COUNT=$((ALERT_COUNT - GRACE_ALERTS))
        if [[ $REAL_COUNT -lt 0 ]]; then REAL_COUNT=0; fi
        echo -e "${CYAN}  [${SECONDS}s/${DURATION}s] Monitoring... Real alerts: ${REAL_COUNT} (warmup: ${GRACE_ALERTS})${NC}"
    fi
    
    sleep 1
done

# ─── Stop Pipeline ──────────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}[STOP] Test window complete. Stopping pipeline...${NC}"
kill $PIPELINE_PID 2>/dev/null || true
pkill -f phase1_loader 2>/dev/null || true
pkill -f zkNIDS_phase2 2>/dev/null || true
pkill -f run-pipeline 2>/dev/null || true
pkill -f run-phase1 2>/dev/null || true
pkill -f run-phase2 2>/dev/null || true
sleep 2

# ─── Results Summary ────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║                    TEST RESULTS SUMMARY                     ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

TOTAL_ALERTS=$(grep -c '"alert_id"' "$ALERT_FILE" 2>/dev/null | tail -1 || true)
TOTAL_ALERTS=${TOTAL_ALERTS:-0}; [[ "$TOTAL_ALERTS" =~ ^[0-9]+$ ]] || TOTAL_ALERTS=0

SYN_ALERTS=$(grep -c '"syn_flood_detection"' "$ALERT_FILE" 2>/dev/null | tail -1 || true)
SYN_ALERTS=${SYN_ALERTS:-0}; [[ "$SYN_ALERTS" =~ ^[0-9]+$ ]] || SYN_ALERTS=0

SPIKE_ALERTS=$(grep -c '"packet_rate_spike"' "$ALERT_FILE" 2>/dev/null | tail -1 || true)
SPIKE_ALERTS=${SPIKE_ALERTS:-0}; [[ "$SPIKE_ALERTS" =~ ^[0-9]+$ ]] || SPIKE_ALERTS=0

EXECVE_ALERTS=$(grep -c '"execve_rate_high"' "$ALERT_FILE" 2>/dev/null | tail -1 || true)
EXECVE_ALERTS=${EXECVE_ALERTS:-0}; [[ "$EXECVE_ALERTS" =~ ^[0-9]+$ ]] || EXECVE_ALERTS=0

REAL_ALERTS=$((TOTAL_ALERTS - GRACE_ALERTS))
if [[ $REAL_ALERTS -lt 0 ]]; then REAL_ALERTS=0; fi

echo -e "  ${BOLD}Total Alerts:         ${TOTAL_ALERTS} (${GRACE_ALERTS} warmup + ${REAL_ALERTS} real)${NC}"
echo -e "  ${BOLD}SYN Flood Alerts:     ${SYN_ALERTS}${NC}"
echo -e "  ${BOLD}Packet Spike Alerts:  ${SPIKE_ALERTS}${NC}"
echo -e "  ${BOLD}Execve Rate Alerts:   ${EXECVE_ALERTS}${NC}"
echo ""

# Phase 1 stats
if [[ -f "$PHASE1_LOG" ]]; then
    TOTAL_SNAPSHOTS=$(grep -c "^T=" "$PHASE1_LOG" 2>/dev/null || echo 0)
    MAX_PACKETS=$(grep "^T=" "$PHASE1_LOG" | sed 's/.*packets=\([0-9]*\).*/\1/' | sort -n | tail -1 2>/dev/null || echo 0)
    MAX_SYN=$(grep "^T=" "$PHASE1_LOG" | sed 's/.*syn=\([0-9]*\).*/\1/' | sort -n | tail -1 2>/dev/null || echo 0)
    
    echo -e "  ${BOLD}Phase 1 Statistics:${NC}"
    echo -e "    Snapshots collected: ${TOTAL_SNAPSHOTS}"
    echo -e "    Peak packets/sec:   ${MAX_PACKETS}"
    echo -e "    Peak SYN/sec:       ${MAX_SYN}"
fi

echo ""
echo -e "  ${BOLD}Output Files:${NC}"
echo -e "    Alerts:     $ALERT_FILE"
echo -e "    Phase 1:    $PHASE1_LOG"
echo -e "    Phase 2:    $PHASE2_LOG"
echo ""

# Pass/Fail assessment
echo -e "${BOLD}──────────────────── VERDICT ────────────────────${NC}"
if [[ $REAL_ALERTS -ge 2 ]]; then
    echo -e "  ${GREEN}${BOLD}✅ PASS - zkNIDS detected attacks successfully! (${REAL_ALERTS} real alerts)${NC}"
else
    echo -e "  ${RED}${BOLD}❌ NEEDS REVIEW - Expected ≥2 real alerts, got ${REAL_ALERTS}${NC}"
    echo -e "  ${YELLOW}  Check logs and ensure attacks were strong enough${NC}"
fi
echo ""
echo -e "${BOLD}════════════════════════════════════════════════════════════════${NC}"
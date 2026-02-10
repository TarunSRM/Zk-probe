#!/usr/bin/env bash
###############################################################################
# zkNIDS - Post-Test Validation & Analysis
#
# Run on Machine A AFTER the test completes.
#
# Usage: ./validate_results.sh [ALERT_FILE]
#
# If no file specified, finds the latest test directory automatically.
###############################################################################

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ─── Find Alert File ────────────────────────────────────────────────────────
if [[ -n "${1:-}" ]]; then
    ALERT_FILE="$1"
else
    # Find latest test directory
    LATEST_DIR=$(ls -dt /tmp/zkNIDS_final_test_* 2>/dev/null | head -1)
    if [[ -z "$LATEST_DIR" ]]; then
        echo -e "${RED}[ERROR] No test results found. Specify alert file path.${NC}"
        echo "Usage: $0 /path/to/alerts.jsonl"
        exit 1
    fi
    ALERT_FILE="$LATEST_DIR/alerts.jsonl"
    PHASE1_LOG="$LATEST_DIR/phase1.log"
fi

if [[ ! -f "$ALERT_FILE" ]]; then
    echo -e "${RED}[ERROR] Alert file not found: $ALERT_FILE${NC}"
    exit 1
fi

echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║           zkNIDS - Post-Test Validation Report              ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Alert file: ${ALERT_FILE}"
echo ""

# ─── Alert Count Breakdown ──────────────────────────────────────────────────
TOTAL=$(grep -c "alert_id" "$ALERT_FILE" 2>/dev/null || echo 0)
SYN_FLOOD=$(grep -c "syn_flood_detection" "$ALERT_FILE" 2>/dev/null || echo 0)
PKT_SPIKE=$(grep -c "packet_rate_spike" "$ALERT_FILE" 2>/dev/null || echo 0)
EXECVE=$(grep -c "execve_rate_high" "$ALERT_FILE" 2>/dev/null || echo 0)

echo -e "${BOLD}  ┌─────────────────────────────────────────────────┐${NC}"
echo -e "${BOLD}  │              ALERT BREAKDOWN                    │${NC}"
echo -e "${BOLD}  ├─────────────────────────────────────────────────┤${NC}"
printf "  │  %-30s  %5s        │\n" "Total Alerts" "$TOTAL"
printf "  │  %-30s  %5s        │\n" "syn_flood_detection" "$SYN_FLOOD"
printf "  │  %-30s  %5s        │\n" "packet_rate_spike" "$PKT_SPIKE"
printf "  │  %-30s  %5s        │\n" "execve_rate_high" "$EXECVE"
echo -e "${BOLD}  └─────────────────────────────────────────────────┘${NC}"
echo ""

# ─── Alert Details ───────────────────────────────────────────────────────────
if [[ $TOTAL -gt 0 ]]; then
    echo -e "${BOLD}  ┌─────────────────────────────────────────────────┐${NC}"
    echo -e "${BOLD}  │              ALERT DETAILS                      │${NC}"
    echo -e "${BOLD}  └─────────────────────────────────────────────────┘${NC}"
    echo ""

    ALERT_NUM=0
    while IFS= read -r line; do
        ALERT_NUM=$((ALERT_NUM + 1))
        
        ALERT_TYPE=$(echo "$line" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(d.get('invariant',{}).get('id','unknown'))
" 2>/dev/null || echo "parse_error")

        SEVERITY=$(echo "$line" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(d.get('metadata',{}).get('severity','unknown'))
" 2>/dev/null || echo "unknown")

        OBSERVED=$(echo "$line" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(round(d.get('observation',{}).get('observed_value',0), 4))
" 2>/dev/null || echo "?")

        THRESHOLD=$(echo "$line" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(d.get('observation',{}).get('threshold','?'))
" 2>/dev/null || echo "?")

        PACKETS=$(echo "$line" | python3 -c "
import sys, json
d = json.load(sys.stdin)
snap = d.get('evidence',{}).get('snapshot_current',{})
print(snap.get('total_packets', '?'))
" 2>/dev/null || echo "?")

        SYN_PKTS=$(echo "$line" | python3 -c "
import sys, json
d = json.load(sys.stdin)
snap = d.get('evidence',{}).get('snapshot_current',{})
print(snap.get('syn_packets', '?'))
" 2>/dev/null || echo "?")

        CONFIDENCE=$(echo "$line" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(d.get('metadata',{}).get('confidence','?'))
" 2>/dev/null || echo "?")

        # Color by severity
        case "$SEVERITY" in
            critical) SEV_COLOR="${RED}" ;;
            high)     SEV_COLOR="${YELLOW}" ;;
            *)        SEV_COLOR="${CYAN}" ;;
        esac

        echo -e "  ${BOLD}Alert #${ALERT_NUM}${NC}"
        echo -e "    Type:       ${SEV_COLOR}${ALERT_TYPE}${NC}"
        echo -e "    Severity:   ${SEV_COLOR}${SEVERITY}${NC}"
        echo -e "    Observed:   ${OBSERVED} (threshold: ${THRESHOLD})"
        echo -e "    Packets:    ${PACKETS}  |  SYN: ${SYN_PKTS}"
        echo -e "    Confidence: ${CONFIDENCE}"
        echo ""
    done < <(grep "alert_id" "$ALERT_FILE")
fi

# ─── Phase 1 Statistics ─────────────────────────────────────────────────────
if [[ -f "${PHASE1_LOG:-}" ]]; then
    echo -e "${BOLD}  ┌─────────────────────────────────────────────────┐${NC}"
    echo -e "${BOLD}  │           PHASE 1 CAPTURE STATISTICS            │${NC}"
    echo -e "${BOLD}  └─────────────────────────────────────────────────┘${NC}"
    echo ""

    TOTAL_SNAPSHOTS=$(grep -c "^T=" "$PHASE1_LOG" 2>/dev/null || echo 0)
    TOTAL_PACKETS=$(grep "^T=" "$PHASE1_LOG" | sed 's/.*packets=\([0-9]*\).*/\1/' | awk '{s+=$1} END {print s+0}' 2>/dev/null || echo 0)
    TOTAL_SYN=$(grep "^T=" "$PHASE1_LOG" | sed 's/.*syn=\([0-9]*\).*/\1/' | awk '{s+=$1} END {print s+0}' 2>/dev/null || echo 0)
    MAX_PKT=$(grep "^T=" "$PHASE1_LOG" | sed 's/.*packets=\([0-9]*\).*/\1/' | sort -n | tail -1 2>/dev/null || echo 0)
    MAX_SYN=$(grep "^T=" "$PHASE1_LOG" | sed 's/.*syn=\([0-9]*\).*/\1/' | sort -n | tail -1 2>/dev/null || echo 0)
    
    printf "    %-25s  %s\n" "Total Snapshots:" "$TOTAL_SNAPSHOTS"
    printf "    %-25s  %s\n" "Total Packets Captured:" "$TOTAL_PACKETS"
    printf "    %-25s  %s\n" "Total SYN Packets:" "$TOTAL_SYN"
    printf "    %-25s  %s pkts/sec\n" "Peak Packet Rate:" "$MAX_PKT"
    printf "    %-25s  %s pkts/sec\n" "Peak SYN Rate:" "$MAX_SYN"
    
    if [[ $TOTAL_PACKETS -gt 0 ]]; then
        SYN_RATIO=$(python3 -c "print(round($TOTAL_SYN / $TOTAL_PACKETS * 100, 2))" 2>/dev/null || echo "?")
        printf "    %-25s  %s%%\n" "Overall SYN Ratio:" "$SYN_RATIO"
    fi
    echo ""
fi

# ─── Detection Coverage Matrix ──────────────────────────────────────────────
echo -e "${BOLD}  ┌─────────────────────────────────────────────────────────┐${NC}"
echo -e "${BOLD}  │              DETECTION COVERAGE MATRIX                  │${NC}"
echo -e "${BOLD}  ├──────────────────────┬──────────┬────────────────────── ┤${NC}"
echo -e "${BOLD}  │  Attack Scenario     │ Expected │ Detected             │${NC}"
echo -e "${BOLD}  ├──────────────────────┼──────────┼────────────────────── ┤${NC}"

# Check each expected detection
check_detection() {
    local label="$1"
    local expected="$2"
    local actual="$3"
    
    if [[ $actual -ge $expected ]]; then
        printf "  │  %-20s│  ≥%-5s  │  ${GREEN}%-5s ✓${NC}                │\n" "$label" "$expected" "$actual"
    else
        printf "  │  %-20s│  ≥%-5s  │  ${RED}%-5s ✗${NC}                │\n" "$label" "$expected" "$actual"
    fi
}

check_detection "SYN Flood" "2" "$SYN_FLOOD"
check_detection "Packet Spike" "1" "$PKT_SPIKE"

echo -e "${BOLD}  └──────────────────────┴──────────┴────────────────────── ┘${NC}"
echo ""

# ─── Final Verdict ───────────────────────────────────────────────────────────
echo -e "${BOLD}  ┌─────────────────────────────────────────────────┐${NC}"
echo -e "${BOLD}  │                 FINAL VERDICT                   │${NC}"
echo -e "${BOLD}  └─────────────────────────────────────────────────┘${NC}"
echo ""

PASS_COUNT=0
TOTAL_CHECKS=3

# Check 1: At least 1 alert generated
if [[ $TOTAL -ge 1 ]]; then
    echo -e "  ${GREEN}✅ [PASS] Alert generation working${NC}"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo -e "  ${RED}❌ [FAIL] No alerts generated${NC}"
fi

# Check 2: SYN flood detected
if [[ $SYN_FLOOD -ge 1 ]]; then
    echo -e "  ${GREEN}✅ [PASS] SYN flood detection working${NC}"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo -e "  ${RED}❌ [FAIL] SYN flood not detected${NC}"
fi

# Check 3: Packet spike detected
if [[ $PKT_SPIKE -ge 1 ]]; then
    echo -e "  ${GREEN}✅ [PASS] Packet rate spike detection working${NC}"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo -e "  ${YELLOW}⚠️  [WARN] Packet spike not detected (may need stronger flood)${NC}"
fi

echo ""
echo -e "  ${BOLD}Score: ${PASS_COUNT}/${TOTAL_CHECKS} checks passed${NC}"
echo ""

if [[ $PASS_COUNT -eq $TOTAL_CHECKS ]]; then
    echo -e "  ${GREEN}${BOLD}══════════════════════════════════════════════════${NC}"
    echo -e "  ${GREEN}${BOLD}  ✅ zkNIDS PHASE 1 + PHASE 2: FULLY VALIDATED  ${NC}"
    echo -e "  ${GREEN}${BOLD}  Ready for Phase 3 development!                ${NC}"
    echo -e "  ${GREEN}${BOLD}══════════════════════════════════════════════════${NC}"
elif [[ $PASS_COUNT -ge 2 ]]; then
    echo -e "  ${YELLOW}${BOLD}══════════════════════════════════════════════════${NC}"
    echo -e "  ${YELLOW}${BOLD}  ⚠️  zkNIDS: MOSTLY VALIDATED (minor gaps)     ${NC}"
    echo -e "  ${YELLOW}${BOLD}══════════════════════════════════════════════════${NC}"
else
    echo -e "  ${RED}${BOLD}══════════════════════════════════════════════════${NC}"
    echo -e "  ${RED}${BOLD}  ❌ zkNIDS: NEEDS INVESTIGATION                 ${NC}"
    echo -e "  ${RED}${BOLD}══════════════════════════════════════════════════${NC}"
fi
echo ""

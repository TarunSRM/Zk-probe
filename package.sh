#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# zkNIDS — Package Builder v2.2
# ═══════════════════════════════════════════════════════════════════════════════
#
# Creates two deployment packages:
#   1. zknids-agent.tar.gz       — Sensor host (eBPF + detector + agent)
#   2. zknids-aggregator.tar.gz  — Central server (API + dashboard + ZK prover)
#
# The standalone verifier (zknids-verifier.tar.gz) is built AFTER deployment
# on the aggregator using build-verifier-package.sh (included in aggregator pkg).
#
# Usage:
#   cd /home/ubuntu/projects/zkNIDS
#   bash package.sh
#
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="$HOME"
STAGING="/tmp/zknids-pkg-$$"

echo "═══════════════════════════════════════════════"
echo "  zkNIDS Package Builder v2.2"
echo "═══════════════════════════════════════════════"
echo "  Source: $PROJECT_ROOT"
echo "  Output: $OUT_DIR"
echo

# ══════════════════════════════════════════════════════════════════════════════
# PACKAGE 1: Agent
# ══════════════════════════════════════════════════════════════════════════════
echo "[1/2] Building agent package..."

AGENT_DIR="$STAGING/zknids-agent"
rm -rf "$AGENT_DIR"
mkdir -p "$AGENT_DIR"

# ── install.sh
if [[ -f "$PROJECT_ROOT/distributed/agent/install.sh" ]]; then
    cp "$PROJECT_ROOT/distributed/agent/install.sh" "$AGENT_DIR/"
else
    echo "  ⚠ No install.sh in distributed/agent/"
fi

# ── Phase 1 source (NO vmlinux.h, NO build/)
mkdir -p "$AGENT_DIR/phase1/ebpf/xdp"
mkdir -p "$AGENT_DIR/phase1/ebpf/tracepoints"
mkdir -p "$AGENT_DIR/phase1/userspace/collector"
mkdir -p "$AGENT_DIR/phase1/include"

cp "$PROJECT_ROOT/phase1/Makefile"                                     "$AGENT_DIR/phase1/"
cp "$PROJECT_ROOT/phase1/ebpf/xdp/xdp_counter.bpf.c"                 "$AGENT_DIR/phase1/ebpf/xdp/"
cp "$PROJECT_ROOT/phase1/ebpf/tracepoints/execve_counter.bpf.c"      "$AGENT_DIR/phase1/ebpf/tracepoints/"
cp "$PROJECT_ROOT/phase1/userspace/collector/phase1_loader.c"         "$AGENT_DIR/phase1/userspace/collector/"
# Copy helper headers if they exist
for hdr in "$PROJECT_ROOT"/phase1/include/*.h; do
    [[ -f "$hdr" ]] && [[ "$(basename "$hdr")" != "vmlinux.h" ]] && cp "$hdr" "$AGENT_DIR/phase1/include/"
done
echo "  ✓ Phase 1 source"

# ── Phase 2 source (NO __pycache__, NO egg-info)
mkdir -p "$AGENT_DIR/phase2/zkNIDS_phase2"
mkdir -p "$AGENT_DIR/phase2/config"

cp "$PROJECT_ROOT/phase2/setup.py"                          "$AGENT_DIR/phase2/" 2>/dev/null || true
cp "$PROJECT_ROOT/phase2/requirements.txt"                  "$AGENT_DIR/phase2/" 2>/dev/null || true
cp "$PROJECT_ROOT/phase2/config/invariants.yaml"            "$AGENT_DIR/phase2/config/"

# Copy all python files in the package
for pyf in "$PROJECT_ROOT"/phase2/zkNIDS_phase2/*.py; do
    [[ -f "$pyf" ]] && cp "$pyf" "$AGENT_DIR/phase2/zkNIDS_phase2/"
done
echo "  ✓ Phase 2 source"

# ── Agent script
if [[ -f "$PROJECT_ROOT/distributed/agent/zknids_agent.py" ]]; then
    cp "$PROJECT_ROOT/distributed/agent/zknids_agent.py" "$AGENT_DIR/"
else
    echo "  ⚠ zknids_agent.py not in distributed/agent/"
fi
echo "  ✓ Agent script"

# ── Pipeline scripts
mkdir -p "$AGENT_DIR/bin"
for script in run-pipeline.sh run-phase1.sh run-phase2.sh; do
    if [[ -f "$PROJECT_ROOT/bin/$script" ]]; then
        cp "$PROJECT_ROOT/bin/$script" "$AGENT_DIR/bin/"
    fi
done
echo "  ✓ Pipeline scripts"

# ── Create tarball
cd "$STAGING"
tar czf "$OUT_DIR/zknids-agent.tar.gz" zknids-agent/
AGENT_SIZE=$(du -h "$OUT_DIR/zknids-agent.tar.gz" | cut -f1)
echo "  ✓ $OUT_DIR/zknids-agent.tar.gz ($AGENT_SIZE)"

# ══════════════════════════════════════════════════════════════════════════════
# PACKAGE 2: Aggregator
# ══════════════════════════════════════════════════════════════════════════════
echo
echo "[2/2] Building aggregator package..."

AGG_DIR="$STAGING/zknids-aggregator"
rm -rf "$AGG_DIR"
mkdir -p "$AGG_DIR"

# ── install.sh
if [[ -f "$PROJECT_ROOT/distributed/aggregator/install.sh" ]]; then
    cp "$PROJECT_ROOT/distributed/aggregator/install.sh" "$AGG_DIR/"
fi

# ── server.py
cp "$PROJECT_ROOT/distributed/aggregator/server.py" "$AGG_DIR/"
echo "  ✓ server.py"

# ── Dashboard
mkdir -p "$AGG_DIR/dashboard"
if [[ -f "$PROJECT_ROOT/distributed/aggregator/dashboard/index.html" ]]; then
    cp "$PROJECT_ROOT/distributed/aggregator/dashboard/index.html" "$AGG_DIR/dashboard/"
fi
echo "  ✓ dashboard/index.html"

# ── test_e2e.py
for f in "$PROJECT_ROOT/phase3/test_e2e.py" "$PROJECT_ROOT/phase3/test_e3e.py"; do
    if [[ -f "$f" ]]; then
        cp "$f" "$AGG_DIR/test_e2e.py"
        break
    fi
done
echo "  ✓ test_e2e.py"

# ── Verifier package builder
if [[ -f "$PROJECT_ROOT/distributed/aggregator/build-verifier-package.sh" ]]; then
    cp "$PROJECT_ROOT/distributed/aggregator/build-verifier-package.sh" "$AGG_DIR/"
fi
echo "  ✓ build-verifier-package.sh"

# ── Phase 3 Rust source (NO target/, NO keys/)
mkdir -p "$AGG_DIR/phase3"

cp "$PROJECT_ROOT/phase3/Cargo.toml"   "$AGG_DIR/phase3/"
cp "$PROJECT_ROOT/phase3/Cargo.lock"   "$AGG_DIR/phase3/" 2>/dev/null || true

# Copy src/ correctly (avoid src/src nesting)
if [[ -d "$PROJECT_ROOT/phase3/src" ]]; then
    cp -r "$PROJECT_ROOT/phase3/src" "$AGG_DIR/phase3/"
fi

if [[ -d "$PROJECT_ROOT/phase3/benches" ]]; then
    cp -r "$PROJECT_ROOT/phase3/benches" "$AGG_DIR/phase3/"
fi
echo "  ✓ Phase 3 Rust source"

# ── Create tarball
cd "$STAGING"
tar czf "$OUT_DIR/zknids-aggregator.tar.gz" zknids-aggregator/
AGG_SIZE=$(du -h "$OUT_DIR/zknids-aggregator.tar.gz" | cut -f1)
echo "  ✓ $OUT_DIR/zknids-aggregator.tar.gz ($AGG_SIZE)"

# NOTE: Standalone verifier package (zknids-verifier.tar.gz) is NOT built here.
# It is built on the aggregator AFTER deployment and proof generation using:
#   bash build-verifier-package.sh
# The build-verifier-package.sh script is included inside zknids-aggregator.tar.gz.

# ── Cleanup ──
rm -rf "$STAGING"

echo
echo "═══════════════════════════════════════════════"
echo "  ✓ All packages built"
echo "═══════════════════════════════════════════════"
echo
echo "  Agent:      $OUT_DIR/zknids-agent.tar.gz"
echo "  Aggregator: $OUT_DIR/zknids-aggregator.tar.gz"
echo
echo "  Deploy:"
echo "  1. Aggregator → sudo bash install.sh"
echo "  2. Agents     → sudo bash install.sh --api-key <KEY>"
echo "  3. After demo → bash build-verifier-package.sh"
echo "     (creates zknids-verifier.tar.gz for reviewers)"
echo "═══════════════════════════════════════════════"
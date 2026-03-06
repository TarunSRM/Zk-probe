#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# zkNIDS Aggregator — Production Install Script v2.2
# ═══════════════════════════════════════════════════════════════════════════════
#
# Installs the FULL aggregator stack on the central server:
#   Step 1: System prerequisites (python3, pip, Rust toolchain)
#   Step 2: Server — install server.py + dashboard + verifier builder
#   Step 3: Phase 3 — clean cargo build + generate circuit params
#   Step 4: API keys — first-run generation, plaintext saved to file
#   Step 5: Systemd services (aggregator + phase3-prover)
#
# Usage:
#   sudo bash install.sh
#   sudo bash install.sh --port 8080 --skip-rust
#
# Requirements: Ubuntu 22.04+, 2GB+ RAM (for Rust compilation)
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Paths ─────────────────────────────────────────────────────────────────────
INSTALL_DIR="/opt/zknids"
DATA_DIR="/var/lib/zknids"
LOG_DIR="$DATA_DIR/logs"
PROOF_DIR="$DATA_DIR/proofs"
KEY_DIR="$INSTALL_DIR/phase3/keys"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── Defaults ──────────────────────────────────────────────────────────────────
PORT=8080
BIND_HOST="0.0.0.0"
SKIP_RUST=false

# ── Parse CLI args ────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        --port)        PORT="$2"; shift 2 ;;
        --host)        BIND_HOST="$2"; shift 2 ;;
        --skip-rust)   SKIP_RUST=true; shift ;;
        --help|-h)
            echo "Usage: sudo bash install.sh [OPTIONS]"
            echo "  --port PORT       Listen port (default: 8080)"
            echo "  --host HOST       Bind address (default: 0.0.0.0)"
            echo "  --skip-rust       Skip Rust toolchain install (if already present)"
            exit 0 ;;
        *) echo "Unknown: $1"; exit 1 ;;
    esac
done

# ── Root check ────────────────────────────────────────────────────────────────
echo "═══════════════════════════════════════════════════════════"
echo "  zkNIDS Aggregator — Production Installer v2.2"
echo "═══════════════════════════════════════════════════════════"
echo

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: Run as root: sudo bash install.sh"
    exit 1
fi

# Detect real user (for rustup, which shouldn't run as root)
REAL_USER="${SUDO_USER:-$(whoami)}"
REAL_HOME=$(eval echo "~$REAL_USER")

# ══════════════════════════════════════════════════════════════════════════════
# STEP 1: System Prerequisites
# ══════════════════════════════════════════════════════════════════════════════
echo "[1/5] Installing system prerequisites..."

apt-get update -qq

# Python deps for server.py
PKGS="python3 python3-pip python3-venv pkg-config libssl-dev build-essential"
for pkg in $PKGS; do
    if ! dpkg -s "$pkg" &>/dev/null 2>&1; then
        echo "  Installing $pkg..."
        apt-get install -y -qq "$pkg" 2>/dev/null || true
    fi
done

# Python packages for server
pip3 install fastapi uvicorn python-multipart requests --break-system-packages -q 2>/dev/null \
    || pip3 install fastapi uvicorn python-multipart requests -q
echo "  ✓ Python + FastAPI installed"

# ── Rust toolchain ──
if [[ "$SKIP_RUST" == true ]]; then
    echo "  Skipping Rust install (--skip-rust)"
elif command -v cargo &>/dev/null; then
    RUST_VER=$(rustc --version 2>/dev/null || echo "unknown")
    echo "  ✓ Rust already installed: $RUST_VER"
else
    echo "  Installing Rust toolchain via rustup..."
    su - "$REAL_USER" -c 'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable'
    export PATH="$REAL_HOME/.cargo/bin:$PATH"
    echo "  ✓ Rust installed: $(rustc --version)"
fi

# Ensure cargo is in PATH
if [[ -f "$REAL_HOME/.cargo/env" ]]; then
    source "$REAL_HOME/.cargo/env" 2>/dev/null || true
fi
export PATH="$REAL_HOME/.cargo/bin:$PATH"

echo "  ✓ All prerequisites installed"

# ══════════════════════════════════════════════════════════════════════════════
# STEP 2: Server + Dashboard + Tools
# ══════════════════════════════════════════════════════════════════════════════
echo
echo "[2/5] Installing aggregator server + dashboard..."

mkdir -p "$INSTALL_DIR"
mkdir -p "$DATA_DIR" "$LOG_DIR" "$PROOF_DIR"

# server.py
cp "$SCRIPT_DIR/server.py" "$INSTALL_DIR/server.py"
chmod 644 "$INSTALL_DIR/server.py"
echo "  ✓ $INSTALL_DIR/server.py"

# Dashboard
mkdir -p "$INSTALL_DIR/dashboard"
if [[ -f "$SCRIPT_DIR/dashboard/index.html" ]]; then
    cp "$SCRIPT_DIR/dashboard/index.html" "$INSTALL_DIR/dashboard/"
    echo "  ✓ $INSTALL_DIR/dashboard/index.html"
else
    echo "  ⚠ No dashboard/index.html in package"
fi

# Test suite
if [[ -f "$SCRIPT_DIR/test_e2e.py" ]]; then
    cp "$SCRIPT_DIR/test_e2e.py" "$INSTALL_DIR/"
    echo "  ✓ $INSTALL_DIR/test_e2e.py"
fi

# Verifier package builder (run after demo to create reviewer package)
if [[ -f "$SCRIPT_DIR/build-verifier-package.sh" ]]; then
    cp "$SCRIPT_DIR/build-verifier-package.sh" "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/build-verifier-package.sh"
    echo "  ✓ $INSTALL_DIR/build-verifier-package.sh"
fi

# ══════════════════════════════════════════════════════════════════════════════
# STEP 3: Phase 3 — Clean Rust Build + Circuit Params
# ══════════════════════════════════════════════════════════════════════════════
echo
echo "[3/5] Building Phase 3 (ZK proof system)..."

if [[ -d "$SCRIPT_DIR/phase3/src" && -f "$SCRIPT_DIR/phase3/Cargo.toml" ]]; then
    # Copy Rust source (clean — no target/, no keys/, no proofs/)
    mkdir -p "$INSTALL_DIR/phase3"
    cp "$SCRIPT_DIR/phase3/Cargo.toml" "$INSTALL_DIR/phase3/"
    cp "$SCRIPT_DIR/phase3/Cargo.lock" "$INSTALL_DIR/phase3/" 2>/dev/null || true
    cp -r "$SCRIPT_DIR/phase3/src" "$INSTALL_DIR/phase3/"

    if [[ -d "$SCRIPT_DIR/phase3/benches" ]]; then
        cp -r "$SCRIPT_DIR/phase3/benches" "$INSTALL_DIR/phase3/"
    fi

    cd "$INSTALL_DIR/phase3"

    echo "  Compiling Phase 3 (this may take 5-10 minutes)..."
    su - "$REAL_USER" -c "cd $INSTALL_DIR/phase3 && cargo build --release 2>&1" | tail -5

    # Verify binaries
    BINS_OK=true
    for bin in phase3-prover phase3-setup phase3-verify; do
        if [[ -f "target/release/$bin" ]]; then
            echo "  ✓ $bin ($(du -h target/release/$bin | cut -f1))"
        else
            echo "  ✗ $bin NOT FOUND"
            BINS_OK=false
        fi
    done

    if [[ "$BINS_OK" == false ]]; then
        echo "  ERROR: Phase 3 build failed."
        echo "  Retry: cd $INSTALL_DIR/phase3 && cargo build --release"
        exit 1
    fi

    # Generate circuit parameters
    echo
    echo "  Generating deterministic circuit parameters..."
    mkdir -p "$KEY_DIR"
    su - "$REAL_USER" -c "cd $INSTALL_DIR/phase3 && ./target/release/phase3-setup --all --output-dir $KEY_DIR 2>&1" | tail -10

    for circuit in ratio_check_v1 rate_check_v1 deviation_check_v1; do
        if [[ -f "$KEY_DIR/${circuit}.params" ]]; then
            echo "  ✓ ${circuit}.params ($(du -h $KEY_DIR/${circuit}.params | cut -f1))"
        else
            echo "  ✗ ${circuit}.params NOT FOUND"
        fi
    done
else
    echo "  ⚠ No phase3/src/ in package. Skipping Rust build."
fi

# ══════════════════════════════════════════════════════════════════════════════
# STEP 4: API Key Generation
# ══════════════════════════════════════════════════════════════════════════════
echo
echo "[4/5] Generating API keys..."

API_KEYS_FILE="$DATA_DIR/api_keys.json"
PLAINTEXT_FILE="$DATA_DIR/api_keys_plaintext.txt"

if [[ -f "$API_KEYS_FILE" ]]; then
    echo "  API keys already exist at $API_KEYS_FILE"
    if [[ -f "$PLAINTEXT_FILE" ]]; then
        echo "  Plaintext: $PLAINTEXT_FILE"
    else
        echo "  ⚠ Plaintext not found. To regenerate:"
        echo "    rm $API_KEYS_FILE && restart server"
    fi
else
    echo "  Starting server briefly to generate keys..."

    # Server writes api_keys_plaintext.txt directly on first run
    timeout 8 python3 "$INSTALL_DIR/server.py" \
        --port 19999 --db "$DATA_DIR/aggregator.db" \
        --data-dir "$DATA_DIR" \
        > /dev/null 2>&1 &
    SERVER_PID=$!
    sleep 5
    kill $SERVER_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true

    if [[ -f "$PLAINTEXT_FILE" ]]; then
        echo "  ✓ API keys generated: $PLAINTEXT_FILE"
    elif [[ -f "$API_KEYS_FILE" ]]; then
        echo "  ⚠ Hashed keys exist but plaintext file missing"
        echo "    Delete $API_KEYS_FILE and restart to regenerate"
    else
        echo "  ⚠ Key generation may have failed"
        echo "    Start manually: python3 $INSTALL_DIR/server.py --port 8080"
    fi
fi

# Read keys for Phase 3 service config
AGENT_KEY=""
if [[ -f "$PLAINTEXT_FILE" ]]; then
    AGENT_KEY=$(grep 'Agent API Key:' "$PLAINTEXT_FILE" 2>/dev/null | cut -d: -f2 | tr -d ' ' || echo "")
fi

# ══════════════════════════════════════════════════════════════════════════════
# STEP 5: Systemd Services
# ══════════════════════════════════════════════════════════════════════════════
echo
echo "[5/5] Installing systemd services..."

# ── Service 1: Aggregator (FastAPI server) ──
cat > /etc/systemd/system/zknids-aggregator.service <<EOF
[Unit]
Description=zkNIDS Aggregator — Alert Collection + Dashboard v2.2
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/server.py --port ${PORT} --host ${BIND_HOST} --db ${DATA_DIR}/aggregator.db --data-dir ${DATA_DIR}
WorkingDirectory=${INSTALL_DIR}
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=zknids-aggregator

[Install]
WantedBy=multi-user.target
EOF
echo "  ✓ zknids-aggregator.service"

# ── Service 2: Phase 3 Prover (watch mode) ──
cat > /etc/systemd/system/zknids-phase3.service <<EOF
[Unit]
Description=zkNIDS Phase 3 — ZK Proof Generator (watch mode)
After=zknids-aggregator.service
Requires=zknids-aggregator.service

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/phase3/target/release/phase3-prover --key-dir ${KEY_DIR} --aggregator http://127.0.0.1:${PORT} --watch --interval 5
Environment=ZKNIDS_API_KEY=${AGENT_KEY}
WorkingDirectory=${INSTALL_DIR}/phase3
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=zknids-phase3

[Install]
WantedBy=multi-user.target
EOF
echo "  ✓ zknids-phase3.service"

if [[ -z "$AGENT_KEY" ]]; then
    echo
    echo "  ⚠ Phase 3 API key not set automatically."
    echo "    Set it manually:"
    echo "      sudo systemctl edit zknids-phase3"
    echo "      [Service]"
    echo "      Environment=ZKNIDS_API_KEY=<agent-key>"
fi

systemctl daemon-reload

# ══════════════════════════════════════════════════════════════════════════════
# DONE — Print Summary + API Keys
# ══════════════════════════════════════════════════════════════════════════════
echo
echo "═══════════════════════════════════════════════════════════"
echo "  ✓ zkNIDS Aggregator — Installation Complete (v2.2)"
echo "═══════════════════════════════════════════════════════════"
echo
echo "  Install dir:   $INSTALL_DIR"
echo "  Data dir:      $DATA_DIR"
echo "  Dashboard:     http://$(hostname -I | awk '{print $1}'):${PORT}"
echo

# Print API keys
if [[ -f "$PLAINTEXT_FILE" ]]; then
    echo "┌─────────────────────────────────────────────────────────┐"
    echo "│                    API KEYS                             │"
    echo "├─────────────────────────────────────────────────────────┤"
    cat "$PLAINTEXT_FILE"
    echo "└─────────────────────────────────────────────────────────┘"
    echo
    echo "  Use Agent API Key when installing agents:"
    echo "    sudo bash install.sh --api-key <AGENT_KEY>"
    echo
fi

echo "  Start services:"
echo "    sudo systemctl enable --now zknids-aggregator"
echo "    sudo systemctl enable --now zknids-phase3"
echo
echo "  After demo (create verifier package for reviewers):"
echo "    bash $INSTALL_DIR/build-verifier-package.sh"
echo
echo "  Check status:"
echo "    journalctl -u zknids-aggregator -f"
echo "    journalctl -u zknids-phase3 -f"
echo "═══════════════════════════════════════════════════════════"
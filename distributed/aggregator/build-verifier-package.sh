#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# zkNIDS Standalone Verifier Package Builder
# ═══════════════════════════════════════════════════════════════════════════════
#
# Run on the aggregator to create a self-contained verifier package.
# The package contains:
#   - phase3-verify binary (statically linked)
#   - Sample proof files for testing
#   - README with verification instructions
#
# Output: ~/zknids-verifier.tar.gz
#
# A reviewer downloads this, extracts it, and can verify any proof
# with ZERO trust assumptions — no keys, no setup, no network access.
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

VERIFY_BIN="/opt/zknids/phase3/target/release/phase3-verify"
PROOF_DIR="/var/lib/zknids/proofs"
PKG_DIR="/tmp/zknids-verifier"
OUTPUT="$HOME/zknids-verifier.tar.gz"

echo "═══════════════════════════════════════════════════════"
echo "  zkNIDS Standalone Verifier Package Builder"
echo "═══════════════════════════════════════════════════════"

# ── Check binary exists ──
if [[ ! -f "$VERIFY_BIN" ]]; then
    echo "ERROR: phase3-verify not found at $VERIFY_BIN"
    echo "  Run 'cargo build --release' in /opt/zknids/phase3 first."
    exit 1
fi

# ── Clean and create package directory ──
rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR/proofs"

# ── Copy binary ──
cp "$VERIFY_BIN" "$PKG_DIR/phase3-verify"
chmod +x "$PKG_DIR/phase3-verify"
echo "  ✓ Binary: phase3-verify ($(du -h "$PKG_DIR/phase3-verify" | cut -f1))"

# ── Copy sample proofs ──
PROOF_COUNT=0
if [[ -d "$PROOF_DIR" ]]; then
    for f in "$PROOF_DIR"/proof_*.json; do
        [[ -f "$f" ]] || continue
        cp "$f" "$PKG_DIR/proofs/"
        PROOF_COUNT=$((PROOF_COUNT + 1))
    done
fi
echo "  ✓ Sample proofs: $PROOF_COUNT files"

# ── Create verify-all.sh convenience script ──
cat > "$PKG_DIR/verify-all.sh" <<'SCRIPT'
#!/bin/bash
# Verify all proof files in the proofs/ directory
echo "═══════════════════════════════════════════════════════"
echo "  zkNIDS Batch Proof Verification"
echo "═══════════════════════════════════════════════════════"
echo ""

DIR="$(cd "$(dirname "$0")" && pwd)"
VERIFY="$DIR/phase3-verify"

if [[ ! -x "$VERIFY" ]]; then
    echo "ERROR: phase3-verify binary not found or not executable"
    exit 1
fi

TOTAL=0
VALID=0
INVALID=0

for proof in "$DIR/proofs"/proof_*.json; do
    [[ -f "$proof" ]] || continue
    TOTAL=$((TOTAL + 1))
    NAME=$(basename "$proof")

    RESULT=$("$VERIFY" --proof "$proof" --json 2>/dev/null)
    if echo "$RESULT" | grep -q '"valid": true'; then
        echo "  ✓ $NAME — VALID"
        VALID=$((VALID + 1))
    else
        echo "  ✗ $NAME — INVALID"
        INVALID=$((INVALID + 1))
    fi
done

echo ""
echo "──────────────────────────────────────────"
echo "  Total:   $TOTAL"
echo "  Valid:   $VALID ✓"
echo "  Invalid: $INVALID ✗"
echo "──────────────────────────────────────────"

if [[ $INVALID -gt 0 ]]; then
    exit 1
fi
SCRIPT
chmod +x "$PKG_DIR/verify-all.sh"

# ── Create verify-single.sh convenience script ──
cat > "$PKG_DIR/verify-single.sh" <<'SCRIPT'
#!/bin/bash
# Verify a single proof file
# Usage: ./verify-single.sh proofs/proof_xxx.json

if [[ -z "$1" ]]; then
    echo "Usage: $0 <proof_file.json>"
    exit 1
fi

DIR="$(cd "$(dirname "$0")" && pwd)"
"$DIR/phase3-verify" --proof "$1"
SCRIPT
chmod +x "$PKG_DIR/verify-single.sh"

# ── Create README ──
cat > "$PKG_DIR/README.txt" <<'README'
═══════════════════════════════════════════════════════════════════════
  zkNIDS Standalone Verifier
  Zero-Trust Proof Verification — No Setup Required
═══════════════════════════════════════════════════════════════════════

WHAT IS THIS?
  This package lets you independently verify zkNIDS alert proofs.
  You need NOTHING else — no keys, no parameters, no network access,
  no trust in the system operator.

  Each ProofBundle is self-contained: it embeds the circuit parameters
  (base64-encoded). The verifier reconstructs the verification key
  deterministically from these parameters and an empty circuit, then
  verifies the PLONK+IPA proof.

HOW TO USE:

  1. Verify all included proofs:
     $ ./verify-all.sh

  2. Verify a single proof:
     $ ./verify-single.sh proofs/proof_abc123.json

  3. Verify with detailed JSON output:
     $ ./phase3-verify --proof proofs/proof_abc123.json --json

  4. Verify a batch directory:
     $ ./phase3-verify --dir proofs/ --json

WHAT THE OUTPUT MEANS:

  ✓ VALID    — The proof is cryptographically sound. The invariant
                violation was genuinely detected by correct computation.
                The prover CANNOT have forged this result.

  ✗ INVALID  — The proof failed verification. Either the proof was
                tampered with, or it was generated incorrectly.

WHAT YOU CAN TRUST:

  - The PLONK+IPA proof system has NO trusted setup.
  - Parameters are DETERMINISTIC — you can regenerate them yourself
    by compiling phase3-setup from source and running it.
  - The proof embeds its own parameters, so the verifier needs
    nothing from the system operator.

WHAT THE PROOF HIDES (Privacy):

  The proof does NOT reveal:
  - Raw packet counts, byte counts, SYN counts
  - IP addresses, port numbers
  - Individual snapshot data
  - Flow hashes or connection details

  The proof DOES reveal:
  - Which invariant was evaluated
  - The threshold value
  - Whether the invariant was violated (true/false)
  - Detector version hash

TECHNICAL DETAILS:

  Proving System:  PLONK + IPA (Inner Product Argument)
  Curve:           Pasta (Pallas/Vesta)
  Library:         halo2 (Zcash / Electric Coin Company)
  Trusted Setup:   NONE
  Proof Size:      ~500-800 bytes
  Verify Time:     ~10-30ms per proof

═══════════════════════════════════════════════════════════════════════
README

echo "  ✓ README.txt"
echo "  ✓ verify-all.sh"
echo "  ✓ verify-single.sh"

# ── Package ──
cd /tmp
tar czf "$OUTPUT" -C /tmp zknids-verifier/
rm -rf "$PKG_DIR"

SIZE=$(du -h "$OUTPUT" | cut -f1)
echo ""
echo "═══════════════════════════════════════════════════════"
echo "  ✓ Package created: $OUTPUT ($SIZE)"
echo "═══════════════════════════════════════════════════════"
echo ""
echo "  A reviewer can verify proofs with:"
echo "    tar xzf zknids-verifier.tar.gz"
echo "    cd zknids-verifier"
echo "    ./verify-all.sh"
echo ""
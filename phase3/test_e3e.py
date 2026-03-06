#!/usr/bin/env python3
"""
zkNIDS Phase 3 — End-to-End Demo Test
======================================

Runs the full pipeline on localhost:
  1. Starts the aggregator server
  2. Injects 8 synthetic alerts (one per invariant, all 3 circuit templates)
  3. Runs phase3-prover to generate ZK proofs
  4. Runs phase3-verify on saved proofs
  5. Queries aggregator to confirm proof_status = verified

Usage:
  cd /home/ubuntu/projects/zkNIDS/phase3
  python3 test_e2e.py
"""

import json
import os
import signal
import subprocess
import sys
import time
import uuid

import requests

AGGREGATOR_URL = "http://127.0.0.1:8080"
HEADERS = {"Content-Type": "application/json"}
PHASE3_DIR = os.path.dirname(os.path.abspath(__file__))
PROVER_BIN = os.path.join(PHASE3_DIR, "target/release/phase3-prover")
VERIFY_BIN = os.path.join(PHASE3_DIR, "target/release/phase3-verify")
KEY_DIR = os.path.join(PHASE3_DIR, "keys")
PROOF_DIR = os.path.join(PHASE3_DIR, "proofs_test")
SERVER_PY = "/home/ubuntu/projects/zkNIDS/distributed/aggregator/server.py"
DB_PATH = "/tmp/zknids_test.db"
DATA_DIR = "/tmp/zknids_test_data"

# ─── 8 synthetic alerts covering all invariants ─────────────────────────

ALERTS = [
    # ratio_check_v1 (2 invariants)
    {
        "alert_id": str(uuid.uuid4()),
        "invariant": {
            "id": "syn_flood_detection",
            "type": "ratio",
            "category": "network_flood",
            "circuit_template": "ratio_check_v1",
            "description": "SYN/total packet ratio exceeds threshold"
        },
        "observation": {
            "observed_value": 0.95,
            "threshold": 0.5,
            "threshold_operator": "greater_than",
            "result": True,
            "timestamp_ns": int(time.time_ns()),
            "window_duration_ns": 5_000_000_000
        },
        "evidence": {
            "snapshot_current": {"hash": "abc123", "flow_hash": "def456"}
        },
        "provenance": {
            "phase1_detector_hash": "p1hash001",
            "phase2_detector_hash": "p2hash001",
            "flow_hash": "flow001"
        },
        "dashboard_fields": {
            "host_id": "host-A",
            "host_ip": "10.0.0.10",
            "hostname": "sensor-alpha",
            "interface": "eth0",
            "total_packets": 4500,
            "syn_packets": 4275
        },
        "metadata": {"severity": "critical"}
    },
    {
        "alert_id": str(uuid.uuid4()),
        "invariant": {
            "id": "fragment_abuse_detection",
            "type": "ratio",
            "category": "evasion",
            "circuit_template": "ratio_check_v1",
            "description": "Fragment ratio exceeds threshold"
        },
        "observation": {
            "observed_value": 0.85,
            "threshold": 0.3,
            "threshold_operator": "greater_than",
            "result": True,
            "timestamp_ns": int(time.time_ns()),
            "window_duration_ns": 5_000_000_000
        },
        "evidence": {
            "snapshot_current": {"hash": "abc124", "flow_hash": "def457"}
        },
        "provenance": {
            "phase1_detector_hash": "p1hash002",
            "phase2_detector_hash": "p2hash002",
            "flow_hash": "flow002"
        },
        "dashboard_fields": {
            "host_id": "host-A",
            "host_ip": "10.0.0.10",
            "hostname": "sensor-alpha",
            "interface": "eth0",
            "total_packets": 3000,
            "syn_packets": 100
        },
        "metadata": {"severity": "high"}
    },
    # rate_check_v1 (3 invariants)
    {
        "alert_id": str(uuid.uuid4()),
        "invariant": {
            "id": "execve_rate_high",
            "type": "rate",
            "category": "host_behavior",
            "circuit_template": "rate_check_v1",
            "description": "Execve syscall rate exceeds threshold"
        },
        "observation": {
            "observed_value": 150.0,
            "threshold": 100.0,
            "threshold_operator": "greater_than",
            "result": True,
            "timestamp_ns": int(time.time_ns()),
            "window_duration_ns": 1_000_000_000
        },
        "evidence": {
            "snapshot_current": {"hash": "abc125", "flow_hash": "def458"}
        },
        "provenance": {
            "phase1_detector_hash": "p1hash003",
            "phase2_detector_hash": "p2hash003",
            "flow_hash": "flow003"
        },
        "dashboard_fields": {
            "host_id": "host-B",
            "host_ip": "10.0.0.20",
            "hostname": "sensor-beta",
            "interface": "eth0"
        },
        "metadata": {"severity": "high"}
    },
    {
        "alert_id": str(uuid.uuid4()),
        "invariant": {
            "id": "port_scan_detection",
            "type": "rate",
            "category": "reconnaissance",
            "circuit_template": "rate_check_v1",
            "description": "Unique port access rate exceeds threshold"
        },
        "observation": {
            "observed_value": 1848.0,
            "threshold": 50.0,
            "threshold_operator": "greater_than",
            "result": True,
            "timestamp_ns": int(time.time_ns()),
            "window_duration_ns": 1_000_000_000
        },
        "evidence": {
            "snapshot_current": {"hash": "abc126", "flow_hash": "def459"}
        },
        "provenance": {
            "phase1_detector_hash": "p1hash004",
            "phase2_detector_hash": "p2hash004",
            "flow_hash": "flow004"
        },
        "dashboard_fields": {
            "host_id": "host-B",
            "host_ip": "10.0.0.20",
            "hostname": "sensor-beta",
            "interface": "eth0"
        },
        "metadata": {"severity": "critical"}
    },
    {
        "alert_id": str(uuid.uuid4()),
        "invariant": {
            "id": "malformed_header_detection",
            "type": "rate",
            "category": "evasion",
            "circuit_template": "rate_check_v1",
            "description": "Malformed packet rate exceeds threshold"
        },
        "observation": {
            "observed_value": 25.0,
            "threshold": 5.0,
            "threshold_operator": "greater_than",
            "result": True,
            "timestamp_ns": int(time.time_ns()),
            "window_duration_ns": 1_000_000_000
        },
        "evidence": {
            "snapshot_current": {"hash": "abc127", "flow_hash": "def460"}
        },
        "provenance": {
            "phase1_detector_hash": "p1hash005",
            "phase2_detector_hash": "p2hash005",
            "flow_hash": "flow005"
        },
        "dashboard_fields": {
            "host_id": "host-A",
            "host_ip": "10.0.0.10",
            "hostname": "sensor-alpha",
            "interface": "eth0"
        },
        "metadata": {"severity": "medium"}
    },
    # deviation_check_v1 (3 invariants)
    {
        "alert_id": str(uuid.uuid4()),
        "invariant": {
            "id": "packet_rate_spike",
            "type": "deviation",
            "category": "anomaly",
            "circuit_template": "deviation_check_v1",
            "description": "Packet rate exceeds baseline multiplier"
        },
        "observation": {
            "observed_value": 17770.0,
            "threshold": 3.0,
            "threshold_operator": "greater_than",
            "result": True,
            "timestamp_ns": int(time.time_ns()),
            "window_duration_ns": 5_000_000_000
        },
        "evidence": {
            "snapshot_current": {"hash": "abc128", "flow_hash": "def461"}
        },
        "provenance": {
            "phase1_detector_hash": "p1hash006",
            "phase2_detector_hash": "p2hash006",
            "flow_hash": "flow006"
        },
        "dashboard_fields": {
            "host_id": "host-A",
            "host_ip": "10.0.0.10",
            "hostname": "sensor-alpha",
            "interface": "eth0",
            "packet_rate": 17770.0
        },
        "metadata": {"severity": "critical"}
    },
    {
        "alert_id": str(uuid.uuid4()),
        "invariant": {
            "id": "packet_size_anomaly",
            "type": "deviation",
            "category": "anomaly",
            "circuit_template": "deviation_check_v1",
            "description": "Packet size variance exceeds baseline"
        },
        "observation": {
            "observed_value": 200.0,
            "threshold": 15.0,
            "threshold_operator": "greater_than",
            "result": True,
            "timestamp_ns": int(time.time_ns()),
            "window_duration_ns": 5_000_000_000
        },
        "evidence": {
            "snapshot_current": {"hash": "abc129", "flow_hash": "def462"}
        },
        "provenance": {
            "phase1_detector_hash": "p1hash007",
            "phase2_detector_hash": "p2hash007",
            "flow_hash": "flow007"
        },
        "dashboard_fields": {
            "host_id": "host-B",
            "host_ip": "10.0.0.20",
            "hostname": "sensor-beta",
            "interface": "eth0"
        },
        "metadata": {"severity": "high"}
    },
    {
        "alert_id": str(uuid.uuid4()),
        "invariant": {
            "id": "flow_churn_detection",
            "type": "deviation",
            "category": "anomaly",
            "circuit_template": "deviation_check_v1",
            "description": "Flow churn rate exceeds baseline"
        },
        "observation": {
            "observed_value": 50.0,
            "threshold": 5.0,
            "threshold_operator": "greater_than",
            "result": True,
            "timestamp_ns": int(time.time_ns()),
            "window_duration_ns": 5_000_000_000
        },
        "evidence": {
            "snapshot_current": {"hash": "abc130", "flow_hash": "def463"}
        },
        "provenance": {
            "phase1_detector_hash": "p1hash008",
            "phase2_detector_hash": "p2hash008",
            "flow_hash": "flow008"
        },
        "dashboard_fields": {
            "host_id": "host-B",
            "host_ip": "10.0.0.20",
            "hostname": "sensor-beta",
            "interface": "eth0",
            "flow_count": 500
        },
        "metadata": {"severity": "high"}
    },
]


def wait_for_server(url, timeout=15):
    """Wait for the aggregator to be reachable."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(f"{url}/api/stats", timeout=2)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def main():
    import argparse
    ap = argparse.ArgumentParser(description="zkNIDS Phase 3 E2E Test")
    ap.add_argument('--keep-server', '-k', action='store_true',
                    help='Keep aggregator running after test. Press Ctrl+C to stop.')
    ap.add_argument('--no-clean', action='store_true',
                    help='Do not delete test DB on exit')
    args = ap.parse_args()

    print("=" * 60)
    print("  zkNIDS Phase 3 — End-to-End Pipeline Test")
    print("=" * 60)
    print()

    # Check binaries exist
    for b in [PROVER_BIN, VERIFY_BIN]:
        if not os.path.exists(b):
            print(f"ERROR: Binary not found: {b}")
            print("Run: cargo build --release")
            sys.exit(1)

    # Check keys exist
    for name in ["ratio_check_v1", "rate_check_v1", "deviation_check_v1"]:
        p = os.path.join(KEY_DIR, f"{name}.params")
        if not os.path.exists(p):
            print(f"ERROR: Params not found: {p}")
            print("Run: ./target/release/phase3-setup --all --output-dir keys/")
            sys.exit(1)

    # ── Clean stale test data ────────────────────────────
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
        print("  Removed stale test DB")
    if os.path.exists(DATA_DIR):
        import shutil
        shutil.rmtree(DATA_DIR, ignore_errors=True)

    # Clean proof output dir
    os.makedirs(PROOF_DIR, exist_ok=True)
    for f in os.listdir(PROOF_DIR):
        os.remove(os.path.join(PROOF_DIR, f))

    # ── Step 1: Start aggregator (--no-auth for testing) ──
    print("[1/5] Starting aggregator server (--no-auth)...")

    # Kill any existing aggregator on port 8080
    os.system("fuser -k 8080/tcp 2>/dev/null")
    time.sleep(1)

    server_env = os.environ.copy()
    server_proc = subprocess.Popen(
        [sys.executable, SERVER_PY, "--port", "8080", "--db", DB_PATH,
         "--data-dir", DATA_DIR, "--no-auth"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=server_env,
    )

    if not wait_for_server(AGGREGATOR_URL):
        print("ERROR: Aggregator failed to start")
        print("  Make sure server.py supports --no-auth flag.")
        print("  Copy the latest server.py from the aggregator package.")
        server_proc.kill()
        sys.exit(1)
    print("  ✓ Aggregator running at", AGGREGATOR_URL)
    print("  ✓ Auth: DISABLED (--no-auth)")

    try:
        # ── Step 2: Inject alerts ───────────────────────────
        print()
        print(f"[2/5] Injecting {len(ALERTS)} synthetic alerts...")
        alert_ids = []
        for alert in ALERTS:
            r = requests.post(f"{AGGREGATOR_URL}/api/alerts", json=alert, headers=HEADERS)
            if r.status_code == 200:
                inv = alert["invariant"]["id"]
                tmpl = alert["invariant"]["circuit_template"]
                sev = alert["metadata"]["severity"]
                print(f"  ✓ {inv} [{tmpl}] severity={sev}")
                alert_ids.append(alert["alert_id"])
            else:
                print(f"  ✗ FAILED: {r.status_code} {r.text}")

        # Verify all are pending
        r = requests.get(f"{AGGREGATOR_URL}/api/alerts?proof_status=pending")
        pending = r.json()
        print(f"  → {len(pending)} alerts with proof_status=pending")

        # ── Step 3: Run prover ──────────────────────────────
        print()
        print("[3/5] Running Phase 3 prover (generating ZK proofs)...")
        prover_result = subprocess.run(
            [PROVER_BIN, "--key-dir", KEY_DIR, "--save-dir", PROOF_DIR,
             "--aggregator", AGGREGATOR_URL],
            capture_output=True, text=True, timeout=120,
        )
        print(prover_result.stderr if prover_result.stderr else prover_result.stdout)

        # Count proofs generated
        proof_files = [f for f in os.listdir(PROOF_DIR) if f.endswith(".json")]
        print(f"  → {len(proof_files)} proof files saved to {PROOF_DIR}")

        # ── Step 4: Verify proofs ───────────────────────────
        print()
        print("[4/5] Running standalone verifier on saved proofs...")
        if proof_files:
            verify_result = subprocess.run(
                [VERIFY_BIN, "--dir", PROOF_DIR],
                capture_output=True, text=True, timeout=60,
            )
            print(verify_result.stdout)
            if verify_result.returncode != 0:
                print("  ⚠ Some proofs failed verification!")
                print(verify_result.stderr)
        else:
            print("  ⚠ No proof files to verify")

        # ── Step 5: Check aggregator state ──────────────────
        print()
        print("[5/5] Checking aggregator proof status...")
        r = requests.get(f"{AGGREGATOR_URL}/api/stats")
        stats = r.json()
        proof_stats = stats.get("proof_stats", {})
        print(f"  Total alerts:     {stats['total_alerts']}")
        print(f"  Proof status:     {json.dumps(proof_stats)}")

        verified = proof_stats.get("verified", 0)
        total = stats["total_alerts"]

        print()
        print("=" * 60)
        if verified == total and total > 0:
            print(f"  ✓ SUCCESS — All {verified}/{total} alerts verified with ZK proofs")
        elif verified > 0:
            print(f"  ~ PARTIAL — {verified}/{total} alerts verified")
        else:
            print(f"  ✗ FAILED — 0/{total} alerts verified")
        print("=" * 60)

        # Print one proof sample
        if proof_files:
            sample = os.path.join(PROOF_DIR, proof_files[0])
            with open(sample) as f:
                bundle = json.load(f)
            print()
            print("Sample proof bundle:")
            print(f"  Proof ID:      {bundle['proof_metadata']['proof_id']}")
            print(f"  Alert ID:      {bundle['proof_metadata']['alert_id']}")
            print(f"  Circuit:       {bundle['public_inputs']['circuit_template']}")
            print(f"  Scheme:        {bundle['cryptographic_proof']['scheme']}")
            print(f"  Proof size:    {len(bundle['cryptographic_proof']['proof_blob'])} chars (base64)")
            print(f"  Gen time:      {bundle['proof_metadata']['generation_time_ms']}ms")
            print(f"  Trustless:     {bundle['verification_instructions']['trustless']}")

        # ── Keep server running if requested ─────────────────
        if args.keep_server:
            print()
            print("─" * 60)
            print("  Server is running at", AGGREGATOR_URL)
            print("  Dashboard:  http://127.0.0.1:8080")
            print("  API docs:   http://127.0.0.1:8080/docs")
            print("  Auth:       DISABLED (--no-auth)")
            print()
            print("  Press Ctrl+C to stop the server and exit.")
            print("─" * 60)
            try:
                server_proc.wait()  # Block until Ctrl+C
            except KeyboardInterrupt:
                print("\n  Stopping server...")

    finally:
        # Cleanup
        server_proc.terminate()
        try:
            server_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server_proc.kill()
        if not args.keep_server and not args.no_clean:
            if os.path.exists(DB_PATH):
                os.remove(DB_PATH)
        print()
        print("Aggregator stopped. Test complete.")


if __name__ == "__main__":
    main()
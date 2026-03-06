# zkNIDS — Zero-Knowledge Network Intrusion Detection System

A three-phase pipeline that monitors network traffic, detects intrusion patterns, and generates **cryptographic proofs** that detection was performed correctly — **without revealing the underlying network data**.

Any third party can verify these proofs independently with **zero trust assumptions**.

---

## Architecture

```
┌──────────────────────────┐     ┌──────────────────────────────┐
│   Agent Host (× N)       │     │   Aggregator (10.0.0.50)     │
│                          │     │                              │
│   Phase 1 (eBPF/XDP)    │────▶│   server.py (FastAPI)        │
│   Phase 2 (Detector)    │HTTP │   dashboard/index.html       │
│   zknids_agent.py        │     │   phase3-prover (Rust)       │
└──────────────────────────┘     └──────────────────────────────┘
                                          │
                                          ▼
                                 ┌──────────────────────┐
                                 │  Standalone Verifier  │
                                 │  (phase3-verify)      │
                                 │  Zero trust. No keys. │
                                 └──────────────────────┘
```

### Phase 1 — eBPF/XDP Kernel Telemetry
Attaches eBPF programs at the XDP hook and tracepoints in the Linux kernel. Counts packets, SYN flags, bytes, fragments, flow hashes, malformed headers, and execve syscalls. Emits JSON snapshots to stdout every second.

**Language:** C | **Hook:** XDP + sys_enter_execve tracepoint

### Phase 2 — Detection Engine
Reads Phase 1 snapshots, maintains a sliding window baseline, and evaluates **8 security invariants**. When an invariant is violated, emits an alert JSON with full evidence.

**Language:** Python | **Config:** `invariants.yaml`

| Invariant | Type | Circuit Template | Detects |
|---|---|---|---|
| syn_flood_detection | ratio | ratio_check_v1 | SYN/total ratio > threshold |
| fragment_abuse_detection | ratio | ratio_check_v1 | Fragment/total ratio > threshold |
| execve_rate_high | rate | rate_check_v1 | Process creation rate spike |
| port_scan | rate | rate_check_v1 | Unique port access rate |
| malformed_header | rate | rate_check_v1 | Invalid TCP flag combinations |
| packet_rate_spike | deviation | deviation_check_v1 | Rate exceeds N× std dev |
| packet_size_anomaly | deviation | deviation_check_v1 | Size variance exceeds baseline |
| flow_churn | deviation | deviation_check_v1 | New flow rate exceeds baseline |

### Phase 3 — Zero-Knowledge Proof System
Generates PLONK+IPA proofs for each alert using the halo2 library on Pasta curves. Proofs are ~600 bytes, generated in ~200ms–3s, and verified in ~10–30ms. **No trusted setup** — parameters are fully deterministic.

**Language:** Rust | **Library:** halo2 (Zcash) | **Curve:** Pasta (Pallas/Vesta)

### Privacy Model
| Public (Verifier Sees) | Private (Hidden in Proof) |
|---|---|
| Threshold, result (true/false), invariant ID, detector version | Packet counts, byte counts, SYN counts, IP addresses, port numbers, flow data |

---

## Project Structure

```
zkNIDS/
├── package.sh                    # Build deployment packages
├── bin/
│   ├── run-pipeline.sh           # Phase 1 → Phase 2 pipeline
│   ├── run-phase1.sh             # Phase 1 standalone
│   └── run-phase2.sh             # Phase 2 standalone
├── distributed/
│   ├── agent/
│   │   ├── install.sh            # Agent host installer
│   │   └── zknids_agent.py       # Heartbeat + alert forwarder
│   ├── aggregator/
│   │   ├── install.sh            # Aggregator installer
│   │   ├── server.py             # FastAPI server (hardened)
│   │   ├── build-verifier-package.sh
│   │   └── dashboard/index.html  # React SPA dashboard
│   └── gns3/
│       └── GNS3_IMPORT_GUIDE.md
├── phase1/                       # eBPF/XDP kernel telemetry
│   ├── Makefile
│   ├── ebpf/xdp/xdp_counter.bpf.c
│   ├── ebpf/tracepoints/execve_counter.bpf.c
│   └── userspace/collector/phase1_loader.c
├── phase2/                       # Python detection engine
│   ├── config/invariants.yaml
│   ├── setup.py
│   └── zkNIDS_phase2/            # Python package
├── phase3/                       # Rust ZK proof system (2,547 LOC)
│   ├── Cargo.toml
│   ├── src/
│   │   ├── circuits/             # 3 PLONK circuits
│   │   ├── prover/               # Proof generation + setup
│   │   ├── verifier/             # Trustless verification
│   │   ├── witness/              # Alert → circuit input
│   │   ├── api_client/           # Aggregator HTTP client
│   │   └── bin/                  # 3 binaries
│   └── benches/
├── deployment/                   # Pre-built packages
│   ├── zknids-agent.tar.gz
│   └── zknids-aggregator.tar.gz
└── shared/docs/                  # Interface specs
```

---

## Deployment

### Prerequisites
- Ubuntu 22.04+ on all hosts
- GNS3 with QEMU VMs (or any network with routing between hosts)
- 2GB+ RAM on aggregator (for Rust compilation)

### Step 1: Install Aggregator

```bash
tar xzf zknids-aggregator.tar.gz
cd zknids-aggregator
sudo bash install.sh
```

This will:
- Install Python, FastAPI, Rust toolchain
- Build Phase 3 (Rust ZK prover) from source (~5–10 min)
- Generate deterministic circuit parameters
- Generate API keys (saved to `/var/lib/zknids/api_keys_plaintext.txt`)
- Create systemd services: `zknids-aggregator`, `zknids-phase3`

**Note the Agent API Key printed at the end — you need it for agent setup.**

Start services:
```bash
sudo systemctl enable --now zknids-aggregator
sudo systemctl enable --now zknids-phase3
```

Dashboard: `http://<aggregator-ip>:8080`

### Step 2: Install Agents (on each sensor host)

```bash
tar xzf zknids-agent.tar.gz
cd zknids-agent
sudo bash install.sh --api-key <AGENT_KEY_FROM_STEP_1>
```

This will:
- Install build tools, clang, libbpf
- Build Phase 1 eBPF programs from source (generates vmlinux.h)
- Install Phase 2 Python detector
- Auto-detect monitoring interface (prefers second NIC)
- Create systemd services: `zknids-agent`, `zknids-pipeline`

Start services:
```bash
sudo systemctl enable --now zknids-agent
sudo systemctl enable --now zknids-pipeline
```

### Step 3: Verify

Check agents appear in the dashboard:
```bash
curl http://<aggregator-ip>:8080/api/hosts
```

Check pipeline is running:
```bash
journalctl -u zknids-pipeline -f
```

### Step 4: Run Attack Demo

From an attacker host on the monitored network:
```bash
# SYN Flood
hping3 -S -p 80 -c 5000 --faster <agent-ip>

# Port Scan
hping3 -S --scan 1-1024 <agent-ip>

# Traffic Burst
timeout 10 hping3 -S -p 80 --flood <agent-ip>
```

Watch alerts appear in the dashboard with `✓ VERIFIED` proof status.

### Step 5: Build Verifier Package (after demo)

On the aggregator:
```bash
bash /opt/zknids/build-verifier-package.sh
```

Output: `~/zknids-verifier.tar.gz` — hand this to a reviewer. They extract it and run:
```bash
./verify-all.sh
```

Every proof is verified independently. No keys, no setup, no trust required.

---

## Building Packages from Source

```bash
cd ~/projects/zkNIDS
bash package.sh
```

Output:
- `~/zknids-agent.tar.gz`
- `~/zknids-aggregator.tar.gz`

The standalone verifier package is built separately on the aggregator after proofs exist.

---

## Technology Stack

| Component | Technology | Purpose |
|---|---|---|
| Phase 1 | C, clang, libbpf, XDP | Kernel-level packet capture |
| Phase 2 | Python 3, PyYAML | Invariant evaluation engine |
| Phase 3 | Rust, halo2, pasta_curves | PLONK+IPA ZK proof system |
| Aggregator | Python, FastAPI, SQLite | REST API + WebSocket server |
| Dashboard | React (single-file SPA) | Real-time monitoring UI |
| Agent | Python, requests | Heartbeat + alert forwarding |
| Network | GNS3, QEMU, Docker | Virtual network lab |
| Curve | Pasta (Pallas/Vesta) | Efficient recursive proof composition |

## Why PLONK+IPA

| Criteria | Groth16 | PLONK+KZG | Bulletproofs | **PLONK+IPA** | STARKs |
|---|---|---|---|---|---|
| Trusted Setup | ✗ Required | △ Universal | ✓ None | **✓ None** | ✓ None |
| Proof Size | ~192B | ~400B | ~1KB | **~600B** | 50-200KB |
| Prove Time | ~100ms | ~200ms | ~2s | **~200ms** | ~10s |
| Verify Time | ~3ms | ~8ms | ~100ms | **~15ms** | ~30ms |
| **Score** | 5.9 | 7.2 | 6.6 | **8.6** | 6.0 |

PLONK+IPA eliminates trusted setup entirely while maintaining practical proof sizes and fast verification. Parameters are **fully deterministic** — a reviewer reproduces identical parameters on their own machine.

---

## Security Features

- API key authentication (SHA-256 hashed, agent + admin roles)
- Per-IP rate limiting (sliding window)
- Input validation and sanitization
- Parameterized SQL (zero user input in SQL strings)
- Path traversal protection on proof downloads
- Security headers (CSP, HSTS, X-Frame-Options)
- Audit logging (DB + file) for all mutations
- WebSocket connection limits

---

## Key Design Decisions

**eBPF/XDP over libpcap:** Near-zero overhead, runs before kernel networking stack. No packet copies to userspace for counting.

**Fixed-point arithmetic in circuits:** All ZK circuits use 10^6 precision integer math to avoid floating-point non-determinism.

**ProofBundle format:** Each proof is self-contained — embeds circuit parameters (base64). The verifier reconstructs VK deterministically. No key files needed.

**hostname+IP for host_id:** QEMU VMs change MAC on reboot. Static IPs are stable identifiers in the GNS3 topology.

**Pipeline reads interface from agent.conf:** Single source of truth. No hardcoded interface names in systemd services.

---

## License

Academic project — Master of Science in Computer Science thesis.

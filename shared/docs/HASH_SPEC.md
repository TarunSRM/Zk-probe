# Phase 1 → Phase 3 Hash Specification

**Version:** 1.1.0
**Status:** Canonical — Phase 3 ZK circuits MUST match these specifications exactly.

---

## 1. Snapshot Integrity Hash (`hash` field)

**Algorithm:** SHA-256
**Output:** 32 bytes (64 hex characters in text output)

### Field Ordering (deterministic)

The snapshot hash is computed by feeding the following fields into SHA-256
in this exact order, using their raw binary representation (little-endian
on x86_64):

| Order | Field             | C Type   | Size    | Notes                          |
|-------|-------------------|----------|---------|--------------------------------|
| 1     | timestamp_ns      | __u64    | 8 bytes | CLOCK_MONOTONIC nanoseconds    |
| 2     | execve_count      | __u64    | 8 bytes | Per-interval count             |
| 3     | flow_count        | __u32    | 4 bytes | Unique source IPs this interval|
| 4     | total_packets     | __u64    | 8 bytes | All packets this interval      |
| 5     | total_bytes       | __u64    | 8 bytes | All bytes this interval        |
| 6     | syn_packets       | __u64    | 8 bytes | SYN-only packets (SYN=1,ACK=0)|
| 7     | malformed_count   | __u64    | 8 bytes | Invalid IP header packets      |
| 8     | fragment_count    | __u64    | 8 bytes | Fragmented IP packets          |
| 9     | max_port_spread   | __u32    | 4 bytes | Max unique dst ports (any src) |
| 10    | min_pkt_size      | __u64    | 8 bytes | Smallest avg pkt size (flow)   |
| 11    | max_pkt_size      | __u64    | 8 bytes | Largest avg pkt size (flow)    |
| 12    | pkt_size_sum_sq   | __u64    | 8 bytes | Sum of squared packet sizes    |
| 13    | flow_hash         | bytes    | 32 bytes| SHA-256 of sorted source IPs   |

**Total input:** 120 bytes → 32 bytes SHA-256 output

### Pseudocode

```
sha256_init(ctx)
sha256_update(ctx, timestamp_ns,    8)
sha256_update(ctx, execve_count,    8)
sha256_update(ctx, flow_count,      4)
sha256_update(ctx, total_packets,   8)
sha256_update(ctx, total_bytes,     8)
sha256_update(ctx, syn_packets,     8)
sha256_update(ctx, malformed_count, 8)
sha256_update(ctx, fragment_count,  8)
sha256_update(ctx, max_port_spread, 4)
sha256_update(ctx, min_pkt_size,    8)
sha256_update(ctx, max_pkt_size,    8)
sha256_update(ctx, pkt_size_sum_sq, 8)
sha256_update(ctx, flow_hash,       32)
sha256_final(ctx) → hash
```

### Implementation Reference

File: `phase1/userspace/collector/phase1_loader.c`
Function: `hash_snapshot()`

---

## 2. Flow Hash (`flow_hash` field)

**Algorithm:** SHA-256
**Output:** 32 bytes (64 hex characters in text output)

### Purpose

The flow hash is a **cryptographic commitment** to the set of source IP
addresses observed during the snapshot interval. It allows Phase 3 to
verify that specific flows were present WITHOUT revealing the actual IP
addresses (privacy preservation for ZK proofs).

### Computation

1. Collect all source IPv4 addresses from `flow_map` (keys)
2. Sort addresses in ascending numerical order (little-endian __u32)
3. Feed sorted addresses sequentially into SHA-256
4. Output 32-byte hash

### Field Ordering

| Order | Field    | C Type | Size    | Notes                       |
|-------|----------|--------|---------|-----------------------------|
| 1..N  | src_ip_i | __u32  | 4 bytes | Sorted ascending, N ≤ 1024  |

### Edge Case: Empty Flow Set

If no flows were observed (flow_count == 0), the flow_hash is
SHA-256 of an empty input: `sha256("")`.

### Pseudocode

```
ips = collect_all_keys(flow_map)
sort_ascending(ips)
sha256_init(ctx)
for ip in ips:
    sha256_update(ctx, ip, 4)
sha256_final(ctx) → flow_hash
```

### Implementation Reference

File: `phase1/userspace/collector/phase1_loader.c`
Function: `compute_flow_hash()`

---

## 3. Detector Version Hash (`detector` field)

**Algorithm:** SHA-256
**Input:** ASCII string of detector version (e.g., "phase1-v0.2.0")
**Output:** 32 bytes (64 hex characters)

### Pseudocode

```
sha256_init(ctx)
sha256_update(ctx, "phase1-v0.2.0", strlen("phase1-v0.2.0"))
sha256_final(ctx) → detector_hash
```

---

## 4. Phase 3 ZK Circuit Requirements

For a Phase 3 ZK circuit to verify a snapshot hash:

1. **Private witness inputs:** All 12 numeric fields + flow_hash (120 bytes total)
2. **Public input:** The claimed hash value (32 bytes)
3. **Circuit constraint:** Recompute SHA-256 over witness fields in the
   exact order above and assert it equals the public hash

### Important Notes

- **Endianness:** All integer fields are stored in native byte order
  (little-endian on x86_64). The ZK circuit must use the same encoding.
- **No padding:** Fields are concatenated directly with no alignment padding
  between them. The C struct may have padding, but `SHA256_Update` is
  called per-field, so struct padding is NOT included in the hash.
- **Determinism:** The hash is fully deterministic given the same field
  values. flow_hash is deterministic because IPs are sorted before hashing.

---

## 5. Version History

| Version | Date       | Changes                                      |
|---------|------------|----------------------------------------------|
| 1.0.0   | 2026-01-25 | Initial: 6 fields (ts, execve, flows, pkts, bytes, syn) |
| 1.1.0   | 2026-02-09 | Extended: +6 fields + flow_hash (Phase 3 compatible)    |

---

## 6. Circuit Template Mapping

Each invariant type maps to a ZK circuit template:

| Circuit Template    | Invariant Type   | What It Proves                                    |
|---------------------|------------------|---------------------------------------------------|
| rate_check_v1       | rate_threshold   | metric_rate > threshold                           |
| ratio_check_v1      | ratio_threshold  | numerator/denominator > threshold                 |
| deviation_check_v1  | spike_detection  | current_rate > baseline_mean * multiplier         |

### Circuit Public/Private Inputs

**rate_check_v1:**
- Private: count_before, count_after, time_before, time_after
- Public: threshold, result (boolean)

**ratio_check_v1:**
- Private: numerator_value, denominator_value
- Public: threshold, result (boolean)

**deviation_check_v1:**
- Private: current_rate, baseline_mean
- Public: multiplier, result (boolean)
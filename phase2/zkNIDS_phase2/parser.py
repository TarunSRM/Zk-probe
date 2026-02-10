"""
Snapshot Parser - Parse Phase 1 text format snapshots
"""

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class Snapshot:
    """Phase 1 snapshot structure."""
    timestamp_ns: int
    execve_count: int
    flow_count: int
    total_packets: int
    total_bytes: int
    syn_packets: int
    hash: str
    detector_hash: Optional[str] = None
    
    def __post_init__(self):
        """Validate snapshot fields."""
        if self.timestamp_ns < 0:
            raise ValueError("timestamp_ns must be non-negative")
        if self.execve_count < 0:
            raise ValueError("execve_count must be non-negative")
        if self.flow_count < 0:
            raise ValueError("flow_count must be non-negative")
        if self.total_packets < 0:
            raise ValueError("total_packets must be non-negative")
        if self.total_bytes < 0:
            raise ValueError("total_bytes must be non-negative")
        if self.syn_packets < 0:
            raise ValueError("syn_packets must be non-negative")
        if len(self.hash) != 64:
            raise ValueError("hash must be 64 hex characters")
        if self.detector_hash and len(self.detector_hash) != 64:
            raise ValueError("detector_hash must be 64 hex characters")


class SnapshotParser:
    """Parser for Phase 1 snapshot format."""
    
    # Pattern matches: T=<num> execve=<num> flows=<num> packets=<num> bytes=<num> syn=<num> hash=<hex> detector=<hex>
    PATTERN = re.compile(
        r'T=(\d+)\s+'
        r'execve=(\d+)\s+'
        r'flows=(\d+)\s+'
        r'packets=(\d+)\s+'
        r'bytes=(\d+)\s+'
        r'syn=(\d+)\s+'
        r'hash=([a-f0-9]{64})'
        r'(?:\s+detector=([a-f0-9]{64}))?'
    )
    
    def parse(self, line: str) -> Snapshot:
        """
        Parse a Phase 1 snapshot line.
        
        Args:
            line: Text line in Phase 1 format
            
        Returns:
            Snapshot object
            
        Raises:
            ValueError: If line doesn't match expected format
        """
        line = line.strip()
        
        match = self.PATTERN.match(line)
        if not match:
            raise ValueError(f"Invalid snapshot format: {line[:100]}")
        
        return Snapshot(
            timestamp_ns=int(match.group(1)),
            execve_count=int(match.group(2)),
            flow_count=int(match.group(3)),
            total_packets=int(match.group(4)),
            total_bytes=int(match.group(5)),
            syn_packets=int(match.group(6)),
            hash=match.group(7),
            detector_hash=match.group(8) if match.group(8) else None
        )
    
    def validate_monotonicity(self, prev: Snapshot, curr: Snapshot) -> bool:
        """
        Validate that counters are monotonic or stable.
        
        Args:
            prev: Previous snapshot
            curr: Current snapshot
            
        Returns:
            True if valid, False if anomaly detected
        """
        # Timestamp must increase
        if curr.timestamp_ns <= prev.timestamp_ns:
            return False
        
        # Counters should be monotonic (unless wraparound/reset)
        if curr.execve_count < prev.execve_count:
            # Potential wraparound or system reset
            return False
        
        if curr.total_packets < prev.total_packets:
            return False
        
        if curr.total_bytes < prev.total_bytes:
            return False
        
        if curr.syn_packets < prev.syn_packets:
            return False
        
        # Flow count can stay same or increase (no expiration in Phase 1)
        if curr.flow_count < prev.flow_count:
            return False
        
        return True


# Example usage and testing
if __name__ == '__main__':
    parser = SnapshotParser()
    
    # Test valid snapshot
    test_line = (
        "T=1234567890123456789 execve=42 flows=5 packets=1523 "
        "bytes=892341 syn=12 "
        "hash=a3f5e8c2d1b4f7a9e6c3b8d2f1a4e7c9b6d3f8a1e4c7b9d2f5a8e1c4b7d9f2a5 "
        "detector=1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    )
    
    try:
        snapshot = parser.parse(test_line)
        print("✓ Parsed successfully:")
        print(f"  Timestamp: {snapshot.timestamp_ns}")
        print(f"  Execve count: {snapshot.execve_count}")
        print(f"  Flows: {snapshot.flow_count}")
        print(f"  Packets: {snapshot.total_packets}")
        print(f"  Bytes: {snapshot.total_bytes}")
        print(f"  SYN packets: {snapshot.syn_packets}")
        print(f"  Hash: {snapshot.hash[:16]}...")
        print(f"  Detector: {snapshot.detector_hash[:16] if snapshot.detector_hash else 'N/A'}...")
    except Exception as e:
        print(f"✗ Parse failed: {e}")
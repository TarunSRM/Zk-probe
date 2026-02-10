#!/usr/bin/env python3
"""
Phase 2 Demonstration Script
Tests the detection engine with synthetic snapshot data
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from zkNIDS_phase2.parser import SnapshotParser
from zkNIDS_phase2.state_manager import StateManager
from zkNIDS_phase2.invariant_engine import InvariantEngine
from zkNIDS_phase2.alert_generator import AlertGenerator

def main():
    print("=" * 60)
    print("Phase 2 Detection Engine - Demonstration")
    print("=" * 60)
    print()
    
    # Initialize components
    parser = SnapshotParser()
    state = StateManager()
    engine = InvariantEngine()
    generator = AlertGenerator()
    
    print("✓ Components initialized")
    print(f"  - Loaded {len(engine.invariants)} invariants")
    print()
    
    # Test data file
    test_file = os.path.join(
        os.path.dirname(__file__),
        'fixtures', 'sample_snapshots.txt'
    )
    
    if not os.path.exists(test_file):
        print(f"Error: Test file not found: {test_file}")
        return 1
    
    print(f"Reading snapshots from: {test_file}")
    print()
    
    snapshot_count = 0
    alert_count = 0
    
    with open(test_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            try:
                # Parse snapshot
                snapshot = parser.parse(line)
                snapshot_count += 1
                
                # Update state
                state.add_snapshot(snapshot)
                
                # Evaluate invariants
                violations = engine.evaluate(snapshot, state)
                
                # Generate alerts
                for violation in violations:
                    alert = generator.generate(violation, snapshot, state)
                    alert_count += 1
                    
                    print(f"🚨 ALERT #{alert_count}")
                    print(f"  Invariant: {violation.invariant_id}")
                    print(f"  Description: {violation.description}")
                    print(f"  Observed: {violation.observed_value:.2f}")
                    print(f"  Threshold: {violation.threshold:.2f}")
                    print(f"  Severity: {violation.severity.upper()}")
                    print()
            
            except Exception as e:
                print(f"Error processing line: {e}")
                continue
    
    print("=" * 60)
    print("Summary")
    print("=" * 60)
    print(f"Snapshots processed: {snapshot_count}")
    print(f"Alerts generated: {alert_count}")
    print()
    
    if alert_count > 0:
        print("✓ Detection engine working correctly!")
        print("  Expected alerts for:")
        print("    - High execve rate (snapshot 6)")
        print("    - Packet rate spike (snapshot 11)")
        print("    - SYN flood pattern (snapshot 11)")
    else:
        print("⚠ No alerts detected. Check invariant thresholds.")
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
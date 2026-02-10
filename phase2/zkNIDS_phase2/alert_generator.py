"""
Alert Generator - Generate structured, proof-ready alert records
"""

import json
import uuid
import hashlib
import time
from typing import Dict, Any
from .invariant_engine import InvariantViolation
from .parser import Snapshot
from .state_manager import StateManager


class AlertGenerator:
    """Generates structured alert records for Phase 3 verification."""
    
    SCHEMA_VERSION = "1.0.0"
    DETECTOR_VERSION = "phase2-v0.1.0"
    
    def __init__(self):
        """Initialize alert generator."""
        self.detector_hash = self._compute_detector_hash()
    
    def _compute_detector_hash(self) -> str:
        """Compute SHA256 hash of detector version."""
        sha = hashlib.sha256()
        sha.update(self.DETECTOR_VERSION.encode('utf-8'))
        return sha.hexdigest()
    
    def generate(self, violation: InvariantViolation, 
                 snapshot: Snapshot, 
                 state: StateManager) -> str:
        """
        Generate a structured alert record.
        
        Args:
            violation: Detected invariant violation
            snapshot: Current snapshot that triggered the violation
            state: State manager for evidence gathering
            
        Returns:
            JSON string of the alert
        """
        alert_id = str(uuid.uuid4())
        generated_at_ns = int(time.time() * 1_000_000_000)
        
        # Get previous snapshot for evidence
        prev_snapshot = state.get_previous()
        
        # Compute delta if previous exists
        delta = None
        if prev_snapshot:
            delta = state.compute_delta(prev_snapshot, snapshot)
        
        # Build alert structure
        alert = {
            'schema_version': self.SCHEMA_VERSION,
            'alert_id': alert_id,
            'alert_type': 'invariant_violation',
            'detector_version': self.DETECTOR_VERSION,
            
            'invariant': {
                'id': violation.invariant_id,
                'type': violation.invariant_type,
                'description': violation.description,
                'category': violation.metadata.get('category', 'unknown')
            },
            
            'observation': {
                'timestamp_ns': snapshot.timestamp_ns,
                'window_start_ns': prev_snapshot.timestamp_ns if prev_snapshot else snapshot.timestamp_ns,
                'window_end_ns': snapshot.timestamp_ns,
                'window_duration_ns': delta['time_delta_ns'] if delta else 0,
                'observed_value': violation.observed_value,
                'threshold': violation.threshold,
                'threshold_operator': violation.operator
            },
            
            'evidence': {
                'snapshot_current': {
                    'timestamp_ns': snapshot.timestamp_ns,
                    'execve_count': snapshot.execve_count,
                    'flow_count': snapshot.flow_count,
                    'total_packets': snapshot.total_packets,
                    'total_bytes': snapshot.total_bytes,
                    'syn_packets': snapshot.syn_packets,
                    'hash': snapshot.hash
                }
            },
            
            'metadata': {
                'severity': violation.severity,
                'confidence': violation.confidence,
                'generated_at_ns': generated_at_ns
            },
            
            'provenance': {
                'phase1_detector_hash': snapshot.detector_hash if snapshot.detector_hash else 'unknown',
                'phase2_detector_hash': self.detector_hash,
                'invariant_metadata': violation.metadata
            }
        }
        
        # Add previous snapshot to evidence if available
        if prev_snapshot:
            alert['evidence']['snapshot_previous'] = {
                'timestamp_ns': prev_snapshot.timestamp_ns,
                'execve_count': prev_snapshot.execve_count,
                'flow_count': prev_snapshot.flow_count,
                'total_packets': prev_snapshot.total_packets,
                'total_bytes': prev_snapshot.total_bytes,
                'syn_packets': prev_snapshot.syn_packets,
                'hash': prev_snapshot.hash
            }
        
        # Add delta to evidence if available
        if delta:
            alert['evidence']['delta'] = {
                'time_delta_ns': delta['time_delta_ns'],
                'execve_delta': delta['execve_delta'],
                'flow_delta': delta['flow_delta'],
                'packet_delta': delta['packet_delta'],
                'byte_delta': delta['byte_delta'],
                'syn_delta': delta['syn_delta'],
                'computed_rates': {
                    'execve_rate': delta['execve_rate'],
                    'packet_rate': delta['packet_rate'],
                    'byte_rate': delta['byte_rate'],
                    'syn_rate': delta['syn_rate']
                }
            }
        
        return json.dumps(alert, separators=(',', ':'))
    
    def compute_alert_hash(self, alert_json: str) -> str:
        """
        Compute SHA256 hash of alert for Phase 3 verification.
        
        Args:
            alert_json: JSON string of the alert
            
        Returns:
            64-character hex hash
        """
        sha = hashlib.sha256()
        sha.update(alert_json.encode('utf-8'))
        return sha.hexdigest()
    
    def validate_alert(self, alert_json: str) -> bool:
        """
        Validate alert structure.
        
        Args:
            alert_json: JSON string of the alert
            
        Returns:
            True if valid, False otherwise
        """
        try:
            alert = json.loads(alert_json)
            
            # Check required top-level fields
            required_fields = [
                'schema_version', 'alert_id', 'alert_type', 
                'detector_version', 'invariant', 'observation', 
                'evidence', 'metadata', 'provenance'
            ]
            
            for field in required_fields:
                if field not in alert:
                    return False
            
            # Check nested structures
            if 'snapshot_current' not in alert['evidence']:
                return False
            
            if 'phase2_detector_hash' not in alert['provenance']:
                return False
            
            return True
        
        except Exception:
            return False


# Testing
if __name__ == '__main__':
    from .parser import Snapshot
    from .state_manager import StateManager
    from .invariant_engine import InvariantViolation
    
    generator = AlertGenerator()
    
    # Create test snapshots
    base_time = 1234567890000000000
    snap1 = Snapshot(
        timestamp_ns=base_time,
        execve_count=100,
        flow_count=5,
        total_packets=1000,
        total_bytes=500000,
        syn_packets=10,
        hash="a" * 64,
        detector_hash="1" * 64
    )
    
    snap2 = Snapshot(
        timestamp_ns=base_time + 1_000_000_000,
        execve_count=250,
        flow_count=5,
        total_packets=1050,
        total_bytes=525000,
        syn_packets=12,
        hash="b" * 64,
        detector_hash="1" * 64
    )
    
    state = StateManager()
    state.add_snapshot(snap1)
    state.add_snapshot(snap2)
    
    # Create test violation
    violation = InvariantViolation(
        invariant_id='execve_rate_high',
        invariant_type='rate_threshold',
        description='Process creation rate exceeds threshold',
        observed_value=150.0,
        threshold=100.0,
        operator='greater_than',
        severity='high',
        metadata={'metric': 'execve_count'}
    )
    
    # Generate alert
    alert_json = generator.generate(violation, snap2, state)
    
    print("✓ Generated alert:")
    alert = json.loads(alert_json)
    print(f"  Alert ID: {alert['alert_id']}")
    print(f"  Invariant: {alert['invariant']['id']}")
    print(f"  Observed: {alert['observation']['observed_value']}")
    print(f"  Threshold: {alert['observation']['threshold']}")
    print(f"  Evidence: {len(alert['evidence'])} sections")
    
    # Validate
    is_valid = generator.validate_alert(alert_json)
    print(f"\n✓ Alert validation: {'PASS' if is_valid else 'FAIL'}")
    
    # Compute hash
    alert_hash = generator.compute_alert_hash(alert_json)
    print(f"✓ Alert hash: {alert_hash[:32]}...")
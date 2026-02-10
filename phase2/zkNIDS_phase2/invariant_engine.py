"""
Invariant Engine - Define and evaluate detection invariants
"""

import yaml
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from .parser import Snapshot
from .state_manager import StateManager


@dataclass
class InvariantViolation:
    """Represents a detected invariant violation."""
    invariant_id: str
    invariant_type: str
    description: str
    observed_value: float
    threshold: float
    operator: str
    severity: str
    confidence: float = 1.0
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class InvariantEngine:
    """Evaluates invariants against snapshots."""
    
    DEFAULT_INVARIANTS = [
        {
            'id': 'execve_rate_high',
            'type': 'rate_threshold',
            'category': 'rate_based',
            'description': 'Process creation rate exceeds threshold',
            'metric': 'execve_count',
            'threshold': 100.0,
            'operator': 'greater_than',
            'severity': 'high',
            'enabled': True
        },
        {
            'id': 'syn_flood_detection',
            'type': 'ratio_threshold',
            'category': 'protocol',
            'description': 'SYN packet ratio indicates potential SYN flood',
            'numerator': 'syn_packets',
            'denominator': 'total_packets',
            'threshold': 0.8,
            'operator': 'greater_than',
            'severity': 'critical',
            'enabled': True
        },
        {
            'id': 'packet_rate_spike',
            'type': 'spike_detection',
            'category': 'behavioral',
            'description': 'Packet rate spike detected',
            'metric': 'total_packets',
            'baseline_multiplier': 5.0,
            'window_seconds': 10,
            'severity': 'medium',
            'enabled': True
        }
    ]
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize invariant engine.
        
        Args:
            config_path: Path to YAML config file, or None for defaults
        """
        self.invariants = self._load_config(config_path)
    
    def _load_config(self, config_path: Optional[str]) -> List[Dict]:
        """Load invariant configuration from file or use defaults."""
        if config_path and Path(config_path).exists():
            with open(config_path) as f:
                config = yaml.safe_load(f)
                return config.get('invariants', self.DEFAULT_INVARIANTS)
        else:
            return self.DEFAULT_INVARIANTS
    
    def evaluate(self, snapshot: Snapshot, state: StateManager) -> List[InvariantViolation]:
        """
        Evaluate all enabled invariants against current snapshot.
        
        Args:
            snapshot: Current snapshot
            state: State manager with historical data
            
        Returns:
            List of detected violations
        """
        violations = []
        
        for inv in self.invariants:
            if not inv.get('enabled', True):
                continue
            
            inv_type = inv['type']
            
            if inv_type == 'rate_threshold':
                violation = self._evaluate_rate_threshold(inv, snapshot, state)
            elif inv_type == 'ratio_threshold':
                violation = self._evaluate_ratio_threshold(inv, snapshot, state)
            elif inv_type == 'spike_detection':
                violation = self._evaluate_spike_detection(inv, snapshot, state)
            else:
                continue
            
            if violation:
                violations.append(violation)
        
        return violations
    
    def _evaluate_rate_threshold(self, inv: Dict, snapshot: Snapshot, 
                                  state: StateManager) -> Optional[InvariantViolation]:
        """Evaluate rate-based threshold invariant."""
        prev = state.get_previous()
        if not prev:
            return None
        
        delta = state.compute_delta(prev, snapshot)
        metric = inv['metric']
        
        # Map metric names to rate keys (strip _count suffix if present)
        metric_base = metric.replace('_count', '').replace('_packets', '').replace('_bytes', '')
        if metric_base == 'total':
            metric_base = metric.replace('total_', '')
        rate_key = f'{metric_base}_rate'
        
        if rate_key not in delta:
            return None
        
        observed = delta[rate_key]
        threshold = inv['threshold']
        operator = inv['operator']
        
        violated = False
        if operator == 'greater_than':
            violated = observed > threshold
        elif operator == 'less_than':
            violated = observed < threshold
        
        if violated:
            return InvariantViolation(
                invariant_id=inv['id'],
                invariant_type=inv['type'],
                description=inv['description'],
                observed_value=observed,
                threshold=threshold,
                operator=operator,
                severity=inv['severity'],
                metadata={
                    'metric': metric,
                    'time_window_ns': delta['time_delta_ns']
                }
            )
        
        return None
    
    def _evaluate_ratio_threshold(self, inv: Dict, snapshot: Snapshot,
                                   state: StateManager) -> Optional[InvariantViolation]:
        """Evaluate ratio-based threshold invariant."""
        prev = state.get_previous()
        if not prev:
            return None
        
        # Use current snapshot values for ratio
        numerator_field = inv['numerator']
        denominator_field = inv['denominator']
        
        numerator = getattr(snapshot, numerator_field, 0)
        denominator = getattr(snapshot, denominator_field, 0)
        
        if denominator == 0:
            return None
        
        observed = numerator / denominator
        threshold = inv['threshold']
        operator = inv['operator']
        
        violated = False
        if operator == 'greater_than':
            violated = observed > threshold
        elif operator == 'less_than':
            violated = observed < threshold
        
        if violated:
            return InvariantViolation(
                invariant_id=inv['id'],
                invariant_type=inv['type'],
                description=inv['description'],
                observed_value=observed,
                threshold=threshold,
                operator=operator,
                severity=inv['severity'],
                metadata={
                    'numerator': numerator_field,
                    'denominator': denominator_field,
                    'numerator_value': numerator,
                    'denominator_value': denominator
                }
            )
        
        return None
    
    def _evaluate_spike_detection(self, inv: Dict, snapshot: Snapshot,
                                   state: StateManager) -> Optional[InvariantViolation]:
        """Evaluate spike detection invariant."""
        metric = inv['metric']
        multiplier = inv['baseline_multiplier']
        window_seconds = inv['window_seconds']
        
        is_spike, details = state.detect_spike(metric, multiplier, window_seconds)
        
        if is_spike:
            return InvariantViolation(
                invariant_id=inv['id'],
                invariant_type=inv['type'],
                description=inv['description'],
                observed_value=details['current_rate'],
                threshold=details['threshold'],
                operator='greater_than',
                severity=inv['severity'],
                confidence=0.9,  # Lower confidence for statistical detection
                metadata={
                    'metric': metric,
                    'baseline_mean': details['baseline_mean'],
                    'baseline_std': details['baseline_std'],
                    'multiplier': multiplier,
                    'window_seconds': window_seconds
                }
            )
        
        return None


# Testing
if __name__ == '__main__':
    from .parser import Snapshot
    from .state_manager import StateManager
    
    engine = InvariantEngine()
    state = StateManager()
    
    print("✓ Invariant engine initialized")
    print(f"  Loaded {len(engine.invariants)} invariants:")
    for inv in engine.invariants:
        print(f"    - {inv['id']}: {inv['description']}")
    
    # Simulate high execve rate
    base_time = 1234567890000000000
    snap1 = Snapshot(
        timestamp_ns=base_time,
        execve_count=100,
        flow_count=5,
        total_packets=1000,
        total_bytes=500000,
        syn_packets=10,
        hash="a" * 64
    )
    state.add_snapshot(snap1)
    
    snap2 = Snapshot(
        timestamp_ns=base_time + 1_000_000_000,
        execve_count=250,  # 150 execve in 1 second
        flow_count=5,
        total_packets=1050,
        total_bytes=525000,
        syn_packets=12,
        hash="b" * 64
    )
    state.add_snapshot(snap2)
    
    violations = engine.evaluate(snap2, state)
    print(f"\n✓ Detected {len(violations)} violations:")
    for v in violations:
        print(f"    - {v.invariant_id}: {v.observed_value:.2f} > {v.threshold}")
"""
State Manager - Maintains sliding windows and baselines
"""

from collections import deque
from typing import Optional, List
from .parser import Snapshot


# Mapping from metric names (as used in invariants.yaml) to delta rate keys
# compute_delta() produces: execve_rate, packet_rate, byte_rate, syn_rate
METRIC_TO_RATE_KEY = {
    'total_packets': 'packet_rate',
    'total_bytes': 'byte_rate',
    'syn_packets': 'syn_rate',
    'execve_count': 'execve_rate',
    'flow_count': 'flow_rate',       # future use
}


class StateManager:
    """Manages historical snapshots for windowing and baseline computation."""
    
    def __init__(self, max_window_size: int = 60):
        """
        Initialize state manager.
        
        Args:
            max_window_size: Maximum number of snapshots to keep in memory
        """
        self.snapshots: deque[Snapshot] = deque(maxlen=max_window_size)
        self.previous_snapshot: Optional[Snapshot] = None
    
    def add_snapshot(self, snapshot: Snapshot):
        """
        Add a new snapshot to the state.
        
        Args:
            snapshot: New snapshot to add
        """
        if self.snapshots:
            self.previous_snapshot = self.snapshots[-1]
        
        self.snapshots.append(snapshot)
    
    def get_previous(self) -> Optional[Snapshot]:
        """Get the previous snapshot (for delta computation)."""
        return self.previous_snapshot
    
    def get_window(self, window_seconds: int) -> List[Snapshot]:
        """
        Get snapshots within a time window.
        
        Args:
            window_seconds: Window size in seconds
            
        Returns:
            List of snapshots within the window
        """
        if not self.snapshots:
            return []
        
        current_time = self.snapshots[-1].timestamp_ns
        window_ns = window_seconds * 1_000_000_000
        cutoff_time = current_time - window_ns
        
        result = []
        for snapshot in reversed(self.snapshots):
            if snapshot.timestamp_ns >= cutoff_time:
                result.append(snapshot)
            else:
                break
        
        return list(reversed(result))
    
    def compute_delta(self, prev: Snapshot, curr: Snapshot) -> dict:
        """
        Compute deltas between two snapshots.
        
        Args:
            prev: Previous snapshot
            curr: Current snapshot
            
        Returns:
            Dictionary of delta values
        """
        time_delta_ns = curr.timestamp_ns - prev.timestamp_ns
        time_delta_sec = time_delta_ns / 1_000_000_000.0
        
        execve_delta = curr.execve_count - prev.execve_count
        flow_delta = curr.flow_count - prev.flow_count
        packet_delta = curr.total_packets - prev.total_packets
        byte_delta = curr.total_bytes - prev.total_bytes
        syn_delta = curr.syn_packets - prev.syn_packets
        
        return {
            'time_delta_ns': time_delta_ns,
            'time_delta_sec': time_delta_sec,
            'execve_delta': execve_delta,
            'flow_delta': flow_delta,
            'packet_delta': packet_delta,
            'byte_delta': byte_delta,
            'syn_delta': syn_delta,
            # Rates (per second)
            'execve_rate': execve_delta / time_delta_sec if time_delta_sec > 0 else 0,
            'packet_rate': packet_delta / time_delta_sec if time_delta_sec > 0 else 0,
            'byte_rate': byte_delta / time_delta_sec if time_delta_sec > 0 else 0,
            'syn_rate': syn_delta / time_delta_sec if time_delta_sec > 0 else 0,
        }
    
    def _resolve_rate_key(self, metric: str) -> str:
        """
        Resolve a metric name to its corresponding rate key in delta dict.
        
        Args:
            metric: Metric name from invariants config (e.g., 'total_packets')
            
        Returns:
            Rate key used in compute_delta output (e.g., 'packet_rate')
        """
        # Direct lookup first
        if metric in METRIC_TO_RATE_KEY:
            return METRIC_TO_RATE_KEY[metric]
        
        # Fallback: try appending _rate
        candidate = f'{metric}_rate'
        return candidate
    
    def compute_baseline(self, metric: str, window_seconds: int = 10) -> dict:
        """
        Compute baseline statistics for a metric over a window.
        
        Args:
            metric: Metric name (e.g., 'total_packets', 'execve_count')
            window_seconds: Window size for baseline
            
        Returns:
            Dictionary with mean, min, max, std
        """
        window = self.get_window(window_seconds)
        
        if len(window) < 2:
            return {
                'mean': 0,
                'min': 0,
                'max': 0,
                'std': 0,
                'sample_size': len(window)
            }
        
        # Compute deltas (rates) using correct rate key
        rate_key = self._resolve_rate_key(metric)
        deltas = []
        for i in range(1, len(window)):
            prev = window[i-1]
            curr = window[i]
            delta = self.compute_delta(prev, curr)
            rate = delta.get(rate_key, 0)
            deltas.append(rate)
        
        if not deltas:
            return {
                'mean': 0,
                'min': 0,
                'max': 0,
                'std': 0,
                'sample_size': 0
            }
        
        mean = sum(deltas) / len(deltas)
        variance = sum((x - mean) ** 2 for x in deltas) / len(deltas)
        std = variance ** 0.5
        
        return {
            'mean': mean,
            'min': min(deltas),
            'max': max(deltas),
            'std': std,
            'sample_size': len(deltas)
        }
    
    def detect_spike(self, metric: str, multiplier: float = 5.0, 
                     window_seconds: int = 10) -> tuple[bool, dict]:
        """
        Detect if current rate is a spike compared to baseline.
        
        Args:
            metric: Metric name (e.g., 'total_packets')
            multiplier: Spike threshold (e.g., 5x baseline)
            window_seconds: Baseline window size
            
        Returns:
            (is_spike, details_dict)
        """
        if len(self.snapshots) < 2:
            return False, {}
        
        # Get current rate using correct rate key
        rate_key = self._resolve_rate_key(metric)
        
        prev = self.snapshots[-2]
        curr = self.snapshots[-1]
        delta = self.compute_delta(prev, curr)
        current_rate = delta.get(rate_key, 0)
        
        # Get baseline
        baseline = self.compute_baseline(metric, window_seconds)
        
        if baseline['sample_size'] < 2:
            return False, {}
        
        # Check for spike
        threshold = baseline['mean'] * multiplier
        is_spike = current_rate > threshold and baseline['mean'] > 0
        
        return is_spike, {
            'current_rate': current_rate,
            'baseline_mean': baseline['mean'],
            'baseline_std': baseline['std'],
            'threshold': threshold,
            'multiplier': multiplier,
            'window_seconds': window_seconds
        }


# Testing
if __name__ == '__main__':
    from .parser import Snapshot
    
    state = StateManager()
    
    # Simulate snapshots
    base_time = 1234567890000000000
    for i in range(5):
        snap = Snapshot(
            timestamp_ns=base_time + i * 1_000_000_000,
            execve_count=100 + i * 10,
            flow_count=5,
            total_packets=1000 + i * 50,
            total_bytes=500000 + i * 25000,
            syn_packets=10 + i * 2,
            hash="a" * 64
        )
        state.add_snapshot(snap)
    
    # Test delta computation
    if state.previous_snapshot:
        delta = state.compute_delta(state.previous_snapshot, state.snapshots[-1])
        print("✓ Delta computation:")
        print(f"  Execve rate: {delta['execve_rate']:.2f} /sec")
        print(f"  Packet rate: {delta['packet_rate']:.2f} /sec")
    
    # Test baseline
    baseline = state.compute_baseline('total_packets', window_seconds=10)
    print("\n✓ Baseline computation:")
    print(f"  Mean packet rate: {baseline['mean']:.2f} /sec")
    print(f"  Std deviation: {baseline['std']:.2f}")
    
    # Test rate key resolution
    print("\n✓ Rate key resolution:")
    for metric in ['total_packets', 'total_bytes', 'syn_packets', 'execve_count']:
        print(f"  {metric} -> {state._resolve_rate_key(metric)}")
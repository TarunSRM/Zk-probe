#!/usr/bin/env python3
"""
Phase 2 Detector - Main Orchestrator
Reads Phase 1 snapshots from stdin, applies invariants, generates alerts.
"""

import sys
import signal
from typing import Optional
from .parser import SnapshotParser
from .invariant_engine import InvariantEngine
from .state_manager import StateManager
from .alert_generator import AlertGenerator


class Phase2Detector:
    """Main orchestrator for Phase 2 detection pipeline."""
    
    def __init__(self, config_path: Optional[str] = None):
        self.parser = SnapshotParser()
        self.state_manager = StateManager()
        self.invariant_engine = InvariantEngine(config_path)
        self.alert_generator = AlertGenerator()
        self.running = True
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle graceful shutdown."""
        sys.stderr.write("\nShutting down Phase 2 detector...\n")
        self.running = False
    
    def run(self):
        """Main detection loop - reads from stdin, processes snapshots."""
        sys.stderr.write("Phase 2 Local Detection & Invariants Engine\n")
        sys.stderr.write("Reading Phase 1 snapshots from stdin...\n")
        sys.stderr.write("----------------------------------------\n")
        
        line_count = 0
        error_count = 0
        alert_count = 0
        
        try:
            for line in sys.stdin:
                if not self.running:
                    break
                
                line = line.strip()
                if not line:
                    continue
                
                line_count += 1
                
                try:
                    # Parse Phase 1 snapshot
                    snapshot = self.parser.parse(line)
                    
                    # Update state manager
                    self.state_manager.add_snapshot(snapshot)
                    
                    # Evaluate invariants
                    violations = self.invariant_engine.evaluate(
                        snapshot, 
                        self.state_manager
                    )
                    
                    # Generate alerts for violations
                    for violation in violations:
                        alert = self.alert_generator.generate(
                            violation,
                            snapshot,
                            self.state_manager
                        )
                        print(alert)
                        sys.stdout.flush()
                        alert_count += 1
                
                except Exception as e:
                    error_count += 1
                    sys.stderr.write(f"Error processing line {line_count}: {e}\n")
                    if error_count > 10:
                        sys.stderr.write("Too many errors, aborting.\n")
                        break
        
        except KeyboardInterrupt:
            pass
        
        finally:
            sys.stderr.write("\n----------------------------------------\n")
            sys.stderr.write(f"Snapshots processed: {line_count}\n")
            sys.stderr.write(f"Alerts generated: {alert_count}\n")
            sys.stderr.write(f"Errors: {error_count}\n")


def main():
    """Entry point for Phase 2 detector."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Phase 2 Local Detection & Invariants Engine'
    )
    parser.add_argument(
        '-c', '--config',
        help='Path to invariants configuration file',
        default=None
    )
    
    args = parser.parse_args()
    
    detector = Phase2Detector(config_path=args.config)
    detector.run()


if __name__ == '__main__':
    main()
use anyhow::{anyhow, Result};

use crate::circuits::{
    CircuitTemplate, DeviationCheckCircuit, RateCheckCircuit, RatioCheckCircuit,
};
use super::types::ProofInput;

/// A circuit instance ready for proof generation.
pub enum PreparedCircuit {
    Ratio(RatioCheckCircuit),
    Rate(RateCheckCircuit),
    Deviation(DeviationCheckCircuit),
}

impl PreparedCircuit {
    pub fn template(&self) -> CircuitTemplate {
        match self {
            Self::Ratio(_) => CircuitTemplate::RatioCheckV1,
            Self::Rate(_) => CircuitTemplate::RateCheckV1,
            Self::Deviation(_) => CircuitTemplate::DeviationCheckV1,
        }
    }
}

/// Extract a circuit instance from a ProofInput.
pub fn extract_circuit(input: &ProofInput) -> Result<PreparedCircuit> {
    let template = CircuitTemplate::from_str(&input.invariant.circuit_template)
        .ok_or_else(|| anyhow!("Unknown circuit template: {}", input.invariant.circuit_template))?;

    match template {
        CircuitTemplate::RatioCheckV1 => {
            let observed_ratio = input.observation.observed_value;
            let denominator: u64 = 1_000_000;
            let numerator: u64 = (observed_ratio * denominator as f64) as u64;

            let circuit = RatioCheckCircuit::new(
                numerator, denominator,
                input.observation.threshold,
                input.observation.result,
            );
            Ok(PreparedCircuit::Ratio(circuit))
        }
        CircuitTemplate::RateCheckV1 => {
            let window_ns = input.observation.window_duration_ns;
            let window_sec = window_ns as f64 / 1_000_000_000.0;
            let observed_rate = input.observation.observed_value;
            let count_delta = (observed_rate * window_sec) as u64;

            let circuit = RateCheckCircuit::new(
                0, count_delta, 0, window_ns,
                input.observation.threshold,
                input.observation.result,
            );
            Ok(PreparedCircuit::Rate(circuit))
        }
        CircuitTemplate::DeviationCheckV1 => {
            let baseline_mean = 1.0;
            let current_rate = input.observation.observed_value;

            let circuit = DeviationCheckCircuit::new(
                current_rate, baseline_mean,
                input.observation.threshold,
                input.observation.result,
            );
            Ok(PreparedCircuit::Deviation(circuit))
        }
    }
}
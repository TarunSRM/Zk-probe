//! ZK Circuit definitions for zkNIDS invariant verification.
//!
//! All 8 invariants map to exactly 3 circuit templates.
//! Backend: halo2 PLONK+IPA (no trusted setup).
//!
//! | Circuit              | Invariants                                         |
//! |----------------------|----------------------------------------------------|
//! | `ratio_check_v1`     | syn_flood_detection, fragment_abuse_detection       |
//! | `rate_check_v1`      | execve_rate_high, port_scan, malformed_header       |
//! | `deviation_check_v1` | packet_rate_spike, packet_size_anomaly, flow_churn  |

pub mod ratio_check;
pub mod rate_check;
pub mod deviation_check;

pub use ratio_check::RatioCheckCircuit;
pub use rate_check::RateCheckCircuit;
pub use deviation_check::DeviationCheckCircuit;

/// Fixed-point precision: 10^6 (supports 6 decimal places).
/// threshold 0.5 → 500_000, threshold 0.3 → 300_000
pub const PRECISION: u64 = 1_000_000;

/// Convert a floating-point value to fixed-point scaled integer.
pub fn to_fixed_point(value: f64) -> u64 {
    (value * PRECISION as f64) as u64
}

/// Identifies which circuit template to use for a given alert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CircuitTemplate {
    RatioCheckV1,
    RateCheckV1,
    DeviationCheckV1,
}

impl CircuitTemplate {
    /// Parse from the `circuit_template` string in alert JSON.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "ratio_check_v1" => Some(Self::RatioCheckV1),
            "rate_check_v1" => Some(Self::RateCheckV1),
            "deviation_check_v1" => Some(Self::DeviationCheckV1),
            _ => None,
        }
    }

    /// Returns the string identifier used in file paths and proof metadata.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RatioCheckV1 => "ratio_check_v1",
            Self::RateCheckV1 => "rate_check_v1",
            Self::DeviationCheckV1 => "deviation_check_v1",
        }
    }

    /// The parameter `k` determines circuit size: 2^k rows.
    /// Larger k = more constraints supported but slower.
    /// Our circuits are small (~10-50 constraints), so k=8 (256 rows) is plenty.
    pub fn k(&self) -> u32 {
        match self {
            Self::RatioCheckV1 => 8,
            Self::RateCheckV1 => 8,
            Self::DeviationCheckV1 => 8,
        }
    }
}